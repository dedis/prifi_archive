/* This file implements the networking code for the life insurance protocol.
 * Building upon the promise.Promise cryptographic primative, this code provides
 * a simple interface for servers to set up and manage life insurance policies
 * for themselves and other servers.
 *
 * In particular, the file allows servers to:
 *
 *   - Create new promises from private keys
 *   - Send promises to insurers to have them certified
 *   - Send promises to clients
 *   - Manage promises from other servers
 *   - Reconstruct promised secrets when necessary
 */
package insure

import (
	"errors"
	"fmt"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/config"
	"github.com/dedis/crypto/poly/promise"

	"github.com/dedis/prifi/connMan"
)

/* The LifePolicyModule is responsible for handling all life insurance logic.
 * In particular, it can
 *
 *   - Create new promises
 *   - Handle promise certification
 *   - Send/receive messages over the network.
 */

type LifePolicyModule struct {

	// The long-term key pair of the server
	keyPair *config.KeyPair
	
	// The id of the server (a string version of its long term public key).
	// This is used primarily to simplify code.
	serverId string
	
	// t, r, and n are parameters used to construct promise.Promise's. These
	// parameters will be used for all promises constructed. Other servers
	// wishing to send promises to this module should use the same values for
	// these parameters.
	//
	// Refer to the crypto promise.Promise documentation for more information
	// about how they are used.
	//
	// TODO Make sure the system behaves properly if these values differ.
	t, r, n int

	// This hash contains promises the server has created. The hash is of
	// the form:
	//
	// promised_public_key_string => state_of_promise
	promises map[string] *promise.State

	// This hash contains promises that originated from other servers.
	// Promises that the server is insuring as well as promises from
	// servers who are performing work for this server are kept here.
	//
	// The hash is of the form:
	//
	// string_of_long_term_key_of_other_server
	//    => promised_public_key_string
	//       => state_of_promise
	serverPromises map[string](map[string]*promise.State)

	// The connection manager used for sending/receiving messages over the network
	cman connMan.ConnManager
}

/* Initializes a new LifePolicyModule object.
 *
 * Arguments:
 *   kp       = the long term public/private key of the server
 *   t, r, n  = configuration parameters for promises. See crypto's promise.Promise
 *              for more details
 *   cmann    = the connection manager for sending/receiving messages.
 */
func (lp *LifePolicyModule) Init(kp *config.KeyPair, t,r,n int, cman connMan.ConnManager) *LifePolicyModule {
	lp.keyPair         = kp
	lp.serverId        = kp.Public.String()
	lp.t               = t
	lp.r               = r
	lp.n               = n
	lp.cman            = cman
	lp.promises        = make(map[string] *promise.State)
	lp.serverPromises  = make(map[string](map[string]*promise.State))
	return lp
}

/* This private method selects n insurers from a larger list of insurers. This
 * is the default method used for selected the insurers to use for constructing
 * a promise.
 *
 * Arguments:
 *    serverList = the list of servers to choose from
 *    n          = the number of servers to choose
 *
 * Returns:
 *   The list of servers to serve as insurers
 *
 * Note:
 *   The function simply returns the first n servers.
 */

func selectInsurersBasic(serverList []abstract.Point, n int) []abstract.Point {
	return serverList[:n]
}

/* This method is responsible for taking out a new life policy. It constructs
 * a new promise, sends the promise to its insurers, and then insures that the
 * promise is certified.
 *
 * Arguments:
 *   secretPair      = the public/private key of the secret to promise
 *   serverList      = a list of public keys of possible insurers
 *   selectInsurers  = a function for selecting insurers from the serverList,
 *                     or nil to use the default selection method
 *
 * Returns:
 *   nil if successful, an eror otherwise.
 *
 * Note:
 *  selectInsurers should return a list exactly of the size specified, otherwise
 *  this function will panic.
 */
func (lp *LifePolicyModule) TakeOutPolicy(secretPair *config.KeyPair, serverList []abstract.Point,
	selectInsurers func([]abstract.Point, int) []abstract.Point) error {

	// If the promise has already been created, do not create a new one but
	// use the existing one.
	if state, ok := lp.promises[secretPair.Public.String()]; ok {
	
		// If the promise is not yet certified, attempt to get its
		// certification.
		if state.PromiseCertified() != nil {
			return lp.certifyPromise(state)
		}

		// Otherwise, return success
		return nil
	}

	// If a promise doesn't already exist, create a new Promise
	if selectInsurers == nil {
		selectInsurers = selectInsurersBasic
	}
	insurersList := selectInsurers(serverList, lp.n)
	if len(insurersList) != lp.n {
		panic("InsurersList too small")
	}

	newPromise := promise.Promise{}
	newPromise.ConstructPromise(secretPair, lp.keyPair, lp.t, lp.r, insurersList)
	state := new(promise.State).Init(newPromise)
	lp.promises[newPromise.Id()] = state
	return lp.certifyPromise(state)
}

/******************************** Request Method ******************************/
// These are methods that are send data to other nodes.


/* This method is responsible for certifying a promise. It sends requests out
 * to the insurers and then waits for the promise to be certified.
 *
 * Arguments:
 *   state  = the promise.State containing the promise to be certified
 *
 * Returns:
 *   nil if the promise is certified, an error otherwise
 */
func (lp *LifePolicyModule) certifyPromise(state *promise.State) error {

	insurersList := state.Promise.Insurers()

	// Send a request off to each server
	for i := 0; i < lp.n; i++ {
		requestMsg := new(CertifyPromiseMessage).createMessage(i, state.Promise)
		policyMsg  := new(PolicyMessage).createCPMessage(requestMsg)
		lp.cman.Put(insurersList[i], policyMsg)
	}

	// TODO: Add a timeout so that this process will end after a certain
	// amount of time.
	
	// Wait for responses
	for state.PromiseCertified() != nil {
		for i := 0; i < lp.n; i++ {	
			msg := new(PolicyMessage).UnmarshalInit(lp.t,lp.r,lp.n, lp.keyPair.Suite)
			lp.cman.Get(insurersList[i], msg)
			lp.handlePolicyMessage(insurersList[i], msg)
		}
	}
	return nil
}

/* This method sends a promise to another server.
 *
 * Arguments:
 *   clientLongPubKey  = the long term public key of the client to send the promise to
 *   secretKey         = the public key of the promised secret to send
 *
 * Returns:
 *   nil if the message is sent, an error otherwise.
 */
func (lp *LifePolicyModule) SendPromiseToClient(clientKey, secretKey abstract.Point) error {
	if state, assigned := lp.promises[secretKey.String()]; assigned {
		policyMsg := new(PolicyMessage).createPTCMessage(&state.Promise)
		lp.cman.Put(clientKey, policyMsg)	
		return nil
	}
	return errors.New("Promise does not exist")
}

func (lp *LifePolicyModule) ReconstructSecret(longTermKey,secretPubKey abstract.Point) abstract.Secret {

	state        := lp.serverPromises[longTermKey.String()][secretPubKey.String()]
	insurersList := state.Promise.Insurers()

	// Send a request off to each server
	for i := 0; i < lp.n; i++ {
		requestMsg := new(PromiseShareMessage).createRequestMessage(i, state.Promise)
		policyMsg  := new(PolicyMessage).createSREQMessage(requestMsg)
		lp.cman.Put(insurersList[i], policyMsg)
	}

	// TODO: Add a timeout such that this process will end after a certain
	// amount of time.
	
	// It is important to have this seen before array. The reason is that
	// Secret reconstruction will panic if not enough shares are provided.
	// Hence, this is used to make sure that a malicious insurer does not
	// send multiple shares and trick the client into thinking it has 
	// received unique ones.
	seenBefore := make([]bool, lp.n, lp.n)
	for i:= 0; i < lp.n; i++ {
		seenBefore[i] = false;
	}
	sharesRetrieved := 0;
	for sharesRetrieved < lp.t {
		for i := 0; i < lp.n; i++ {	
			msg := new(PolicyMessage).UnmarshalInit(lp.t,lp.r,lp.n, lp.keyPair.Suite)
			lp.cman.Get(insurersList[i], msg)
			msgType, err := lp.handlePolicyMessage(insurersList[i], msg)
			if msgType == ShareRevealResponse && err == nil &&
			   seenBefore[i] == false {
				seenBefore[i] = true
				sharesRetrieved += 1
			}
		}
	}
	return state.PriShares.Secret()
}



/******************************** Receive Method ******************************/
// These are methods responsible for handling mesges that come into the system.


/* This function handles policy messages received. This function will handle
 * updating the life policy appropriately. Simply give it the policy message
 * and let it handle the rest.
 *
 * Arguments:
 *   msg = the message to handle
 *
 * Returns:
 *      - The type of message received.
 *	- an error denoting the status of the message
 *
 * NOTE: An error need not be alarming. For example, if one node sends a
 * duplicate request, the policy can simply ignore the duplicate.
 */
func (lp *LifePolicyModule) handlePolicyMessage(pubKey abstract.Point, msg *PolicyMessage) (PolicyMessageType, error) {
	switch msg.Type {
		case CertifyPromise:
			return CertifyPromise, lp.handleCertifyPromiseMessage(pubKey, msg.getCPM())
		case PromiseResponse:
			return PromiseResponse, lp.handlePromiseResponseMessage(msg.getPRM())
		case PromiseToClient:
			return PromiseToClient, lp.handlePromiseToClientMessage(pubKey, msg.getPTCM())
		case ShareRevealRequest:
			return ShareRevealRequest, lp.handleRevealShareRequestMessage(pubKey, msg.getSREQ())
		case ShareRevealResponse:
			return ShareRevealResponse, lp.handleRevealShareResponseMessage(msg.getSRSP())
	}
	return Error, errors.New("Invald message type")
}

/* This method handles CertifyPromiseMessages. If another node requests to be insured,
 * verify that the share it sent is valid. If so, insure it and send a confirmation
 * message back.
 *
 * Arguments:
 *   msg = the message requesting insurance
 *
 * Returns:
 *	the error status (possibly nil)
 *
 * TODO Add an option to differentiate between taking out a promise and certifying
 * a promise that already exists.
 */
func (lp *LifePolicyModule) handleCertifyPromiseMessage(pubKey abstract.Point, msg *CertifyPromiseMessage) error {
	promiserId := msg.Promise.PromiserId()
	id         := msg.Promise.Id()
	if _, assigned := lp.serverPromises[promiserId]; !assigned{
		lp.serverPromises[promiserId] = make(map[string]*promise.State)
	}
	if _, assigned := lp.serverPromises[promiserId][id]; !assigned {
		state := new(promise.State).Init(msg.Promise)
		lp.serverPromises[promiserId][id] = state
	}
	state := lp.serverPromises[promiserId][id]
	response, err := state.Promise.ProduceResponse(msg.ShareIndex, lp.keyPair)
	if err != nil {
		return err
	}
	replyMsg := new(PromiseResponseMessage).createMessage(msg.ShareIndex, state.Promise, response)
	lp.cman.Put(pubKey, new(PolicyMessage).createPRMessage(replyMsg))
	return nil
}

/* This method handles CertifyPromiseMessages. If another node requests to be
 * insured, verify that the share it sent is valid. If so, insure it and send a
 * confirmation message back.
 *
 * Arguments:
 *   msg = the message requesting insurance
 *
 * Returns:
 *	Whether or not the request was accepted.
 */
func (lp *LifePolicyModule) handlePromiseResponseMessage(msg *PromiseResponseMessage) error {
	if state, ok := lp.promises[msg.Id]; ok &&
		msg.PromiserId == lp.keyPair.Public.String() {

		state.AddResponse(msg.ShareIndex, msg.Response)
		return nil
	}	
	if state, ok := lp.serverPromises[msg.PromiserId][msg.Id]; ok {
		state.AddResponse(msg.ShareIndex, msg.Response)
		return nil
	}

	panic("DEATH AND DOOM")
	return errors.New("Promise specified does not exist.")
}

// TODO check to make sure origin of the promise and the promiser are the same.
func (lp *LifePolicyModule) handlePromiseToClientMessage(pubKey abstract.Point, prom *promise.Promise) error {
	if prom.PromiserId() != pubKey.String() {
		return errors.New("The sender does not own the promise sent.")
	}
	if lp.serverId == prom.PromiserId() {
		return errors.New("Sent promise to oneself. Ignoring.")
	}
	promiserId := prom.PromiserId()
	id         := prom.Id()

	if _, assigned := lp.serverPromises[promiserId]; !assigned {
		lp.serverPromises[promiserId] = make(map[string]*promise.State)
	}
	if _, assigned := lp.serverPromises[promiserId][id]; !assigned {
		state := new(promise.State).Init(*prom)
		lp.serverPromises[promiserId][id] = state
	}
	state := lp.serverPromises[promiserId][id]

	// If this promise is already considered valid, ignore it.
	if state.PromiseCertified() == nil {
		panic("Should not happen in tests")
		return nil
	}

	return lp.certifyPromise(state)
}

func (lp *LifePolicyModule) handleRevealShareRequestMessage(pubKey abstract.Point, msg *PromiseShareMessage) error {
	promiserId := msg.PromiserId
	id := msg.Id
	if state, assigned := lp.serverPromises[promiserId][id]; assigned {
		if state.PromiseCertified() != nil {
			// A promise must be certified before a share can be revealed.
			// get the certification if so.
			
			// TODO if you add a timelimit to certifyPromise
			// make sure that you check it here before continuing.
			lp.certifyPromise(state)
		}
		// TODO change RevealShare to do standard checking and to return
		// an error if it finds one.
		share := state.RevealShare(msg.ShareIndex, lp.keyPair)
		responseMsg := new(PromiseShareMessage).createResponseMessage(
			msg.ShareIndex, state.Promise, share)
		lp.cman.Put(pubKey, new(PolicyMessage).createSRSPMessage(responseMsg))
		return nil
	}
	return errors.New("This server insurers no such Promise.")
}

// Add the share to the Promise if it is valid. Ignore it otherwise.
func (lp *LifePolicyModule) handleRevealShareResponseMessage(msg *PromiseShareMessage) error {
	if state, assigned := lp.serverPromises[msg.PromiserId][msg.Id]; assigned {
		if err := state.Promise.VerifyRevealedShare(msg.ShareIndex, msg.Share); err != nil {
			return err
		}
		state.PriShares.SetShare(msg.ShareIndex, msg.Share)
		fmt.Println("SHARE REVEALED")
		return nil
	}
	return errors.New("This server does not know of the specified promise.")
}
