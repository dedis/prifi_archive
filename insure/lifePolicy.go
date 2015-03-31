package insure

import (
	"errors"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/config"
	"github.com/dedis/crypto/poly/promise"

	"github.com/dedis/prifi/connMan"
)

/* This file provides an implementation of the life insurance policy. Coco
 * servers will each carry their own policies and will be required to take one
 * out before participating in the system. At any point, they should be ready to
 * prove that they carry a valid policy. For a detailed summary of the insurance
 * policy protocol, please see doc.go
 *
 * To create a policy:
 * newPolicy, ok := new(LifePolicyModule).Init(KeyPairOfServer, ConnectionManager).TakeOutPolicy(
 *		ListOfInsurrers, OptionalMethodOfChoosingInsurers, GroupForPrivateShares,
 *		MinimumNumberOfPrivateSharesNeededForReconstruction, TotalNumberOfShares)
 *
 * For safety measures, the function returns nil if the policy fails to be
 * created along with an updated status in ok.
 */

type LifePolicyModule struct {
	// The long term key pair of the server
	keyPair *config.KeyPair
	
	serverId string
	
	t int
	
	r int
	
	n int

	// A hash of promises this server has made.
	// promise_id => State
	promises map[string]*promise.State

	// A hash of promises sent to this server from others servers.
	// Promises that this server is insuring and promises received from
	// other servers are stored here.
	// PromiserLongTermKey => PromiserShortTermKey => State
	serverPromises map[string](map[string]*promise.State)

	// The connection manager to use for networking
	cman connMan.ConnManager
}

/* This method initializes a policy. This function should be called first before
 * using the policy in any manner. After being initialize, the policy will be
 * able to insure other clients. However, it will not provide a policy for the
 * server who owns it until TakeOutPolicy has been called.
 *
 * Arguments:
 *   kp       = the public/private key of the owner server
 *   cmann    = the connection manager to handle requests.
 */
func (lp *LifePolicyModule) Init(kp *config.KeyPair, t,r,n int, cman connMan.ConnManager) *LifePolicyModule {
	lp.keyPair         = kp
	lp.serverId        = kp.Public.String()
	lp.t               = t
	lp.r               = r
	lp.n               = n
	lp.cman            = cman
	lp.promises        = make(map[string]*promise.State)
	lp.serverPromises  = make(map[string](map[string]*promise.State))
	return lp
}

/* This function selects a set of servers to serve as insurers. This is an
 * extremely rudimentary version that selects the first n servers from the list.
 *
 * Arguments:
 *    serverList = the list of servers to choose from
 *    n          = the number of servers to choose
 *
 * Returns:
 *   The list of servers to server as insurers
 */

func selectInsurersBasic(serverList []abstract.Point, n int) []abstract.Point {
	if n < len(serverList) {
		panic("Not enough insurer keys given")
	}

	return serverList[:n]
}

/* This method is responsible for "taking out" the insurance policy. The
 * function takes the server's private key, divides it up into
 * shares using Shamir Secret Sharing, distribute these shares to trustees,
 * and then provides a "receipt list" of digital signatures proving that
 * the server has indeed selected insurers.
 *
 * Arguments:
 *   keyPair         = the public/private key of the server
 *   serverList      = a list of the public keys of possible insurers
 *   selectInsurers  = a function for selecting insurers
 *   g               = the group that the private shares should be made from
 *   t               = the minimum number of shares to reconstruct the secret
 *   n               = the total shares to be distributed
 *
 *
 * Note: If selectInsurers is null, the policy will resort to a default
 * selection function.
 */

func (lp *LifePolicyModule) TakeOutPolicy(secretPair *config.KeyPair,
        serverList []abstract.Point,
	selectInsurers func([]abstract.Point, int) []abstract.Point) error {

	// Initialize the policy.

	// If we have no selectInsurers function, use the basic algorithm.
	// TODO if selectInsurers is malicious, panic.
	if selectInsurers == nil {
		selectInsurers = selectInsurersBasic
	}
	insurersList := selectInsurers(serverList, lp.n)

	newPromise   := promise.Promise{}
	newPromise.ConstructPromise(secretPair, lp.keyPair, lp.t, lp.r, insurersList)
	state := new(promise.State).Init(newPromise)
	lp.promises[newPromise.Id()] = state
	return lp.getPromiseCertification(state, insurersList)
}

func (lp *LifePolicyModule) getPromiseCertification(state *promise.State, insurersList []abstract.Point) error {

	// Send a request off to each server
	for i := 0; i < lp.n; i++ {
		requestMsg := new(CertifyPromiseMessage).createMessage(i, state.Promise)
		policyMsg  := new(PolicyMessage).createCPMessage(requestMsg)
		lp.cman.Put(insurersList[i], policyMsg)
	}

	// TODO: Add a timeout such that this process will end after a certain
	// amount of time.
	for state.PromiseCertified() != nil {
		for i := 0; i < lp.n; i++ {	
			msg := new(PolicyMessage).UnmarshalInit(lp.t,lp.r,lp.n, lp.keyPair.Suite)
			lp.cman.Get(insurersList[i], msg)
			lp.handlePolicyMessage(insurersList[i], msg)
		}
	}
	return nil
}

func (lp *LifePolicyModule) SendClientPolicy(clientLongPubKey, secretPubKey abstract.Point) error {
	if state, assigned := lp.promises[secretPubKey.String()]; assigned {
		policyMsg := new(PolicyMessage).createPTCMessage(&state.Promise)
		lp.cman.Put(clientLongPubKey, policyMsg)	
		return nil
	}
	return errors.New("Promise does not exist")
}

func (lp *LifePolicyModule) ReconstructSecret(longTermKey,secretPubKey abstract.Point) error {

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
	return nil
}

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

	insurers := state.Promise.Insurers()
	return lp.getPromiseCertification(state, insurers)
}

func (lp *LifePolicyModule) handleRevealShareRequestMessage(pubKey abstract.Point, msg *PromiseShareMessage) error {
	promiserId := msg.PromiserId
	id := msg.Id
	if state, assigned := lp.serverPromises[promiserId][id]; assigned {
		if state.PromiseCertified() != nil {
			// A promise must be certified before a share can be revealed.
			// get the certification if so.
			
			// TODO if you add a timelimit to getPromiseCertification
			// make sure that you check it here before continuing.
			insurers := state.Promise.Insurers()
			lp.getPromiseCertification(state, insurers)
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
	}
	return errors.New("This server does not know of the specified promise.")
}
