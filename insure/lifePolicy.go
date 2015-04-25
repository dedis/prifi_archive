/* This file implements the networking code for the life insurance protocol.
 * Building upon the promise.Promise cryptographic primative of
 * crypto/poly/promise, this code provides a simple interface for servers to
 * set up and manage life insurance policies.
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
	"log"
	"time"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/config"
	"github.com/dedis/crypto/poly/promise"

	"github.com/dedis/prifi/connMan"
)

/* The LifePolicyModule is responsible for handling all life insurance logic.
 * In particular, it provides the following functions:
 *
 *   Init
 *   TakeOutPolicy
 *   SendPromiseToClient
 *   CertifyPromise
 *   ReconstructSecret
 *   HandlePolicyMessage
 *
 *
 * Servers can use Init to create the module and define what type of promises
 * it is expecing to receive.
 *
 * They can then use TakeOutPolicy to create new promises and get them certified
 * from insurers.
 *
 * Once the promise has been made, SendPromiseToClient can be used to send the
 * promise to clients of the server.
 *
 * Clients can then use CertifyPromise to contact the insurers to certify the
 * promise.
 *
 * If the promiser becomes unresponsive, clients can use ReconstructSecret to
 * contact the insurers and reconstruct the promised secret.
 *
 * Lastly, HandlePolicyMessage can be used to handle messages sent by other
 * servers. It is recommended to check frequently for other messages. 
 *
 * Please see the comments below for a more information about these functions.
 *
 * Note: It is important that users of this code frequently check and handle
 * messages from all servers in the system. Other servers will send promised
 * secrets to your server, request your server to become its insurer, check if 
 * your server is still alive, etc. It is important to be able to receive these
 * quickly and make a speedy response.
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
	
	// This is the default timeout in seconds.
	defaultTimeout int
	
	// This function is used to check whether a server is still alive.
	// Insurers use this function to verify a promiser is dead before
	// revealing its share of the promise.
	//
	// Arguments
	//   reason = a string stating what type of work the client wanted the
	//            server to do.
	//   serverKey = the public key of the promiser
	//   clientKey = the public key of the client
	//   timeout   = how long to wait for a response from the promiser
	//
	// Returns
	//   nil if the server is deemed alive, error otherwise.
	//
	// Note:
	//   A default method is provided that simply pings the promiser. Users
	//   of this code can define more complex functions in which the insurer
	//   requests the work on behalf of the client, receives the work, and 
	//   then sends it off to the client.
	verifyServerAlive func(reason string, serverKey, clientKey abstract.Point, timeout int) error
}

/* Initializes a new LifePolicyModule object.
 *
 * Arguments:
 *   kp                = the long term public/private key of the server
 *   t, r, n           = configuration parameters for promises. See crypto's promise.Promise
 *                       for more details
 *   cmann             = the connection manager for sending/receiving messages.
 *   defaultTimeout    = the default timeout for waiting for messages.
 *   verifyServerAlive = the function used to verify that a server is dead. Enter
 *                       nil to use the default method. See the documentation for
 *                       theLifePolicyModule for more information on how to write
 *                       such a function.
 *
 * Integration Note: cman should provide some way for the server to communicate with
 *                   itself. Insurers will sometimes need to check that the promise they
 *                   are insuring is certified. Hence, they will send messages to
 *                   themselves when trying to get promiseResponses.
 */
func (lp *LifePolicyModule) Init(kp *config.KeyPair, t,r,n int,
                                 cman connMan.ConnManager, defaultTimeout int,
                                 verifyServerAlive func(reason string, serverKey, clientKey abstract.Point, timeout int) error) *LifePolicyModule {
	lp.keyPair         = kp
	lp.serverId        = kp.Public.String()
	lp.t               = t
	lp.r               = r
	lp.n               = n
	lp.cman            = cman
	lp.promises        = make(map[string] *promise.State)
	lp.serverPromises  = make(map[string](map[string]*promise.State))
	lp.defaultTimeout  = defaultTimeout
	lp.verifyServerAlive = lp.verifyServerAliveDefault
	if verifyServerAlive != nil {
		lp.verifyServerAlive = verifyServerAlive
	}
	return lp
}

/* This is a simple helper function for timeouts. It sleeps for the timeout
 * duration and then sends true to the timeoutChan to let the caller know that
 * the timeout has expired
 *
 * Arguments:
 *   timeout     = the time to wait in seconds
 *   timeoutChan = the channel to send the results to
 *
 * Postcondition:
 *   The timeout is sent to the channel after the appropriate time has elapsed.
 *
 */
func handleTimeout(timeout int, timeoutChan chan<- bool) {
	time.Sleep(time.Duration(timeout) * time.Second)
	timeoutChan <- true
}

/* This private method is the default for determining if a server is alive. It
 * simply pings the server to see if it will respond within a given timelimit.
 * If so, it is alive. Otherwise, it is dead.
 *
 * See the documentation for the verifyServerAlive function in the LifePolicyModule
 * struct for more information on the arguments and return results.
 */
func (lp *LifePolicyModule) verifyServerAliveDefault(reason string,
	serverKey, clientKey abstract.Point, timeout int) error {

	// Send the request message first.
	policyMsg  := new(PolicyMessage).createSAREQMessage()
	lp.cman.Put(serverKey, policyMsg)

	// Setup the timeout.	
	timeoutChan  := make(chan bool, 1)
	go handleTimeout(timeout, timeoutChan)
	
	// Wait for the response
	for true {
		select {
			case result := <- timeoutChan:
				if result == true {
					return errors.New("Server failed to respond in time.")
				}
			default:
		}

		msg := new(PolicyMessage).UnmarshalInit(lp.t,lp.r,lp.n,
				lp.keyPair.Suite)
		lp.cman.Get(serverKey, msg)
		msgType, err := lp.handlePolicyMessage(serverKey, msg)
		if msgType == ServerAliveResponse && err == nil {
			break
		}
		if err != nil {
			log.Println(msgType, err)
		}
	}
	return nil
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

	// If the promise is already certified simply return nil.
	if state.PromiseCertified() == nil {
		return nil
	}

	insurersList := state.Promise.Insurers()

	// Send a request off to each server
	for i := 0; i < lp.n; i++ {
		requestMsg := new(CertifyPromiseMessage).createMessage(i, state.Promise)
		policyMsg  := new(PolicyMessage).createCPMessage(requestMsg)
		lp.cman.Put(insurersList[i], policyMsg)
	}

	// TODO: Consider the case for invalid promises due to a valid blameProof.

	// Setup the timeout.	
	timeoutChan  := make(chan bool, 1)
	go handleTimeout(lp.defaultTimeout, timeoutChan)

	// Wait for responses
	for state.PromiseCertified() != nil {
		select {
			case result := <- timeoutChan:
				if result == true {
					return errors.New("Certification timed out.")
				}
			default:
		}
		for i := 0; i < lp.n; i++ {
			msg := new(PolicyMessage).UnmarshalInit(lp.t,lp.r,lp.n, lp.keyPair.Suite)
			lp.cman.Get(insurersList[i], msg)
			msgType, err := lp.handlePolicyMessage(insurersList[i], msg)
			if err != nil {
				log.Println("Message Type = ", msgType, ":", err)
			}
		}
	}
	return nil
}

/* This is a public wrapper for the private certifyPromise method. The caller can
 * specify a promise from the serverHash that it wishes to certify.
 *
 * Arguments
 *   serverKey  = the long term public key of the server
 *   promiseKey = the public key of the secret being promised
 *
 * Returns
 *   nil if the promise is certified, an error otherwise.
 */
func (lp *LifePolicyModule) CertifyPromise(serverKey, promiseKey abstract.Point) error {
	state, assigned := lp.serverPromises[serverKey.String()][promiseKey.String()]
	if !assigned {
		return errors.New("No such promise")
	}
	return lp.certifyPromise(state)
}

/* This function is responsible for revealing a share and sending it to a client.
 * Once insurers have verified that the promiser is dead, insurers can use this
 * method to reveal the share.
 * 
 * Arguments:
 *   shareIndex = the index of the share to reveal
 *   state      = the state of the promise holding the share to reveal
 *   clientKey  = the long-term public key of the client to send the share to
 *
 * Returns:
 *   nil if the share was sent successfully, err otherwise.
 *
 * Note:
 *   This function is solely responsible for sending the share to the client, not
 *   verifying if the insurer should actually send the share to the client. Such
 *   verification must be done before the call to this function.
 */
func (lp * LifePolicyModule) revealShare(shareIndex int, state * promise.State, clientKey abstract.Point) error {
	// A promise must be certified before a share can be revealed.
	if state.PromiseCertified() != nil {
		err := lp.certifyPromise(state)
		if err != nil {
			return err
		}
	}

	share := state.RevealShare(shareIndex, lp.keyPair)
	responseMsg := new(PromiseShareMessage).createResponseMessage(
		shareIndex, state.Promise, share)
	lp.cman.Put(clientKey, new(PolicyMessage).createSRSPMessage(responseMsg))
	return nil
}

/* This method sends a promise to another server.
 *
 * Arguments:
 *   clientKey    = the long term public key of the client to send the promise to
 *   secretKey    = the public key of the promised secret to send
 *
 * Returns:
 *   nil if the message is sent, an error otherwise.
 */
func (lp *LifePolicyModule) SendPromiseToClient(clientKey, secretKey abstract.Point) error {
	state, assigned := lp.promises[secretKey.String()]
	if !assigned {
		return errors.New("Promise does not exist")
	}
	if state.PromiseCertified() != nil {
		return errors.New("Promise must be certified.")
	}
	policyMsg := new(PolicyMessage).createPTCMessage(&state.Promise)
	lp.cman.Put(clientKey, policyMsg)	
	return nil
}

/* Clients can use this function to reconstruct a promised secret that
 * it has. This function will contact the insurers and then recreate the secret
 * if it has received enough shares. It is the responsibility of the caller to
 * ensure that the promiser has been unresponsive before calling this function.
 *
 * Arguments:
 *   reason = the reason why the client is attempting to reconstruct the secret.
 *            This is mostly used when insurers receive the request to reveal
 *            their share. The insurers then call the function that determines
 *            whether the promiser is dead and passes the "reason" value to it.
 *            Methods created by users of this code can use this reason to determine
 *            what type of request the client was waiting on the promiser to do
 *            when the promiser became unresponsive. The functions can then take
 *            additional actions appropriately.
 *
 *            For the default method provided by this module, nil will suffice.
 *
 *   serverKey  = the long term key of the promiser of the secret
 *   promiseKey = the public key of the secret promised
 *
 * Returns
 *   (key, error) pair
 *      key   = the reconstructed key on success, nil otherwise
 *      error = nil on success, the error that occurred otherwise 
 */
func (lp *LifePolicyModule) ReconstructSecret(reason string,
	serverKey,promiseKey abstract.Point) (abstract.Secret, error) {

	state, assigned := lp.serverPromises[serverKey.String()][promiseKey.String()]
	if !assigned {
		return nil, errors.New("No such Promise.")
	}
	insurersList := state.Promise.Insurers()

	// Send a request off to each server
	for i := 0; i < lp.n; i++ {
		requestMsg := new(PromiseShareMessage).createRequestMessage(i, reason, state.Promise)
		policyMsg  := new(PolicyMessage).createSREQMessage(requestMsg)
		lp.cman.Put(insurersList[i], policyMsg)
	}
	
	// It is important to have this seenBefore array. Secret reconstruction
	// relies on crypto/poly.PriShares. The function used will panic if
	// not enough shares have been recovered. The function also doesn't keep
	// track of which promises have been added. Hence, this array along with
	// the sharesRetrieved counter is used to keep track of this information.
	// Otherwise, a malicious insurer could send multiple copies of its share
	// and trick the client into thinking it has received unique shares and
	// consequently try to reconstruct the secret to early.
	seenBefore := make([]bool, lp.n, lp.n)
	for i:= 0; i < lp.n; i++ {
		seenBefore[i] = false;
	}
	sharesRetrieved := 0;

	// TODO: Add timeout mechanism.
	for sharesRetrieved < lp.t {
		for i := 0; i < lp.n; i++ {	
			msg := new(PolicyMessage).UnmarshalInit(lp.t,lp.r,lp.n,
				lp.keyPair.Suite)
			lp.cman.Get(insurersList[i], msg)
			msgType, err := lp.handlePolicyMessage(insurersList[i], msg)
			if err == nil &&
			   seenBefore[i] == false &&
			   msgType == ShareRevealResponse {
				seenBefore[i] = true
				sharesRetrieved += 1
			}
		}
	}
	return state.PriShares.Secret(), nil
}


/******************************** Receive Method ******************************/
// These are methods responsible for handling mesges that come into the system.

/* This function processes policy messages received over the internet and updates
 * the life policy appropriately.
 *
 * Arguments:
 *   pubKey = the public key of the sender of the message.
 *   msg    = the message to process
 *
 * Returns:
 *      A tuple of the form (type, err)
 *         type  = the type of message processed
 *         err   = the error status received
 *
 * Note: errors need not be alarming as they can occur for a wide variety of reasons
 * (The message specified a promise that doesn't exist, a server tried to share
 * a promise with itself, etc.)
 *
 * Note: In the case of ServerAliveResponse, nothing needs to be done. Simply
 * inform the caller that the sender is alive.
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
		case ServerAliveRequest:
			return ServerAliveRequest, lp.handleServerAliveRequestMessage(pubKey)
		case ServerAliveResponse:
			return ServerAliveResponse, nil
	}
	return Error, errors.New("Invald message type")
}


/* This internal helper method properly adds a new promise to the serverPromises
 * hash. If the promise already exists in the hash, the function does nothing.
 *
 * Arguments:
 *   prom = the promise to add
 *
 * Postconditions:
 *   The promise has been added to:
 *
 *      serverPromises[long_term_id_of_promiser][id_of_promise]
 *
 *   The method also creates and assigns a hash to
 *
 *      serverPromises[long_term_id_of_promiser]
 *
 *   if one does not already exist.
 */
func (lp *LifePolicyModule) addServerPromise(prom promise.Promise) {
	promiserId := prom.PromiserId()
	id         := prom.Id()
	if _, assigned := lp.serverPromises[promiserId]; !assigned{
		lp.serverPromises[promiserId] = make(map[string]*promise.State)
	}
	if _, assigned := lp.serverPromises[promiserId][id]; !assigned {
		state := new(promise.State).Init(prom)
		lp.serverPromises[promiserId][id] = state
	}
}

/* This method handles CertifyPromiseMessages. Insurers use this method to
 * respond to both clients and promisers.
 *
 *    promisers = the method adds the promise to its serverPromises hash and
 *                returns a response
 *
 *    clients   = the method returns a response if the specified promise exists.
 *
 * Arguments:
 *   pubKey = the long-term public key of the requestor
 *   msg    = the CertifyPromiseMessage
 *
 * Returns:
 *	nil if a response is successfully sent, an error otherwise.
 */
func (lp *LifePolicyModule) handleCertifyPromiseMessage(pubKey abstract.Point, msg *CertifyPromiseMessage) error {

	// Both promisers and clients will send CertifyPromiseMessages to insurers.
	// An insurer only wants to add the promise to the serverPromises hash if
	// the server sending the message is the one who created the promise.
	// Otherwise, malicious servers could register promises in other's names.
	if pubKey.String() == msg.Promise.PromiserId() {
		lp.addServerPromise(msg.Promise)
	}

	// Retrieve the promise, produce a response, and send the reply to the
	// server who sent the message.
	state, assigned := lp.serverPromises[msg.Promise.PromiserId()][msg.Promise.Id()]
	if !assigned {
		return errors.New("No such promise exists.")
	}
	
	response, err := state.Promise.ProduceResponse(msg.ShareIndex, lp.keyPair)
	if err != nil {
		return err
	}
	replyMsg := new(PromiseResponseMessage).createMessage(msg.ShareIndex,
		state.Promise, response)
	lp.cman.Put(pubKey, new(PolicyMessage).createPRMessage(replyMsg))
	return nil
}

/* This method handles PromiseResponseMessages. Servers will send CertifyPromiseMessages
 * to insurers so they can approve or disapprove promises. Ahe promise can
 * either be one the server created itself or one it has received from another server.
 * The insurer will then send a PromiseResponse back for the server to add to the
 * promise state.
 *
 * Arguments:
 *   msg = the PromiseResponseMessage
 *
 * Returns:
 *	nil if the PromiseResponse was added to the state, err otherwise.
 *
 * TODO Change promise.AddResponse so that it verifies that the response is
 *      well-formed and returns an error status.
 *
 * TODO Alter promise.AddResponse to keep track of the number of valid responses
 *      it has received. To do so:
 *
 *          - Only add valid responses
 *          - Increment a counter each time a valid response is added.
 *          - If a valid response replaces another valid response, update the
 *            array but don't change the counter
 *          - Once a validly produced blameProof is found, set a flag to permanently
 *            denote the promise as invalid
 *          - Perhaps also prevent any new promises from being added to prevent
 *            overwritting the blameproof?
 */
func (lp *LifePolicyModule) handlePromiseResponseMessage(msg *PromiseResponseMessage) error {
	// If the promise was created by the server, add the response to the
	// server's promise state. This should only be done if the promiser id of the
	// promise is the same as the server's long term public key.
	state, ok := lp.promises[msg.Id];
	if  ok && msg.PromiserId == lp.serverId {
		state.AddResponse(msg.ShareIndex, msg.Response)
		return nil
	}

	// Otherwise, the server was requesting a certificate for a promise
	// from another server.
	state, ok = lp.serverPromises[msg.PromiserId][msg.Id];	
	if ok {
		state.AddResponse(msg.ShareIndex, msg.Response)
		return nil
	}
	return errors.New("Promise does not exist.")
}

/* This method handles PromiseToClientMessages. When a server sends a new
 * promise to a client, this method checks to make sure the promise is okay and
 * adds it to the serverPromise hash
 *
 * Arguments:
 *   pubKey = the long-term public key of the sender
 *   prom   = the promise to add
 *
 * Returns
 *   nil if added successfully, error otherwise
 *
 * Note
 *   There are two major error conditions to consider:
 *
 *      - Servers can only send promises they actually own to prevent malicious
 *      servers from registering bad promises under another's name.
 *
 *      - Servers should simply ignore promises they send to themselves.
 */
func (lp *LifePolicyModule) handlePromiseToClientMessage(pubKey abstract.Point, prom *promise.Promise) error {
	if prom.PromiserId() != pubKey.String() {
		return errors.New("Sender does not own the promise sent.")
	}
	if lp.serverId == prom.PromiserId() {
		return errors.New("Sent promise to oneself. Ignoring.")
	}
	lp.addServerPromise(*prom)
	return nil
}

/* This is a simple method that handles ServerAliveRequests. It simply sends a
 * response so that the caller knows the server is alive.
 *
 * Arguments
 *   pubKey = the public key of the sender.
 *
 * Returns
 *   nil (since the send should always succeed)
 */
func (lp *LifePolicyModule) handleServerAliveRequestMessage(pubKey abstract.Point) error {
	lp.cman.Put(pubKey, new(PolicyMessage).createSARSPMessage())
	return nil
}

/* This method is responsible for handling RevealShareRequests. If a client believes
 * a promiser to be down, it will send such messages to the insurers. The insurers will
 * then verify that the server is actually down. If the server is down, it will
 * send the revealed share to the client.
 *
 * Arguments:
 *   pubKey = the public key of the sender of the message
 *   msg    = the RevealShareRequests itself
 *
 * Returns
 *  nil if the share is revealed, err otherwise
 *
 * Note:
 *  If the server is actually alive, verifyServerAlive is responsible for sending
 *  to the client any information it needs (possibly none).
 */
func (lp *LifePolicyModule) handleRevealShareRequestMessage(pubKey abstract.Point, msg *PromiseShareMessage) error {
	state, assigned := lp.serverPromises[msg.PromiserId][msg.Id]
	if !assigned {
		return errors.New("This server insurers no such Promise.")
	}
	
	err := lp.verifyServerAlive(msg.Reason, state.Promise.PromiserKey(), pubKey, lp.defaultTimeout)
	if err == nil {
		return errors.New("Server is still alive. Share not revealed.")
	}
	return lp.revealShare(msg.ShareIndex, state, pubKey)
}

/* This function handles RevealShareResponses. When a client requests that an insurer
 * reveals a share, the insurer will respond with a RevealShareResponseMessage if
 * the promiser is deemed dead. This method verifies that the share is valid and
 * then adds the share to the promise state.
 *
 * Arguments:
 *   msg = the PromiseShareMessage containing the share
 *
 * Returns:
 *   nil if successful, err otherwise
 */
func (lp *LifePolicyModule) handleRevealShareResponseMessage(msg *PromiseShareMessage) error {
	state, assigned := lp.serverPromises[msg.PromiserId][msg.Id]
	if !assigned {
		return errors.New("Promise does not exist on this server.")
	}	
	if err := state.Promise.VerifyRevealedShare(msg.ShareIndex, msg.Share); err != nil {
		return err
	}
	state.PriShares.SetShare(msg.ShareIndex, msg.Share)
	return nil
}

