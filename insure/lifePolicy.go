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

	// A hash of promises this server has made.
	// promise_id => State
	promises map[string]*promise.State
	
	// A hash of promises that this server is insuring
	// PromiserLongTermKey => PromiserShortTermKey => Promise
	insuredPromises map[string](map[string]promise.Promise)

	// A hash of promises sent to this server from others servers.
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
func (lp *LifePolicyModule) Init(kp *config.KeyPair, cman connMan.ConnManager) *LifePolicyModule {
	lp.keyPair         = kp
	lp.cman            = cman
	lp.promises        = make(map[string]*promise.State)
	lp.insuredPromises = make(map[string](map[string]promise.Promise))
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

func (lp *LifePolicyModule) TakeOutPolicy(secretPair *config.KeyPair, t, r, n int,
        serverList []abstract.Point,
	selectInsurers func([]abstract.Point, int) []abstract.Point) bool {

	// Initialize the policy.

	// If we have no selectInsurers function, use the basic algorithm.
	if selectInsurers == nil {
		selectInsurers = selectInsurersBasic
	}
	insurersList := selectInsurers(serverList, n)

	newPromise   := promise.Promise{}
	newPromise.ConstructPromise(secretPair, lp.keyPair, t, r, insurersList)
	state := new(promise.State).Init(newPromise)
	lp.promises[newPromise.Id()] = state

	// Send each share off to the appropriate server.
	for i := 0; i < n; i++ {
		requestMsg := new(CertifyPromiseMessage).createMessage(i, newPromise)
		policyMsg  := new(PolicyMessage).createCPMessage(requestMsg)
		lp.cman.Put(insurersList[i], policyMsg)
	}

	// TODO: Add a timeout such that this process will end after a certain
	// time and a new batch of insurers can be picked.
	for state.PromiseCertified() != nil {
		for i := 0; i < n; i++ {
			msg := new(PolicyMessage).UnmarshalInit(t,r,n, lp.keyPair.Suite)
			lp.cman.Get(insurersList[i], msg)
			lp.handlePolicyMessage(insurersList[i], msg)
		}
	}

	return true
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
 */
func (lp *LifePolicyModule) handleCertifyPromiseMessage(pubKey abstract.Point, msg *CertifyPromiseMessage) error {
	if _, assigned := lp.insuredPromises[pubKey.String()]; !assigned{
		lp.insuredPromises[pubKey.String()] = make(map[string]promise.Promise)
	}
	if _, assigned := lp.insuredPromises[pubKey.String()][msg.Promise.Id()]; !assigned {
		lp.insuredPromises[pubKey.String()][msg.Promise.Id()] = msg.Promise
	}
	response, err := msg.Promise.ProduceResponse(msg.ShareIndex, lp.keyPair)
	if err != nil {
		return err
	}
	replyMsg := new(PromiseResponseMessage).createMessage(msg.ShareIndex, msg.Promise, response)
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

	if state, ok := lp.promises[msg.Id]; ok {
		state.AddResponse(msg.ShareIndex, msg.Response)
		return nil
	}
	if state, ok := lp.serverPromises[msg.PromiserId][msg.Id]; ok {
		state.AddResponse(msg.ShareIndex, msg.Response)
		return nil
	}	
	return errors.New("Promise specified does not exist.")
}
