package insure

import (
	"container/list"
	
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/config"
	"github.com/dedis/crypto/poly"
	"github.com/dedis/crypto/random"
	
	"github.com/dedis/prifi/coco/connMan"
)

/* This file provides an implementation of the Policy interface via
 * the struct LifePolicy. Check the other files in this package for more
 * on the Policy interface and the life insurance protocol in general.
 *
 * To create a policy:
 * newPolicy, ok := new(LifePolicy).TakeOutPolicy(MyKeyPair,
 *    ListOfPotentialServers, functionForSelectingServers,
 *    MinimumNumberOfSharesToReconstructSecret, NumberOfInsurers)
 *
 * For safety measures, the function returns nil if the policy fails to be
 * created along with an updated status in ok.
 */

type LifePolicy struct {
	// The key that is being insured.
	keyPair *config.KeyPair

	// A list of the public keys of the insurers of this policy
	insurersList []abstract.Point

	// Digitial Signatures that serve as "proof of insurance"
	// The PolicyApprovedMessage contains the signatures.
	proofList *list.List

	// Denotes whether or not a policy has been taken out yet.
	hasPolicy bool
	
	// This stores the secrets of other nodes this server is insuring.
	// The map is: abstract.Point.String() => abstract.Secret
	insuredClients map[string]abstract.Secret
}


/* This method initializes a policy. This function should be called first before
 * using the policy in any manner. After being initialize, the policy will be
 * able to insure other clients. However, it will not provide a policy for the
 * owner server until TakeOutPolicy has been called.
 *
 * Arguments:
 *   keyPair         = the public/private key of the owner server
 *
 */
func (lp *LifePolicy) Init(keyPair *config.KeyPair) *list.List {
	lp.keyPair = keyPair
	lp.hasPolicy = false
	lp.insuredClients = make(map[string]abstract.Secret)
	return lp.proofList
}

// Returns the private key that is being insured.
func (lp *LifePolicy) getKeyPair() *config.KeyPair {
	return lp.keyPair
}

// Returns the list of insurers for the policy.
func (lp *LifePolicy) GetInsurers() []abstract.Point {
	return lp.insurersList
}

// Returns the certificates of the insurers for each policy.
func (lp *LifePolicy) GetPolicyProof() *list.List {
	return lp.proofList
}


/* This function selects a set of servers to serve as insurers.
 * This is an extremely rudimentary version that selects the first
 * n servers from the list.
 *
 * Arguments:
 *    serverList = the list of servers to choose from
 *    n          = the number of servers to choose
 *
 * Returns:
 *   The list of servers to server as insurers or nil if not enough servers
 *   Whether or not the function terminated successfully
 *      (i.e. whether there are at least n elements in the array)
 */

func selectInsurersBasic(serverList []abstract.Point, n int) ([]abstract.Point, bool) {
	if n < len(serverList) {
		return nil, false
	}

	return serverList[:n], true
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
 *   cman            = the connection manager for sending messages.
 *   t               = the minimum number of shares to reconstruct the secret
 *   n               = the total shares to be distributed
 *
 *
 * Note: If selectInsurers is null, the policy will resort to a default
 * selection function.
 */

func (lp *LifePolicy) TakeOutPolicy(keyPair *config.KeyPair, serverList []abstract.Point,
	selectInsurers func([]abstract.Point, int) ([]abstract.Point, bool),
	cman connMan.ConnManager, n int) (*LifePolicy, bool) {

	// If n is less than the expected number of shares to reconstruct the
	// secret, fail
	if n < TSHARES {
		return lp, false
	}

	// Initialize the policy.
	ok := true
	lp.keyPair = keyPair

	// If we have no selectInsurers function, use the basic algorithm.
	if selectInsurers == nil {
		lp.insurersList, ok = selectInsurersBasic(serverList, n)
		if !ok || len(lp.insurersList) < n {
			return nil, ok
		}
	} else {
		// Otherwise use the function provided.
		lp.insurersList, ok = selectInsurers(serverList, n)
		if !ok || len(lp.insurersList) < n {
			return nil, ok
		}
	}
	//TODO: Use bytes maybe?
	lp.proofList = new(list.List)

	// Create a new polynomial from the private key where t
	// shares are needed to reconstruct the secret. Then, split it
	// into secret shares and create the public polynomial.
	pripoly := new(poly.PriPoly).Pick(keyPair.Suite, TSHARES,
		keyPair.Secret, random.Stream)
	prishares := new(poly.PriShares).Split(pripoly, n)
	pubPoly := new(poly.PubPoly).Commit(pripoly, keyPair.Public)


	// Send each share off to the appropriate server.
	for i := 0; i < n; i++ {
		requestMsg := new(RequestInsuranceMessage).createMessage(keyPair.Public, i, prishares.Share(i), pubPoly)
		cman.Put(lp.insurersList[i], new(PolicyMessage).createRIMessage(requestMsg))	
	}

	receivedList := make([]bool, len(lp.insurersList))

	// TODO: Add a timeout such that this process will end after a certain
	// time and a new batch of insurers can be picked.
	// TODO: Make it so that it stops as soon as we get R other insurers
	// for t <= r <= n
	for lp.proofList.Len() < n {

		for i := 0; i < n; i++ {
			// If we have already received a certificate for this
			// node, move on.
			if receivedList[i] == true {
				continue
			}
		
			msg := new(PolicyMessage)
			cman.Get(lp.insurersList[i], msg)
			
			// If we got an approve message and it is valid, add it
			// to our list of proofs and remove the node from the
			// temporary insurer list.
			if msg.Type == PolicyApproved &&
			   msg.getPAM().verifyCertificate(keyPair.Suite, keyPair.Public){
				receivedList[i] = true
				lp.proofList.PushBack(msg.getPAM())
			}
		}
	}

	lp.hasPolicy = true
	return lp, ok
}


/*
func handlePolicyMessage() {

	for true {
		msg := new(PolicyMessage)
		cm.Get(keyPairT.Public, msg)
			
		// If a RequestInsuranceMessage, send an acceptance message and then
		// exit.
		if msg.Type == RequestInsurance {
			reply := new(PolicyApprovedMessage).createMessage(k, msg.getRIM().PubKey)
			cm.Put(msg.getRIM().PubKey, new(PolicyMessage).createPAMessage(reply))
			
			// Send a duplicate to make sure that our insurance policy doesn't add
			// the same message from the same source twice.
			cm.Put(msg.getRIM().PubKey, new(PolicyMessage).createPAMessage(reply))	
			return
		}
	}
}

/* This method handles RequestInsuranceMessages. If another node requests to be insured,
 * verify that the share it sent is valid. If so, insure it and send a confirmation
 * message back.
 *
 * Arguments:
 *   msg = the message requesting insurance
 *
 *
 * Note: If selectInsurers is null, the policy will resort to a default
 * selection function.
 * /
func (lp *LifePolicy) handleRequestInsuranceMessage(msg * RequestInsuranceMessage) {
	reply := new(PolicyApprovedMessage).createMessage(lp.keyPair, msg.getRIM().PubKey)
	cm.Put(msg.getRIM().PubKey, new(PolicyMessage).createPAMessage(reply))
}
*/
