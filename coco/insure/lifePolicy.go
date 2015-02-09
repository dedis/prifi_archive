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
	// Private Key that is being insured.
	privateKey abstract.Secret

	// A list of the public keys of the insurers of this policy
	insurersList []abstract.Point

	// Digitial Signatures that serve as "proof of insurance"
	// The PolicyApprovedMessage contains the signatures.
	proofList *list.List
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

// Returns the private key that is being insured.
func (lp *LifePolicy) GetPrivateKey() abstract.Secret {
	return lp.privateKey
}

// Returns the list of insurers for the policy.
func (lp *LifePolicy) GetInsurers() []abstract.Point {
	return lp.insurersList
}

// Returns the certificates of the insurers for each policy.
func (lp *LifePolicy) GetPolicyProof() *list.List {
	return lp.proofList
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

func (lp *LifePolicy) TakeOutPolicy(keyPair config.KeyPair, serverList []abstract.Point,
	selectInsurers func([]abstract.Point, int) ([]abstract.Point, bool),
	cman connMan.ConnManager, t int, n int) (*LifePolicy, bool) {

	// Initialize the policy.
	ok := true
	lp.privateKey = keyPair.Secret

	// If we have no selectInsurers function, use the basic algorithm.
	if selectInsurers == nil {
		lp.insurersList, ok = selectInsurersBasic(serverList, n)
		if !ok {
			return nil, ok
		}
	} else {
		// Otherwise use the function provided.
		lp.insurersList, ok = selectInsurers(serverList, n)
		if !ok {
			return nil, ok
		}
	}
	//TODO: Use bytes maybe?
	lp.proofList = new(list.List)

	// Create a new polynomial from the private key where t
	// shares are needed to reconstruct the secret. Then, split it
	// into secret shares and create the public polynomial.
	pripoly := new(poly.PriPoly).Pick(keyPair.Suite, t,
		keyPair.Secret, random.Stream)
	prishares := new(poly.PriShares).Split(pripoly, n)
	pubPoly := new(poly.PubPoly).Commit(pripoly, keyPair.Public)


	// Send each share off to the appropriate server.
	for i := 0; i < n; i++ {
		requestMsg := new(RequestInsuranceMessage).createMessage(prishares.Share(i), pubPoly)
		cman.Put(lp.insurersList[i], new(PolicyMessage).createRIMessage(requestMsg))	
	}

	insurersListTemp := make([]abstract.Point, len(lp.insurersList))
	copy(insurersListTemp, lp.insurersList)

	// TODO: Add a timeout such that this process will end after a certain
	// time and a new batch of insurers can be picked.
	// TODO: Make it so that it stops as soon as we get R other insurers
	// for t <= r <= n
	for lp.proofList.Len() < n {

		for i := 0; i < n; i++ {
			// If we have already received a certificate for this
			// node, move on.
			if insurersListTemp[i] == nil {
				continue
			}
		
			msg := new(PolicyMessage)
			cman.Get(lp.insurersList[i], msg)
			
			// If we got an approve message and it is valid, add it
			// to our list of proofs and remove the node from the
			// temporary insurer list.
			if msg.Type == PolicyApproved &&
			   msg.getPAM().verifyCertificate(keyPair.Suite, keyPair.Public){
				insurersListTemp[i] = nil
				lp.proofList.PushBack(msg.getPAM())
			}
		}
	}

	return lp, ok
}
