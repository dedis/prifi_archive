package insure

import (
	"container/list"
	
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/config"
	"github.com/dedis/crypto/poly"
	"github.com/dedis/crypto/random"
	
	"github.com/dedis/prifi/coco/connMan"
)

type PolicyStatus int

const (
	PolicyError PolicyStatus = iota
	PolicyUninitialized
	PolicySetup
	PolicyReady
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

	// Denotes the current status of the policy.
	policyStatus PolicyStatus
	
	// This stores the secrets of other nodes this server is insuring.
	// The map is: abstract.Point.String() => RequestInsuranceMessage
	insuredClients map[string]*RequestInsuranceMessage
	
	// The connection manager to use for this policy
	cman connMan.ConnManager
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
func (lp *LifePolicy) Init(keyPair *config.KeyPair, cman connMan.ConnManager) *LifePolicy {
	lp.keyPair        = keyPair
	lp.policyStatus   = PolicyUninitialized
	lp.insuredClients = make(map[string]*RequestInsuranceMessage)
	lp.cman           = cman
	return lp
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
func (lp *LifePolicy) GetPolicyProof()  *list.List {
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

func (lp *LifePolicy) TakeOutPolicy(serverList []abstract.Point,
	selectInsurers func([]abstract.Point, int) ([]abstract.Point, bool), n int) (*LifePolicy, bool) {

	// If n is less than the expected number of shares to reconstruct the
	// secret, fail
	if n < TSHARES {
		return lp, false
	}

	// Initialize the policy.
	ok := true

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
	pripoly := new(poly.PriPoly).Pick(INSURE_GROUP, TSHARES,
		lp.keyPair.Secret, random.Stream)
	prishares := new(poly.PriShares).Split(pripoly, n)
	pubPoly := new(poly.PubPoly)
	pubPoly.Init(INSURE_GROUP, n, nil)
	pubPoly = new(poly.PubPoly).Commit(pripoly, nil)


	// Denote that the policy is now in the setup stage and ready to begin
	// receiving PolicyApproveMessages.
	lp.policyStatus = PolicySetup

	// Send each share off to the appropriate server.
	for i := 0; i < n; i++ {
		requestMsg := new(RequestInsuranceMessage).createMessage(lp.keyPair.Public, i, prishares.Share(i), pubPoly)	
		lp.cman.Put(lp.insurersList[i], new(PolicyMessage).createRIMessage(requestMsg))	
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
			lp.cman.Get(lp.insurersList[i], msg)
			msgType, ok := lp.handlePolicyMessage(msg)
						
			// Merely for efficiency, to update the receive list.
			if msgType == PolicyApproved {
				receivedList[i] = ok
			}
		}
	}

	lp.policyStatus = PolicyReady 
	return lp, ok
}


/* This function handles policy messages received. This function will handle
 * updating the life policy appropriately. Simply give it the policy message
 * and let it handle it.
 *
 * Arguments:
 *   msg = the message to handle
 *
 * Returns:
 *      - The type of message received.
 *	- true if the request was a new one and handled properly. 
 *        false otherwise.
 *
 * NOTE: False need not be alarming. For example, if one node sends a duplicate
 * request, the policy can simply ignore the duplicate and return false.
 */
func (lp *LifePolicy) handlePolicyMessage(msg * PolicyMessage) (MessageType, bool) {		
	switch msg.Type {
		case RequestInsurance:
			return RequestInsurance, lp.handleRequestInsuranceMessage(msg.getRIM())
		case PolicyApproved:
			return PolicyApproved, lp.handlePolicyApproveMessage(msg.getPAM())
	}
	return Error, false
}

/* This method handles RequestInsuranceMessages. If another node requests to be insured,
 * verify that the share it sent is valid. If so, insure it and send a confirmation
 * message back.
 *
 * Arguments:
 *   msg = the message requesting insurance
 *
 * Returns:
 *	Whether or not the request was accepted.
 */
func (lp *LifePolicy) handleRequestInsuranceMessage(msg * RequestInsuranceMessage) bool {

	// TODO: Uncomment that after dealing with PubCommit error.
	//if !msg.PubCommit.Check(int(msg.ShareNumber.V.Int64()), msg.Share) {
	//	return false
	//}
		
	// If we are already insuring this key, fail.
	if _, exists := lp.insuredClients[msg.PubKey.String()]; exists {
		panic("OH NO! To bad.")
		return false
	}

	// Otherwise, add the message to the hash of insured clients
	// and send back an approve message.
	lp.insuredClients[msg.PubKey.String()] = msg

	reply := new(PolicyApprovedMessage).createMessage(lp.keyPair, msg.PubKey)
	lp.cman.Put(msg.PubKey, new(PolicyMessage).createPAMessage(reply))
	return true
}

/* This method handles RequestInsuranceMessages. If another node requests to be insured,
 * verify that the share it sent is valid. If so, insure it and send a confirmation
 * message back.
 *
 * Arguments:
 *   msg = the message requesting insurance
 *
 * Returns:
 *	Whether or not the request was accepted.
 */
func (lp *LifePolicy) handlePolicyApproveMessage(msg * PolicyApprovedMessage) bool {
	
	// If the policy has not been taken out yet, ignore the message.
	if lp.policyStatus == PolicyUninitialized {
		return false
	}

	// If the certificate is invalid, fail and don't receive it.
	if !msg.verifyCertificate(lp.keyPair.Suite, lp.keyPair.Public) {
		return false
	}

	// If this server has already received an approval message from the 
	// sender, ignore it	
	for nextElt := lp.proofList.Front(); nextElt != nil; nextElt = nextElt.Next() {
		if msg.PubKey.Equal(nextElt.Value.(*PolicyApprovedMessage).PubKey) {
			return false	
		}
	}
	
	// Ignore the message if not sent from an insurer.
	fromInsurer := false
	for i := 0; i < len(lp.insurersList); i++ {
		if msg.PubKey.Equal(lp.insurersList[i]) {
			fromInsurer = true
		}
	}
	if !fromInsurer {
		return false
	}

	// Otherwise, add it to the list	
	lp.proofList.PushBack(msg)
	return true
}

