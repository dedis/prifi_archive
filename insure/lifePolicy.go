package insure

import (
	"container/list"
	"errors"
	
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

/* This file provides an implementation of the life insurance policy. Coco
 * servers will each carry their own policies and will be required to take one
 * out before participating in the system. At any point, they should be ready to
 * prove that they carry a valid policy. For a detailed summary of the insurance
 * policy protocol, please see doc.go
 *
 * To create a policy:
 * newPolicy, ok := new(LifePolicy).Init(KeyPairOfServer, ConnectionManager).TakeOutPolicy(
 *		ListOfInsurrers, OptionalMethodOfChoosingInsurers, GroupForPrivateShares,
 *		MinimumNumberOfPrivateSharesNeededForReconstruction, TotalNumberOfShares)
 *
 * For safety measures, the function returns nil if the policy fails to be
 * created along with an updated status in ok.
 */

type LifePolicy struct {
	// The key that is being insured.
	keyPair *config.KeyPair

	// A list of the public keys of the insurers of this policy
	insurersList []abstract.Point

	// Digitial Signatures that serve as "proof of insurance". The list
	// contains PolicyApprovedMessages with the signatures.
	proofList *list.List

	// Denotes the current status of the policy.
	policyStatus PolicyStatus
	
	// This stores the secrets of other nodes this server is insuring.
	// The map is:
	//    PublicKeyOfInsured.String() + MyPrivateShare.String() => RequestInsuranceMessage
	insuredClients map[string]*RequestInsuranceMessage
	
	// The connection manager to use for this policy
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
func (lp *LifePolicy) Init(kp *config.KeyPair, cman connMan.ConnManager) *LifePolicy {
	lp.keyPair        = kp
	lp.policyStatus   = PolicyUninitialized
	lp.insuredClients = make(map[string]*RequestInsuranceMessage)
	lp.cman           = cman
	return lp
}

// Returns the private key that is being insured.
func (lp *LifePolicy) GetKeyPair() *config.KeyPair {
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

// Returns the current status of the policy
func (lp *LifePolicy) GetStatus() PolicyStatus {
	return lp.policyStatus
}


/* This function selects a set of servers to serve as insurers. This is an
 * extremely rudimentary version that selects the first n servers from the list.
 *
 * Arguments:
 *    serverList = the list of servers to choose from
 *    n          = the number of servers to choose
 *
 * Returns:
 *   The list of servers to server as insurers or nil if not enough servers
 */

func selectInsurersBasic(serverList []abstract.Point, n int) []abstract.Point {
	if n < len(serverList) {
		return nil
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

func (lp *LifePolicy) TakeOutPolicy(serverList []abstract.Point,
	selectInsurers func([]abstract.Point, int) []abstract.Point,
	g abstract.Group, t int, n int) (*LifePolicy, bool) {

	// If n is less than the expected number of shares to reconstruct the
	// secret, fail
	if n < t {
		return lp, false
	}

	// Initialize the policy.

	// If we have no selectInsurers function, use the basic algorithm.
	if selectInsurers == nil {
		selectInsurers = selectInsurersBasic
	}
	
	lp.insurersList = selectInsurers(serverList, n)
	if lp.insurersList == nil || len(lp.insurersList) < n {
		return lp, false
	}

	//TODO: Use bytes maybe?
	lp.proofList = new(list.List)

	// Create a new polynomial from the private key where t shares are
	// needed to reconstruct the secret. Then, split it into secret shares
	// and create the public polynomial.
	pripoly := new(poly.PriPoly).Pick(g,t, lp.keyPair.Secret, random.Stream)
	prishares := new(poly.PriShares).Split(pripoly, n)
	pubPoly := new(poly.PubPoly)
	pubPoly.Init(g, n, nil)
	pubPoly = new(poly.PubPoly).Commit(pripoly, nil)

	// Mark the policy as being in the setup stage and ready to begin
	// receiving PolicyApproveMessages.
	lp.policyStatus = PolicySetup

	// Send each share off to the appropriate server.
	for i := 0; i < n; i++ {
		requestMsg := new(RequestInsuranceMessage).createMessage(
			lp.keyPair.Public, i, prishares.Share(i), pubPoly)	
		lp.cman.Put(lp.insurersList[i],
			new(PolicyMessage).createRIMessage(requestMsg))	
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
			msgType, err := lp.handlePolicyMessage(msg)
						
			// Merely for efficiency, to update the receive list.
			if msgType == PolicyApproved {
				receivedList[i] = (err == nil)
			}
		}
	}

	lp.policyStatus = PolicyReady 
	return lp, true
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
func (lp *LifePolicy) handlePolicyMessage(msg * PolicyMessage) (MessageType, error) {		
	switch msg.Type {
		case RequestInsurance:
			return RequestInsurance, lp.handleRequestInsuranceMessage(msg.getRIM())
		case PolicyApproved:
			return PolicyApproved, lp.handlePolicyApproveMessage(msg.getPAM())
	}
	return Error, errors.New("Invald message type")
}

/* This method handles RequestInsuranceMessages. If another node requests to be insured,
 * verify that the share it sent is valid. If so, insure it and send a confirmation
 * message back.
 *
 * Arguments:
 *   msg = the message requesting insurance
 *
 * Returns:
 *	the error status (possibly nil)
 */
func (lp *LifePolicy) handleRequestInsuranceMessage(msg * RequestInsuranceMessage) error {

	// Return an error if the polict has not been initialized yet.
	if lp.policyStatus == PolicyError {
		return errors.New("Policy not yet initialized.")
	}

	if !msg.PubCommit.Check(int(msg.ShareNumber.V.Int64()), msg.Share) {
		return errors.New("The private share failed PubPoly.Check.")		      
	}
		
	// If we are already insuring this key, fail.
	keyValue := msg.PubKey.String() + msg.Share.String()
	if _, exists := lp.insuredClients[keyValue]; exists {
		return errors.New("Already insuring this policy.")
	}

	// Otherwise, add the message to the hash of insured clients and send
	// back an approve message.
	lp.insuredClients[keyValue] = msg

	reply := new(PolicyApprovedMessage).createMessage(lp.keyPair, msg.PubKey)
	lp.cman.Put(msg.PubKey, new(PolicyMessage).createPAMessage(reply))
	return nil
}

/* This method handles RequestInsuranceMessages. If another node requests to be
 * insured, verify that the share it sent is valid. If so, insure it and send a
 * confirmation message back.
 *
 * Arguments:
 *   msg = the message requesting insurance
 *
 * Returns:
 *	Whether or not the request was accepted.
 */
func (lp *LifePolicy) handlePolicyApproveMessage(msg * PolicyApprovedMessage) error {
	
	// If the policy has not been taken out yet, ignore the message.
	if lp.policyStatus == PolicyUninitialized ||
	   lp.policyStatus == PolicyError {
		return errors.New("Policy not yet initialized.")
	}

	// If the certificate is invalid, fail and don't receive it.
	if !msg.verifyCertificate(lp.keyPair.Suite, lp.keyPair.Public) {
		return errors.New("The digital signature failed to be validated.")
	}

	// If this server has already received an approval message from the 
	// sender, ignore it	
	for nextElt := lp.proofList.Front(); nextElt != nil; nextElt = nextElt.Next() {
		if msg.PubKey.Equal(nextElt.Value.(*PolicyApprovedMessage).PubKey) {
			return errors.New("Duplicate approval message.")	
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
		return errors.New("Unsolicited approval message received.")
	}

	// Otherwise, add it to the list	
	lp.proofList.PushBack(msg)
	return nil
}

