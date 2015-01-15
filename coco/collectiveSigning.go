package coco

import (
	"crypto/cipher"
	"github.com/dedis/crypto/abstract"
	"errors"
	"fmt"
	"time"
	// "strconv"
	// "os"
)

// Collective Signing via ElGamal
// 1. Announcement
// 2. Commitment
// 3. Challenge
// 4. Response

type SigningNode struct{
	Host
	// hostNode HostNode
	suite	 abstract.Suite 
	pubKey 	 abstract.Point       // long lasting public key
	privKey  abstract.Secret      // long lasting private key

	v        abstract.Secret      // round lasting secret
	V        abstract.Point       // round lasting commitment point
	c  	     abstract.Secret      // round lasting challenge
	r 		 abstract.Secret      // round lasting response

	V_hat 	 abstract.Point 	  // aggregate of commit points
	r_hat 	 abstract.Secret 	  // aggregate of responses
	X_hat 	 abstract.Point 	  // aggregate of public keys

	logTest []byte				  // for testing purposes	
}

// Broadcasted message initiated and signed by proposer
type AnnouncementMessage struct{
	logTest []byte
}

type CommitmentMessage struct{
	V 	   abstract.Point 		// commitment Point
	V_hat  abstract.Point       // product of children's commitment points
}

type ChallengeMessage struct{
	c  abstract.Secret 			// challenge
}

type ResponseMessage struct{
	r  abstract.Secret 			// response
}

func NewSigningNode(hn *HostNode, suite abstract.Suite, random cipher.Stream) *SigningNode{
	sn := &SigningNode{Host: hn, suite: suite}
	sn.privKey = suite.Secret().Pick(random)
	sn.pubKey = suite.Point().Mul(nil, sn.privKey)
	return sn
}

// Start listening for messages coming from parent(up)
func (sn *SigningNode) Listen(){
	go func() {
		for {
			if ! sn.IsRoot() {
				data := sn.GetUp()

				sn.HandleFromUp(data)
			} else {
				// fmt.Println("I am root")
				time.Sleep(1 * time.Second)
			}
		}
	} ()
}

// Determine type of message coming from the parent
// Pass the duty of acting on it to another function
func (sn *SigningNode) HandleFromUp( data interface{} ){
	switch messg := data.(type) {
		default:
			// Not possible in current system where little randomness is allowed
			// In real system some action is required
			panic("Message from parent is of unknown type")
		case AnnouncementMessage:
			sn.Announce(messg)
		case ChallengeMessage:
			sn.Challenge(messg)
	}	
}

// initiated by root, propagated by all others
func (sn *SigningNode) Announce( am AnnouncementMessage ){
	// inform all children of announcement
	sn.PutDown(am)
	// initiate commit phase
	sn.Commit()
}

func (sn *SigningNode) Commit( ){
	// generate secret and point commitment for this round
	rand := abstract.HashStream(sn.suite, []byte(sn.Name()), nil)   // change me  
	sn.v = sn.suite.Secret().Pick(rand)
	sn.V = sn.suite.Point().Mul(nil, sn.v)
	sn.V_hat = sn.V
	// wait for all children to commit
	dataSlice := sn.GetDown()
	for _, data := range(dataSlice) {
		switch cm := data.(type) {
		default:
			// Not possible in current system where little randomness is allowed
			// In real system failing is required
			fmt.Println(cm)
			panic("Reply to announcement is not a commit")
		case CommitmentMessage:
			sn.V_hat.Add(sn.V_hat, cm.V_hat)      
		}
	}
	if sn.IsRoot() {
		fmt.Println(sn.Name(), "finalizing commit")
		sn.FinalizeCommits()
	} else {
		// create and putup own commit message
		sn.PutUp(CommitmentMessage{sn.V, sn.V_hat})
	}
}

// initiated by root, propagated by all others
func (sn *SigningNode) Challenge( cm ChallengeMessage ){
	// register challenge
	sn.c = cm.c
	// inform all children of challenge
	sn.PutDown(cm)
	// initiate response phase
	sn.Respond()
}

func (sn *SigningNode) Respond(){
	// generate response   r = v - xc
	sn.r = sn.suite.Secret()
	sn.r.Mul(sn.privKey, sn.c).Sub(sn.v, sn.r)
	// initialize sum of children's responses + own response
	sn.r_hat = sn.suite.Secret()
	sn.r_hat.Set(sn.r)
	// wait for all children to respond
	dataSlice := sn.GetDown()
	for _, data := range(dataSlice) {
		switch rm := data.(type) {
		default:
			// Not possible in current system where little randomness is allowed
			// In real system failing is required
			panic("Reply to challenge is not a response")
		case ResponseMessage:
			sn.r_hat.Add(sn.r_hat, rm.r)
		}
	}

	if sn.IsRoot() {
		fmt.Println(sn.Name(), "verifying response")
		sn.VerifyResponses()
	} else {			
		// create and putup own response message
		sn.PutUp(ResponseMessage{sn.r_hat})
	}
}

// Called *only* by root node after receiving all commits
func (sn *SigningNode) FinalizeCommits(){
	// challenge = Hash(message, sn.V_hat) 
	fmt.Println(sn.logTest)
	fmt.Println(sn.V_hat)
	sn.c = hashElGamal(sn.suite, sn.logTest, sn.V_hat)
	sn.Challenge(ChallengeMessage{sn.c})
}

// Called *only* by root node after receiving all responses
func (sn *SigningNode) VerifyResponses() error{
	// Check that: base**r_hat * X_hat**c == V_hat 
	// Equivalent to base**(r+xc) == base**(v) == T in vanillaElGamal
	var P, T abstract.Point
	P = sn.suite.Point()
	T = sn.suite.Point()
	T.Add(T.Mul(nil, sn.r_hat), P.Mul(sn.X_hat, sn.c))
	c2 := hashElGamal(sn.suite, sn.logTest, T)

	fmt.Println(sn.logTest)
	fmt.Println(T)
	if sn.c != c2 {
		fmt.Println(sn.c)
		fmt.Println(c2)
		// panic("Veryfing ElGamal Collective Signature failed")
		return errors.New("Veryfing ElGamal Collective Signature failed")
	}
	fmt.Println("ElGamal Collective Signature succeeded")
	return nil
}

// This function has to be eventually removed
// Returns a secret that depends on on a message and a point
func hashElGamal(suite abstract.Suite, message []byte, p abstract.Point) abstract.Secret {
	H := suite.Hash()
	H.Write(message)
	H.Write(p.Encode())

	b := H.Sum(nil)
	s := suite.Stream(b[:suite.KeyLen()])
	return suite.Secret().Pick(s)
}