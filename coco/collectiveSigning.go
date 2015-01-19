package coco

import (
	"errors"
	"fmt"

	"github.com/dedis/crypto/abstract"
	// "strconv"
	// "os"
)

// Collective Signing via ElGamal
// 1. Announcement
// 2. Commitment
// 3. Challenge
// 4. Response

// Start listening for messages coming from parent(up)
func (sn *SigningNode) Listen() {
	go func() {
		for {
			if sn.IsRoot() {
				// Sleep/ Yield until change in network
				sn.WaitTick()
			} else {
				// Determine type of message coming from the parent
				// Pass the duty of acting on it to another function
				sm := SigningMessage{}
				if err := sn.GetUp(&sm); err != nil {
					panic("could not get up message in listen " + err.Error())
				}
				switch sm.Type {
				default:
					// Not possible in current system where little randomness is allowed
					// In real system some action is required
					panic("Message from parent is of unknown type")
				case Announcement:
					sn.Announce(sm.am)
				case Challenge:
					sn.Challenge(sm.chm)
				}
			}
		}
	}()
}

// initiated by root, propagated by all others
func (sn *SigningNode) Announce(am *AnnouncementMessage) {
	//fmt.Println(sn.Name(), "announces")
	// Inform all children of announcement
	// PutDown requires each child to have his own message
	messgs := make([]BinaryMarshaler, sn.NChildren())
	for i := range messgs {
		sm := SigningMessage{Type: Announcement, am: am}
		messgs[i] = sm
	}
	if err := sn.PutDown(messgs); err != nil {
		panic("could not put down all Annoucement Messages" + err.Error())
	}
	// initiate commit phase
	sn.Commit()
}

func (sn *SigningNode) Commit() {
	// generate secret and point commitment for this round
	rand := sn.suite.Cipher([]byte(sn.Name()))
	sn.v = sn.suite.Secret().Pick(rand)
	sn.V = sn.suite.Point().Mul(nil, sn.v)
	// initialize product of point commitments
	sn.V_hat = sn.V
	// grab space for children messages
	messgs := make([]BinaryUnmarshaler, sn.NChildren())
	for i := range messgs {
		messgs[i] = &SigningMessage{}
	}
	// wait for all children to commit
	if err := sn.GetDown(messgs); err != nil {
		panic("could not get down all Commit Messages" + err.Error())
	}
	for _, messg := range messgs {
		sm := messg.(*SigningMessage)
		switch sm.Type {
		default:
			// Not possible in current system where little randomness is allowed
			// In real system failing is required
			fmt.Println(sm.com)
			panic("Reply to announcement is not a commit")
		case Commitment:
			sn.V_hat.Add(sn.V_hat, sm.com.V_hat)
		}
	}
	if sn.IsRoot() {
		sn.FinalizeCommits()
	} else {
		// create and putup own commit message
		sn.PutUp(SigningMessage{
			Type: Commitment,
			com:  &CommitmentMessage{V: sn.V, V_hat: sn.V_hat}})
	}
}

// initiated by root, propagated by all others
func (sn *SigningNode) Challenge(chm *ChallengeMessage) {
	// register challenge
	sn.c = chm.C
	// inform all children of challenge
	// PutDown requires each child to have his own message
	messgs := make([]BinaryMarshaler, sn.NChildren())
	for i := range messgs {
		sm := SigningMessage{Type: Challenge, chm: chm}
		messgs[i] = sm
	}
	if err := sn.PutDown(messgs); err != nil {
		panic("could not put down all Challenge Messages" + err.Error())
	}
	// initiate response phase
	sn.Respond()
}

func (sn *SigningNode) Respond() {
	// generate response   r = v - xc
	sn.r = sn.suite.Secret()
	sn.r.Mul(sn.privKey, sn.c).Sub(sn.v, sn.r)
	// initialize sum of children's responses
	sn.r_hat = sn.r
	// wait for all children to respond
	messgs := make([]BinaryUnmarshaler, sn.NChildren())
	for i := range messgs {
		messgs[i] = &SigningMessage{}
	}
	if err := sn.GetDown(messgs); err != nil {
		panic("could not get down all Respond Messages" + err.Error())
	}
	for _, messg := range messgs {
		sm := messg.(*SigningMessage)
		switch sm.Type {
		default:
			// Not possible in current system where little randomness is allowed
			// In real system failing is required
			panic("Reply to challenge is not a response")
		case Response:
			sn.r_hat.Add(sn.r_hat, sm.rm.R_hat)
		}
	}

	sn.VerifyResponses()
	if !sn.IsRoot() {
		// create and putup own response message
		sn.PutUp(SigningMessage{
			Type: Response,
			rm:   &ResponseMessage{sn.r_hat}})
	}
}

// Called *only* by root node after receiving all commits
func (sn *SigningNode) FinalizeCommits() {
	// challenge = Hash(message, sn.V_hat)
	sn.c = hashElGamal(sn.suite, sn.logTest, sn.V_hat)
	sn.Challenge(&ChallengeMessage{C: sn.c})
}

// Called by every node after receiving aggregate responses from descendants
func (sn *SigningNode) VerifyResponses() error {
	// Check that: base**r_hat * X_hat**c == V_hat
	// Equivalent to base**(r+xc) == base**(v) == T in vanillaElGamal
	var P, T abstract.Point
	P = sn.suite.Point()
	T = sn.suite.Point()
	T.Add(T.Mul(nil, sn.r_hat), P.Mul(sn.X_hat, sn.c))
	c2 := hashElGamal(sn.suite, sn.logTest, T)

	// intermediary nodes check partial responses aginst their partial keys
	// the root node is also able to check against the challenge it emitted
	if !T.Equal(sn.V_hat) || (sn.IsRoot() && !sn.c.Equal(c2)) {
		fmt.Println(sn.Name(), "reports ElGamal Collective Signature failed")
		return errors.New("Veryfing ElGamal Collective Signature failed")
	}

	//fmt.Println(sn.Name(), "reports ElGamal Collective Signature succeeded")
	return nil
}

// Returns a secret that depends on on a message and a point
func hashElGamal(suite abstract.Suite, message []byte, p abstract.Point) abstract.Secret {
	c := suite.Cipher(p.Encode(), abstract.More{})
	c.Crypt(nil, message)
	return suite.Secret().Pick(c)
}
