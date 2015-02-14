package sign

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"sort"
	"strconv"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/prifi/coco/coconet"
	"github.com/dedis/prifi/coco/hashid"
	"github.com/dedis/prifi/coco/proof"
	// "strconv"
	// "os"
)

// Collective Signing via ElGamal
// 1. Announcement
// 2. Commitment
// 3. Challenge
// 4. Response

var ErrUnknownMessageType error = errors.New("Received message of unknown type")

// Start listening for messages coming from parent(up)
func (sn *SigningNode) Listen() error {
	for {
		if sn.IsRoot() {
			// Sleep/ Yield until change in network
			sn.WaitTick()
		} else {
			// Determine type of message coming from the parent
			// Pass the duty of acting on it to another function
			sm := SigningMessage{}
			if err := sn.GetUp(&sm); err != nil {
				return err
			}
			switch sm.Type {
			default:
				// Not possible in current system where little randomness is allowed
				// In real system some action is required
				return ErrUnknownMessageType
			case Announcement:
				sn.Announce(sm.Am)
			case Challenge:
				sn.Challenge(sm.Chm)
			}
		}
	}
	return nil
}

// initiated by root, propagated by all others
func (sn *SigningNode) Announce(am *AnnouncementMessage) error {
	// Inform all children of announcement
	// PutDown requires each child to have his own message
	messgs := make([]coconet.BinaryMarshaler, sn.NChildren())
	for i := range messgs {
		sm := SigningMessage{Type: Announcement, Am: am}
		messgs[i] = sm
	}
	if err := sn.PutDown(messgs); err != nil {
		return err
	}
	// initiate commit phase
	return sn.Commit()
}

// Used in Commit and Respond to get commits and responses from all
// children before creating own commit and response
// Messages from children are returns in STRICT order
// ith message = message from ith child
func (sn *SigningNode) getDownMessgs() ([]coconet.BinaryUnmarshaler, error) {
	// grab space for children messages
	messgs := make([]coconet.BinaryUnmarshaler, sn.NChildren())
	for i := range messgs {
		messgs[i] = &SigningMessage{}
	}

	// update waiting time based on current depth
	// and wait for all children to commit
	sn.UpdateTimeout()
	err := sn.GetDown(messgs)
	if err != nil {
		log.Println(sn.Name(), "getDown error\t\t\t", err)
	}

	// log rather than propagate network TimeoutOut errors
	if err == coconet.TimeoutError {
		log.Println(sn.Name() + err.Error())
		err = nil
	}
	return messgs, err
}

func (sn *SigningNode) GetChildrenMerkleRoots() {
	// children commit roots
	sn.CMTRoots = make([]hashid.HashId, len(sn.Leaves))
	copy(sn.CMTRoots, sn.Leaves)

	// concatenate children commit roots in one binary blob for easy marshalling
	sn.Log.CMTRoots = make([]byte, 0)
	for _, leaf := range sn.Leaves {
		sn.Log.CMTRoots = append(sn.Log.CMTRoots, leaf...)
	}
}

func (sn *SigningNode) GetLocalMerkleRoot() {
	// add own local mtroot to leaves
	if sn.CommitFunc != nil {
		sn.LocalMTRoot = sn.CommitFunc()
	} else {
		sn.LocalMTRoot = make([]byte, hashid.Size)
	}
	sn.Leaves = append(sn.Leaves, sn.LocalMTRoot)
	sn.LocalMTRootIndex = len(sn.Leaves) - 1

}

func (sn *SigningNode) ComputeCombinedMerkleRoot() {
	// add hash of whole log to leaves
	sn.Leaves = append(sn.Leaves, sn.HashedLog)

	// compute MT root based on Log as right child and
	// MT of leaves as left child and send it up to parent
	sort.Sort(hashid.ByHashId(sn.Leaves))
	left, proofs := proof.ProofTree(sn.GetSuite().Hash, sn.Leaves)
	right := sn.HashedLog
	moreLeaves := make([]hashid.HashId, 0)
	moreLeaves = append(moreLeaves, left, right)
	sn.MTRoot, _ = proof.ProofTree(sn.GetSuite().Hash, moreLeaves)

	// Hashed Log has to come first in the proof
	sn.Proofs = make([]proof.Proof, len(sn.CMTRoots)+1) // +1 for local proof
	for i := 0; i < len(sn.Proofs); i++ {
		sn.Proofs[i] = append(sn.Proofs[i], right)
	}

	// separate proofs by children (need to send personalized proofs to children)
	// also separate local proof (need to send it to timestamp server)
	sn.SeparateProofs(proofs, sn.Leaves)
}

// Create round lasting secret and commit point v and V
// Initialize log structure for the round
func (sn *SigningNode) initCommitCrypto() {
	// generate secret and point commitment for this round
	rand := sn.suite.Cipher([]byte(sn.Name()))
	sn.Log = SNLog{}
	sn.Log.v = sn.suite.Secret().Pick(rand)
	sn.Log.V = sn.suite.Point().Mul(nil, sn.Log.v)
	// initialize product of point commitments
	sn.Log.V_hat = sn.suite.Point().Null()
	sn.add(sn.Log.V_hat, sn.Log.V)

	sn.X_hat = sn.suite.Point().Null()
	sn.add(sn.X_hat, sn.PubKey)
}

func (sn *SigningNode) Commit() error {
	sn.initCommitCrypto()

	// get commits from kids
	messgs, err := sn.getDownMessgs()
	if err != nil {
		return err
	}

	// prepare to handle exceptions
	sn.ExceptionList = make([]abstract.Point, 0)
	sn.ChildV_hat = make([]abstract.Point, len(sn.Children()))
	sn.ChildX_hat = make([]abstract.Point, len(sn.Children()))
	children := sn.Children()

	// Commits from children are the first Merkle Tree leaves for the round
	sn.Leaves = make([]hashid.HashId, 0)

	for i, messg := range messgs {
		sm := messg.(*SigningMessage)
		switch sm.Type {
		default: // default == no response from i
			// fmt.Println(sn.Name(), "no commit from", i)
			sn.ExceptionList = append(sn.ExceptionList, children[i].PubKey())
			// take note of lack of pub keys and commit points from i
			sn.ChildX_hat[i] = sn.suite.Point().Null()
			sn.ChildV_hat[i] = sn.suite.Point().Null()
			continue
		case Commitment:
			sn.Leaves = append(sn.Leaves, sm.Com.MTRoot)
			sn.ChildV_hat[i] = sm.Com.V_hat
			sn.ChildX_hat[i] = sm.Com.X_hat
			sn.ExceptionList = append(sn.ExceptionList, sm.Com.ExceptionList...)

			// add good child server to combined public key, and point commit
			sn.add(sn.X_hat, sm.Com.X_hat)
			sn.add(sn.Log.V_hat, sm.Com.V_hat)
		}
	}

	if sn.Type == PubKey {
		return sn.actOnCommits()
	} else {
		sn.GetChildrenMerkleRoots()
		sn.GetLocalMerkleRoot()
		sn.HashLog()
		sn.ComputeCombinedMerkleRoot()
		return sn.actOnCommits()
	}
}

// Finalize commits by initiating the challenge pahse if root
// Send own commitment message up to parent if non-root
func (sn *SigningNode) actOnCommits() (err error) {
	if sn.IsRoot() {
		err = sn.FinalizeCommits()
	} else {
		// create and putup own commit message
		com := &CommitmentMessage{
			V:             sn.Log.V,
			V_hat:         sn.Log.V_hat,
			X_hat:         sn.X_hat,
			MTRoot:        sn.MTRoot,
			ExceptionList: sn.ExceptionList}

		if sn.TestingFailures == true &&
			(sn.Host.(*coconet.FaultyHost).IsDead() ||
				sn.Host.(*coconet.FaultyHost).IsDeadFor("commit")) {
			fmt.Println(sn.Name(), "dead for commits")
			return
		}

		err = sn.PutUp(SigningMessage{
			Type: Commitment,
			Com:  com})
	}
	return
}

func (sn *SigningNode) VerifyAllProofs(chm *ChallengeMessage, proofForClient proof.Proof) {
	// proof from client to my root
	proof.CheckProof(sn.GetSuite().Hash, sn.MTRoot, sn.LocalMTRoot, sn.Proofs[sn.LocalMTRootIndex])
	// proof from my root to big root
	proof.CheckProof(sn.GetSuite().Hash, chm.MTRoot, sn.MTRoot, chm.Proof)
	// proof from client to big root
	proof.CheckProof(sn.GetSuite().Hash, chm.MTRoot, sn.LocalMTRoot, proofForClient)
}

// Create Merkle Proof for local client (timestamp server)
// Send Merkle Proof to local client (timestamp server)
func (sn *SigningNode) SendLocalMerkleProof(chm *ChallengeMessage) error {
	if sn.DoneFunc != nil {
		proofForClient := make(proof.Proof, len(chm.Proof))
		copy(proofForClient, chm.Proof)

		// To the proof from our root to big root we must add the separated proof
		// from the localMKT of the client (timestamp server) to our root
		proofForClient = append(proofForClient, sn.Proofs[sn.LocalMTRootIndex]...)

		// if want to verify partial and full proofs
		sn.VerifyAllProofs(chm, proofForClient)

		// 'reply' to client
		// TODO: add error to done function
		sn.DoneFunc(chm.MTRoot, sn.MTRoot, proofForClient)
	}

	return nil
}

// Create Personalized Merkle Proofs for children servers
// Send Personalized Merkle Proofs to children servers
func (sn *SigningNode) SendChildrenChallengesProofs(chm *ChallengeMessage) error {
	// proof from big root to our root will be sent to all children
	baseProof := make(proof.Proof, len(chm.Proof))
	copy(baseProof, chm.Proof)

	// for each child, create personalized part of proof
	// embed it in SigningMessage, and send it
	for i, child := range sn.Children() {
		newChm := *chm
		newChm.Proof = append(baseProof, sn.Proofs[i]...)

		var messg coconet.BinaryMarshaler
		messg = SigningMessage{Type: Challenge, Chm: &newChm}

		// send challenge message to child
		if err := <-child.Put(messg); err != nil {
			return err
		}
	}

	return nil
}

// Send children challenges
func (sn *SigningNode) SendChildrenChallenges(chm *ChallengeMessage) error {
	for _, child := range sn.Children() {
		var messg coconet.BinaryMarshaler
		messg = SigningMessage{Type: Challenge, Chm: chm}

		// send challenge message to child
		if err := <-child.Put(messg); err != nil {
			return err
		}
	}

	return nil
}

// initiated by root, propagated by all others
func (sn *SigningNode) Challenge(chm *ChallengeMessage) error {
	// register challenge
	sn.c = chm.C

	if sn.Type == PubKey {
		if err := sn.SendChildrenChallenges(chm); err != nil {
			return err
		}
		return sn.Respond()
	} else {
		// messages from clients, proofs computed
		if err := sn.SendLocalMerkleProof(chm); err != nil {
			return err
		}
		if err := sn.SendChildrenChallengesProofs(chm); err != nil {
			return err
		}
		return sn.Respond()
	}

}

func (sn *SigningNode) initResponseCrypto() {
	// generate response   r = v - xc
	sn.r = sn.suite.Secret()
	sn.r.Mul(sn.PrivKey, sn.c).Sub(sn.Log.v, sn.r)
	// initialize sum of children's responses
	sn.r_hat = sn.r
}

// accommodate nils
func (sn *SigningNode) add(a abstract.Point, b abstract.Point) {
	if a == nil {
		a = sn.suite.Point().Null()
	}
	if b != nil {
		a.Add(a, b)
	}

}

// accommodate nils
func (sn *SigningNode) sub(a abstract.Point, b abstract.Point) {
	if a == nil {
		a = sn.suite.Point().Null()
	}
	if b != nil {
		a.Sub(a, b)
	}

}

func (sn *SigningNode) Respond() error {
	var err error
	sn.initResponseCrypto()

	// get responses from kids
	messgs, err := sn.getDownMessgs()
	if err != nil {
		return err
	}

	// initialize exception handling
	var exceptionV_hat abstract.Point
	var exceptionX_hat abstract.Point
	sn.ExceptionList = make([]abstract.Point, 0)
	nullPoint := sn.suite.Point().Null()
	children := sn.Children()

	for i, messg := range messgs {
		sm := messg.(*SigningMessage)
		switch sm.Type {
		default:
			// default == no response from child
			// log.Println(sn.Name(), "received nil response from", i)
			sn.ExceptionList = append(sn.ExceptionList, children[i].PubKey())

			// remove public keys and point commits from subtree of faild child
			sn.add(exceptionX_hat, sn.ChildX_hat[i])
			sn.add(exceptionV_hat, sn.ChildV_hat[i])
			continue
		case Response:
			// disregard response from children that did not commit
			if sn.ChildV_hat[i].Equal(nullPoint) {
				continue
			}

			// log.Println(sn.Name(), "accepts response from", i)
			sn.r_hat.Add(sn.r_hat, sm.Rm.R_hat)

			sn.add(exceptionV_hat, sm.Rm.ExceptionV_hat)
			sn.add(exceptionX_hat, sm.Rm.ExceptionX_hat)
			sn.ExceptionList = append(sn.ExceptionList, sm.Rm.ExceptionList...)

		// Report errors that are not networking errors
		case Error:
			log.Println(sn.Name(), "Error in respond for child", i, sm)
			if sm.Err == nil {
				log.Println("Error but no error set in respond for child", i, err)
				// ignore if no error is actually set
				continue
			}
			return errors.New(sm.Err.Err)
		}
	}

	// remove all Vs of nodes from subtree that failed
	// fmt.Println(sn.Name(), "Removing exception V_hat", exceptionV_hat)
	sn.sub(sn.Log.V_hat, exceptionV_hat)
	sn.sub(sn.X_hat, exceptionX_hat)
	err = sn.VerifyResponses()

	if !sn.IsRoot() {
		// report verify response error
		// fmt.Println(sn.Name(), "put up response", err)
		if err != nil {
			return sn.PutUp(SigningMessage{
				Type: Error,
				Err:  &ErrorMessage{Err: err.Error()}})
		}
		rm := &ResponseMessage{
			R_hat:          sn.r_hat,
			ExceptionList:  sn.ExceptionList,
			ExceptionV_hat: exceptionV_hat,
			ExceptionX_hat: exceptionX_hat}
		// create and putup own response message
		return sn.PutUp(SigningMessage{
			Type: Response,
			Rm:   rm})
	}
	return err
}

// Called *only* by root node after receiving all commits
func (sn *SigningNode) FinalizeCommits() error {
	// NOTE: root has sn.ExceptionList <-- the nodes that
	// did not reply to its annoucement

	// challenge = Hash(Merkle Tree Root/ Announcement Message, sn.Log.V_hat)
	if sn.Type == PubKey {
		sn.c = hashElGamal(sn.suite, sn.LogTest, sn.Log.V_hat)
	} else {
		sn.c = hashElGamal(sn.suite, sn.MTRoot, sn.Log.V_hat)
	}

	proof := make([]hashid.HashId, 0)
	err := sn.Challenge(&ChallengeMessage{
		C:      sn.c,
		MTRoot: sn.MTRoot,
		Proof:  proof})
	return err
}

func (sn *SigningNode) cleanXHat() {
	for _, pubKey := range sn.ExceptionList {
		sn.X_hat.Sub(sn.X_hat, pubKey)
	}
}

// Called by every node after receiving aggregate responses from descendants
func (sn *SigningNode) VerifyResponses() error {
	// Check that: base**r_hat * X_hat**c == V_hat
	// Equivalent to base**(r+xc) == base**(v) == T in vanillaElGamal
	var P, T abstract.Point
	P = sn.suite.Point()
	T = sn.suite.Point()
	T.Add(T.Mul(nil, sn.r_hat), P.Mul(sn.X_hat, sn.c))

	var c2 abstract.Secret
	if sn.IsRoot() {
		if sn.Type == PubKey {
			c2 = hashElGamal(sn.suite, sn.LogTest, T)
		} else {
			c2 = hashElGamal(sn.suite, sn.MTRoot, T)
		}
	}

	// intermediary nodes check partial responses aginst their partial keys
	// the root node is also able to check against the challenge it emitted
	if !T.Equal(sn.Log.V_hat) || (sn.IsRoot() && !sn.c.Equal(c2)) {
		log.Println(sn.Name(), "reports ElGamal Collective Signature failed")
		return errors.New("Veryfing ElGamal Collective Signature failed in " + sn.Name())
	}

	log.Println(sn.Name(), "reports ElGamal Collective Signature succeeded")
	return nil
}

// Called when log for round if full and ready to be hashed
func (sn *SigningNode) HashLog() error {
	var err error
	sn.HashedLog, err = sn.hashLog()
	return err
}

// Auxilary function to perform the actual hashing of the log
func (sn *SigningNode) hashLog() ([]byte, error) {
	h := sn.suite.Hash()
	logBytes, err := sn.Log.MarshalBinary()
	if err != nil {
		return nil, err
	}
	h.Write(logBytes)
	return h.Sum(nil), nil
}

// Identify which proof corresponds to which leaf
// Needed given that the leaves are sorted before passed to the function that create
// the Merkle Tree and its Proofs
func (sn *SigningNode) SeparateProofs(proofs []proof.Proof, leaves []hashid.HashId) {
	// separate proofs for children servers mt roots
	for i := 0; i < len(sn.CMTRoots); i++ {
		for j := 0; j < len(leaves); j++ {
			if bytes.Compare(sn.CMTRoots[i], leaves[j]) == 0 {
				sn.Proofs[i] = append(sn.Proofs[i], proofs[j]...)
				continue
			}
		}
	}

	// separate proof for local mt root
	for j := 0; j < len(leaves); j++ {
		if bytes.Compare(sn.LocalMTRoot, leaves[j]) == 0 {
			sn.Proofs[sn.LocalMTRootIndex] = append(sn.Proofs[sn.LocalMTRootIndex], proofs[j]...)
		}
	}
}

// Returns a secret that depends on on a message and a point
func hashElGamal(suite abstract.Suite, message []byte, p abstract.Point) abstract.Secret {
	pb, _ := p.MarshalBinary()
	c := suite.Cipher(pb)
	c.Message(nil, nil, message)
	return suite.Secret().Pick(c)
}

// Check that starting from its own committed message each child can reach our subtrees' mtroot
// Also checks that starting from local mt root we can get to  our subtrees' mtroot <-- could be in diff fct
func (sn *SigningNode) checkChildrenProofs() {
	cmtAndLocal := make([]hashid.HashId, len(sn.CMTRoots))
	copy(cmtAndLocal, sn.CMTRoots)
	cmtAndLocal = append(cmtAndLocal, sn.LocalMTRoot)

	if proof.CheckLocalProofs(sn.GetSuite().Hash, sn.MTRoot, cmtAndLocal, sn.Proofs) == true {
		log.Println("Chidlren Proofs of", sn.Name(), "successful for round "+strconv.Itoa(sn.nRounds))
	} else {
		panic("Children Proofs" + sn.Name() + " unsuccessful for round " + strconv.Itoa(sn.nRounds))
	}
}
