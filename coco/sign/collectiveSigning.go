package sign

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"sort"
	"strconv"
	"sync"
	"time"

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

// Determine type of message coming from the parent
// Pass the duty of acting on it to another function
func (sn *SigningNode) getUp() {
	for {
		sm := SigningMessage{}
		if err := sn.GetUp(&sm); err != nil {
			// TODO: could pass err up via channel
			log.Println("err")
		}
		switch sm.Type {
		default:
			log.Println("in get up", ErrUnknownMessageType, sm)
			// return ErrUnknownMessageType
		case Announcement:
			sn.Announce(sm.Am)
		case Challenge:
			sn.Challenge(sm.Chm)
		}
	}
}

// Used in Commit and Respond to get commits and responses from all
// children before creating own commit and response
// Messages from children are returns in STRICT order
// ith message = message from ith child
func (sn *SigningNode) getDown() {
	// grab space for children messages
	// messgs := make([]coconet.BinaryUnmarshaler, sn.NChildren())
	// for i := range messgs {
	// 	messgs[i] = &SigningMessage{}
	// }

	// update waiting time based on current depth
	// and wait for all children to commit
	sn.UpdateTimeout()
	ch, errch := sn.GetDown()

	var sm *SigningMessage
	var nm coconet.NetworkMessg
	var err error
	for {
		nm = <-ch
		err = <-errch

		if err != nil {
			// TODO: something else?
			continue
		}

		sm = nm.Data.(*SigningMessage)
		sm.From = nm.From
		switch sm.Type {
		default:
			log.Println(sn.Name(), "getDown", ErrUnknownMessageType, sm)
			// return ErrUnknownMessageType
		case Commitment:
			// shove message on commit channel for its round
			round := sm.Com.Round
			sn.ComCh[round] <- sm
		case Response:
			// shove message on response channel for its round
			round := sm.Rm.Round
			sn.RmCh[round] <- sm
		case Error:
			log.Println(sn.Name(), "error", ErrUnknownMessageType, sm, sm.Err)
		}
	}
}

func (sn *SigningNode) setPool() {
	var p sync.Pool
	p.New = NewSigningMessage
	sn.Host.SetPool(p)
}

// Start listening for messages coming from parent(up)
func (sn *SigningNode) Listen() error {
	sn.setPool()

	if sn.IsRoot() {
		// Sleep/ Yield until change in network
		// sn.WaitTick()
		go sn.getDown()
	} else {
		go sn.getUp()
		go sn.getDown()
	}
	return nil
}

// initiated by root, propagated by all others
func (sn *SigningNode) Announce(am *AnnouncementMessage) error {
	// the root is the only node that keeps track of round # internally
	if sn.IsRoot() {
		sn.Round = am.Round
	}
	sn.Rounds[am.Round] = NewRound()
	sn.ComCh[am.Round] = make(chan *SigningMessage, 1)
	sn.RmCh[am.Round] = make(chan *SigningMessage, 1)

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
	return sn.Commit(am.Round)
}

func (sn *SigningNode) GetChildrenMerkleRoots(Round int) {
	round := sn.Rounds[Round]
	// children commit roots
	round.CMTRoots = make([]hashid.HashId, len(round.Leaves))
	copy(round.CMTRoots, round.Leaves)
	round.CMTRootNames = make([]string, len(round.Leaves))
	copy(round.CMTRootNames, round.LeavesFrom)

	if len(round.Leaves) != len(round.LeavesFrom) {
		panic("len leaves != len leaves from")
	}

	// concatenate children commit roots in one binary blob for easy marshalling
	round.Log.CMTRoots = make([]byte, 0)
	for _, leaf := range round.Leaves {
		round.Log.CMTRoots = append(round.Log.CMTRoots, leaf...)
	}
}

func (sn *SigningNode) GetLocalMerkleRoot(Round int) {
	round := sn.Rounds[Round]
	// add own local mtroot to leaves
	if sn.CommitFunc != nil {
		round.LocalMTRoot = sn.CommitFunc()
	} else {
		round.LocalMTRoot = make([]byte, hashid.Size)
	}
	round.Leaves = append(round.Leaves, round.LocalMTRoot)
	// sn.LocalMTRootIndex = len(sn.Leaves) - 1

}

func (sn *SigningNode) ComputeCombinedMerkleRoot(Round int) {
	round := sn.Rounds[Round]
	// add hash of whole log to leaves
	round.Leaves = append(round.Leaves, round.HashedLog)

	// compute MT root based on Log as right child and
	// MT of leaves as left child and send it up to parent
	sort.Sort(hashid.ByHashId(round.Leaves))
	left, proofs := proof.ProofTree(sn.GetSuite().Hash, round.Leaves)
	right := round.HashedLog
	moreLeaves := make([]hashid.HashId, 0)
	moreLeaves = append(moreLeaves, left, right)
	round.MTRoot, _ = proof.ProofTree(sn.GetSuite().Hash, moreLeaves)

	// Hashed Log has to come first in the proof; len(sn.CMTRoots)+1 proofs
	round.Proofs = make(map[string]proof.Proof, 0)
	children := sn.Children()
	for name := range children {
		round.Proofs[name] = append(round.Proofs[name], right)
	}
	round.Proofs["local"] = append(round.Proofs["local"], right)

	// separate proofs by children (need to send personalized proofs to children)
	// also separate local proof (need to send it to timestamp server)
	sn.SeparateProofs(proofs, round.Leaves, Round)
}

// Create round lasting secret and commit point v and V
// Initialize log structure for the round
func (sn *SigningNode) initCommitCrypto(Round int) {
	round := sn.Rounds[Round]
	// generate secret and point commitment for this round
	rand := sn.suite.Cipher([]byte(sn.Name()))
	round.Log = SNLog{}
	round.Log.v = sn.suite.Secret().Pick(rand)
	round.Log.V = sn.suite.Point().Mul(nil, round.Log.v)
	// initialize product of point commitments
	round.Log.V_hat = sn.suite.Point().Null()
	sn.add(round.Log.V_hat, round.Log.V)

	round.X_hat = sn.suite.Point().Null()
	sn.add(round.X_hat, sn.PubKey)
}

func (sn *SigningNode) waitOn(ch chan *SigningMessage, timeout time.Duration) []*SigningMessage {
	nChildren := len(sn.Children())
	messgs := make([]*SigningMessage, 0)
	received := 0
	if nChildren > 0 {
	forloop:
		for {

			select {
			case sm := <-ch:
				messgs = append(messgs, sm)
				received += 1
				if received == nChildren {
					break forloop
				}
			case <-time.After(timeout):
				log.Println(sn.Name(), "timeouted", timeout)
				break forloop
			}
		}
	}

	return messgs
}

func (sn *SigningNode) Commit(Round int) error {
	round := sn.Rounds[Round]
	sn.initCommitCrypto(Round)

	// wait on commits from children
	messgs := sn.waitOn(sn.ComCh[Round], sn.GetTimeout())

	// prepare to handle exceptions
	round.ExceptionList = make([]abstract.Point, 0)
	round.ChildV_hat = make(map[string]abstract.Point, len(sn.Children()))
	round.ChildX_hat = make(map[string]abstract.Point, len(sn.Children()))
	children := sn.Children()

	// Commits from children are the first Merkle Tree leaves for the round
	round.Leaves = make([]hashid.HashId, 0)
	round.LeavesFrom = make([]string, 0)

	for _, sm := range messgs {
		from := sm.From
		switch sm.Type {
		default: // default == no response from i
			// fmt.Println(sn.Name(), "no commit from", i)
			round.ExceptionList = append(round.ExceptionList, children[from].PubKey())
			// take note of lack of pub keys and commit points from i
			round.ChildX_hat[from] = sn.suite.Point().Null()
			round.ChildV_hat[from] = sn.suite.Point().Null()
			continue
		case Commitment:
			round.Leaves = append(round.Leaves, sm.Com.MTRoot)
			round.LeavesFrom = append(round.LeavesFrom, from)
			round.ChildV_hat[from] = sm.Com.V_hat
			round.ChildX_hat[from] = sm.Com.X_hat
			round.ExceptionList = append(round.ExceptionList, sm.Com.ExceptionList...)

			// add good child server to combined public key, and point commit
			sn.add(round.X_hat, sm.Com.X_hat)
			sn.add(round.Log.V_hat, sm.Com.V_hat)
		}

		// sn.Pool().Put(sm)
	}

	if sn.Type == PubKey {
		return sn.actOnCommits(Round)
	} else {
		sn.GetChildrenMerkleRoots(Round)
		sn.GetLocalMerkleRoot(Round)
		sn.HashLog(Round)
		sn.ComputeCombinedMerkleRoot(Round)
		return sn.actOnCommits(Round)
	}
}

// Finalize commits by initiating the challenge pahse if root
// Send own commitment message up to parent if non-root
func (sn *SigningNode) actOnCommits(Round int) (err error) {
	round := sn.Rounds[Round]
	if sn.IsRoot() {
		err = sn.FinalizeCommits()
	} else {
		// create and putup own commit message
		com := &CommitmentMessage{
			V:             round.Log.V,
			V_hat:         round.Log.V_hat,
			X_hat:         round.X_hat,
			MTRoot:        round.MTRoot,
			ExceptionList: round.ExceptionList,
			Round:         Round}

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
	round := sn.Rounds[chm.Round]
	// proof from client to my root
	proof.CheckProof(sn.GetSuite().Hash, round.MTRoot, round.LocalMTRoot, round.Proofs["local"])
	// proof from my root to big root
	proof.CheckProof(sn.GetSuite().Hash, chm.MTRoot, round.MTRoot, chm.Proof)
	// proof from client to big root
	proof.CheckProof(sn.GetSuite().Hash, chm.MTRoot, round.LocalMTRoot, proofForClient)
}

// Create Merkle Proof for local client (timestamp server)
// Send Merkle Proof to local client (timestamp server)
func (sn *SigningNode) SendLocalMerkleProof(chm *ChallengeMessage) error {
	if sn.DoneFunc != nil {
		round := sn.Rounds[chm.Round]
		proofForClient := make(proof.Proof, len(chm.Proof))
		copy(proofForClient, chm.Proof)

		// To the proof from our root to big root we must add the separated proof
		// from the localMKT of the client (timestamp server) to our root
		proofForClient = append(proofForClient, round.Proofs["local"]...)

		// if want to verify partial and full proofs
		sn.VerifyAllProofs(chm, proofForClient)

		// 'reply' to client
		// TODO: add error to done function
		sn.DoneFunc(chm.MTRoot, round.MTRoot, proofForClient)
	}

	return nil
}

// Create Personalized Merkle Proofs for children servers
// Send Personalized Merkle Proofs to children servers
func (sn *SigningNode) SendChildrenChallengesProofs(chm *ChallengeMessage) error {
	round := sn.Rounds[chm.Round]
	// proof from big root to our root will be sent to all children
	baseProof := make(proof.Proof, len(chm.Proof))
	copy(baseProof, chm.Proof)

	// for each child, create personalized part of proof
	// embed it in SigningMessage, and send it
	for name, conn := range sn.Children() {
		newChm := *chm
		newChm.Proof = append(baseProof, round.Proofs[name]...)

		var messg coconet.BinaryMarshaler
		messg = SigningMessage{Type: Challenge, Chm: &newChm}

		// send challenge message to child
		if err := <-conn.Put(messg); err != nil {
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
	round := sn.Rounds[chm.Round]
	round.c = chm.C

	if sn.Type == PubKey {
		if err := sn.SendChildrenChallenges(chm); err != nil {
			return err
		}
		return sn.Respond(chm.Round)
	} else {
		// messages from clients, proofs computed
		if err := sn.SendLocalMerkleProof(chm); err != nil {
			return err
		}
		if err := sn.SendChildrenChallengesProofs(chm); err != nil {
			return err
		}
		return sn.Respond(chm.Round)
	}

}

func (sn *SigningNode) initResponseCrypto(Round int) {
	round := sn.Rounds[Round]
	// generate response   r = v - xc
	round.r = sn.suite.Secret()
	round.r.Mul(sn.PrivKey, round.c).Sub(round.Log.v, round.r)
	// initialize sum of children's responses
	round.r_hat = round.r
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

func (sn *SigningNode) Respond(Round int) error {
	var err error
	round := sn.Rounds[Round]
	sn.initResponseCrypto(Round)

	// wait on responses from children
	messgs := sn.waitOn(sn.RmCh[Round], sn.GetTimeout())

	// initialize exception handling
	var exceptionV_hat abstract.Point
	var exceptionX_hat abstract.Point
	round.ExceptionList = make([]abstract.Point, 0)
	nullPoint := sn.suite.Point().Null()
	children := sn.Children()

	for _, sm := range messgs {
		from := sm.From
		switch sm.Type {
		default:
			// default == no response from child
			// log.Println(sn.Name(), "default in respose for child", from, sm)
			round.ExceptionList = append(round.ExceptionList, children[from].PubKey())

			// remove public keys and point commits from subtree of faild child
			sn.add(exceptionX_hat, round.ChildX_hat[from])
			sn.add(exceptionV_hat, round.ChildV_hat[from])
			continue
		case Response:
			// disregard response from children that did not commit
			_, ok := round.ChildV_hat[from]
			if ok == true && round.ChildV_hat[from].Equal(nullPoint) {
				continue
			}

			// log.Println(sn.Name(), "accepts response from", from)
			round.r_hat.Add(round.r_hat, sm.Rm.R_hat)

			sn.add(exceptionV_hat, sm.Rm.ExceptionV_hat)
			sn.add(exceptionX_hat, sm.Rm.ExceptionX_hat)
			round.ExceptionList = append(round.ExceptionList, sm.Rm.ExceptionList...)

		// Report errors that are not networking errors
		case Error:
			log.Println(sn.Name(), "Error in respose for child", from, sm)
			if sm.Err == nil {
				log.Println("Error but no error set in respond for child", from, err)
				// ignore if no error is actually set
				continue
			}
			return errors.New(sm.Err.Err)
		}
	}

	// remove all Vs of nodes from subtree that failed
	// fmt.Println(sn.Name(), "Removing exception V_hat", exceptionV_hat)
	sn.sub(round.Log.V_hat, exceptionV_hat)
	sn.sub(round.X_hat, exceptionX_hat)
	log.Println(sn.Name(), "Verify responses ", len(messgs), "messgs")
	err = sn.VerifyResponses(Round)

	if !sn.IsRoot() {
		// report verify response error
		// log.Println(sn.Name(), "put up response with err", err)
		if err != nil {
			return sn.PutUp(SigningMessage{
				Type: Error,
				Err:  &ErrorMessage{Err: err.Error()}})
		}
		rm := &ResponseMessage{
			R_hat:          round.r_hat,
			ExceptionList:  round.ExceptionList,
			ExceptionV_hat: exceptionV_hat,
			ExceptionX_hat: exceptionX_hat,
			Round:          Round}
		// create and putup own response message
		return sn.PutUp(SigningMessage{
			Type: Response,
			Rm:   rm})
	}
	return err
}

// Called *only* by root node after receiving all commits
func (sn *SigningNode) FinalizeCommits() error {
	Round := sn.Round // *only* in root
	round := sn.Rounds[Round]
	// NOTE: root has sn.ExceptionList <-- the nodes that
	// did not reply to its annoucement

	// challenge = Hash(Merkle Tree Root/ Announcement Message, sn.Log.V_hat)
	if sn.Type == PubKey {
		round.c = hashElGamal(sn.suite, sn.LogTest, round.Log.V_hat)
	} else {
		round.c = hashElGamal(sn.suite, round.MTRoot, round.Log.V_hat)
	}

	proof := make([]hashid.HashId, 0)
	err := sn.Challenge(&ChallengeMessage{
		C:      round.c,
		MTRoot: round.MTRoot,
		Proof:  proof,
		Round:  Round})
	return err
}

func (sn *SigningNode) cleanXHat(Round int) {
	round := sn.Rounds[Round]
	for _, pubKey := range round.ExceptionList {
		round.X_hat.Sub(round.X_hat, pubKey)
	}
}

// Called by every node after receiving aggregate responses from descendants
func (sn *SigningNode) VerifyResponses(Round int) error {
	round := sn.Rounds[Round]
	// Check that: base**r_hat * X_hat**c == V_hat
	// Equivalent to base**(r+xc) == base**(v) == T in vanillaElGamal
	var P, T abstract.Point
	P = sn.suite.Point()
	T = sn.suite.Point()
	T.Add(T.Mul(nil, round.r_hat), P.Mul(round.X_hat, round.c))

	var c2 abstract.Secret
	if sn.IsRoot() {
		if sn.Type == PubKey {
			c2 = hashElGamal(sn.suite, sn.LogTest, T)
		} else {
			c2 = hashElGamal(sn.suite, round.MTRoot, T)
		}
	}

	// intermediary nodes check partial responses aginst their partial keys
	// the root node is also able to check against the challenge it emitted
	if !T.Equal(round.Log.V_hat) || (sn.IsRoot() && !round.c.Equal(c2)) {
		log.Println(sn.Name(), "reports ElGamal Collective Signature failed for Round", Round)
		return errors.New("Veryfing ElGamal Collective Signature failed in " + sn.Name() + "for round " + strconv.Itoa(Round))
	}

	log.Println(sn.Name(), "reports ElGamal Collective Signature succeeded for round", Round)
	return nil
}

// Called when log for round if full and ready to be hashed
func (sn *SigningNode) HashLog(Round int) error {
	round := sn.Rounds[Round]
	var err error
	round.HashedLog, err = sn.hashLog(Round)
	return err
}

// Auxilary function to perform the actual hashing of the log
func (sn *SigningNode) hashLog(Round int) ([]byte, error) {
	round := sn.Rounds[Round]

	h := sn.suite.Hash()
	logBytes, err := round.Log.MarshalBinary()
	if err != nil {
		return nil, err
	}
	h.Write(logBytes)
	return h.Sum(nil), nil
}

// Identify which proof corresponds to which leaf
// Needed given that the leaves are sorted before passed to the function that create
// the Merkle Tree and its Proofs
func (sn *SigningNode) SeparateProofs(proofs []proof.Proof, leaves []hashid.HashId, Round int) {
	round := sn.Rounds[Round]
	// separate proofs for children servers mt roots
	for i := 0; i < len(round.CMTRoots); i++ {
		name := round.CMTRootNames[i]
		for j := 0; j < len(leaves); j++ {
			if bytes.Compare(round.CMTRoots[i], leaves[j]) == 0 {
				// sn.Proofs[i] = append(sn.Proofs[i], proofs[j]...)
				round.Proofs[name] = append(round.Proofs[name], proofs[j]...)
				continue
			}
		}
	}

	// separate proof for local mt root
	for j := 0; j < len(leaves); j++ {
		if bytes.Compare(round.LocalMTRoot, leaves[j]) == 0 {
			round.Proofs["local"] = append(round.Proofs["local"], proofs[j]...)
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
func (sn *SigningNode) checkChildrenProofs(Round int) {
	round := sn.Rounds[Round]
	cmtAndLocal := make([]hashid.HashId, len(round.CMTRoots))
	copy(cmtAndLocal, round.CMTRoots)
	cmtAndLocal = append(cmtAndLocal, round.LocalMTRoot)

	proofs := make([]proof.Proof, 0)
	for _, name := range round.CMTRootNames {
		proofs = append(proofs, round.Proofs[name])
	}

	if proof.CheckLocalProofs(sn.GetSuite().Hash, round.MTRoot, cmtAndLocal, proofs) == true {
		log.Println("Chidlren Proofs of", sn.Name(), "successful for round "+strconv.Itoa(sn.nRounds))
	} else {
		panic("Children Proofs" + sn.Name() + " unsuccessful for round " + strconv.Itoa(sn.nRounds))
	}
}
