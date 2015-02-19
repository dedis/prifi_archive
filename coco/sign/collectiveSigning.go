package sign

import (
	"bytes"
	"errors"
	"sort"
	"strconv"
	"time"

	log "github.com/Sirupsen/logrus"

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
func (sn *Node) getUp() {
	for {
		sm := SigningMessage{}
		if err := sn.GetUp(&sm); err != nil {
			if err == coconet.ErrorConnClosed {
				// stop getting up if the connection is closed
				return
			}
		}
		switch sm.Type {
		default:
			continue
		case Announcement:
			sn.Announce(sm.Am)
		case Challenge:
			sn.Challenge(sm.Chm)
		}
	}
}

// Used in Commit and Respond to get commits and responses from all
// children before creating own commit and response
func (sn *Node) getDown() {
	// update waiting time based on current depth
	sn.UpdateTimeout()
	// wait for all children to commit
	ch, errch := sn.GetDown()

	for {
		nm := <-ch
		err := <-errch

		if err != nil {
			if err == coconet.ErrorConnClosed {
				continue
			}
		}

		// interpret network message as Siging Message
		sm := nm.Data.(*SigningMessage)
		sm.From = nm.From

		switch sm.Type {
		default:
			continue
		case Commitment:
			// shove message on commit channel for its round
			round := sm.Com.Round
			sn.roundLock.Lock()
			comch := sn.ComCh[round]
			sn.roundLock.Unlock()
			comch <- sm
		case Response:
			// shove message on response channel for its round
			round := sm.Rm.Round
			sn.roundLock.Lock()
			rmch := sn.RmCh[round]
			sn.roundLock.Unlock()
			rmch <- sm
		case Error:
			log.Println(sn.Name(), "error", ErrUnknownMessageType, sm, sm.Err)
		}
	}
}

// Start listening for messages coming from parent(up)
func (sn *Node) Listen() error {
	sn.setPool()

	if !sn.IsRoot() {
		go sn.getUp()
	}
	go sn.getDown()

	return nil
}

// initiated by root, propagated by all others
func (sn *Node) Announce(am *AnnouncementMessage) error {
	// the root is the only node that keeps track of round # internally
	if sn.IsRoot() {
		sn.Round = am.Round
	}
	sn.roundLock.Lock()
	sn.Rounds[am.Round] = NewRound()
	sn.ComCh[am.Round] = make(chan *SigningMessage, 1)
	sn.RmCh[am.Round] = make(chan *SigningMessage, 1)
	sn.roundLock.Unlock()

	// Inform all children of announcement
	messgs := make([]coconet.BinaryMarshaler, sn.NChildren())
	for i := range messgs {
		sm := SigningMessage{Type: Announcement, Am: am}
		messgs[i] = &sm
	}
	if err := sn.PutDown(messgs); err != nil {
		return err
	}

	// initiate commit phase
	return sn.Commit(am.Round)
}

func (sn *Node) GetChildrenMerkleRoots(Round int) {
	round := sn.Rounds[Round]
	// children commit roots
	round.CMTRoots = make([]hashid.HashId, len(round.Leaves))
	copy(round.CMTRoots, round.Leaves)
	round.CMTRootNames = make([]string, len(round.Leaves))
	copy(round.CMTRootNames, round.LeavesFrom)

	// concatenate children commit roots in one binary blob for easy marshalling
	round.Log.CMTRoots = make([]byte, 0)
	for _, leaf := range round.Leaves {
		round.Log.CMTRoots = append(round.Log.CMTRoots, leaf...)
	}
}

func (sn *Node) GetLocalMerkleRoot(Round int) {
	round := sn.Rounds[Round]
	// add own local mtroot to leaves
	if sn.CommitFunc != nil {
		round.LocalMTRoot = sn.CommitFunc()
	} else {
		round.LocalMTRoot = make([]byte, hashid.Size)
	}
	round.Leaves = append(round.Leaves, round.LocalMTRoot)
}

func (sn *Node) ComputeCombinedMerkleRoot(Round int) {
	round := sn.Rounds[Round]
	// add hash of whole log to leaves
	round.Leaves = append(round.Leaves, round.HashedLog)

	// compute MT root based on Log as right child and
	// MT of leaves as left child and send it up to parent
	sort.Sort(hashid.ByHashId(round.Leaves))
	left, proofs := proof.ProofTree(sn.Suite().Hash, round.Leaves)
	right := round.HashedLog
	moreLeaves := make([]hashid.HashId, 0)
	moreLeaves = append(moreLeaves, left, right)
	round.MTRoot, _ = proof.ProofTree(sn.Suite().Hash, moreLeaves)

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
func (sn *Node) initCommitCrypto(Round int) {
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

func (sn *Node) waitOn(ch chan *SigningMessage, timeout time.Duration, what string) []*SigningMessage {
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
				log.Println(sn.Name(), "timeouted on", what, timeout)
				break forloop
			}
		}
	}

	return messgs
}

func (sn *Node) Commit(Round int) error {
	round := sn.Rounds[Round]
	sn.initCommitCrypto(Round)

	// wait on commits from children
	sn.UpdateTimeout()
	messgs := sn.waitOn(sn.ComCh[Round], sn.GetTimeout(), "commits")

	// prepare to handle exceptions
	round.ExceptionList = make([]abstract.Point, 0)
	round.ChildV_hat = make(map[string]abstract.Point, len(sn.Children()))
	round.ChildX_hat = make(map[string]abstract.Point, len(sn.Children()))
	children := sn.Children()

	// Commits from children are the first Merkle Tree leaves for the round
	round.Leaves = make([]hashid.HashId, 0)
	round.LeavesFrom = make([]string, 0)

	for key := range children {
		round.ChildX_hat[key] = sn.suite.Point().Null()
		round.ChildV_hat[key] = sn.suite.Point().Null()
	}
	for _, sm := range messgs {
		from := sm.From
		switch sm.Type {
		default: // default == no response from i
			// fmt.Println(sn.Name(), "no commit from", i)
			round.ExceptionList = append(round.ExceptionList, children[from].PubKey())
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
func (sn *Node) actOnCommits(Round int) (err error) {
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
			// fmt.Println(sn.Name(), "dead for commits")
			return
		}

		err = sn.PutUp(&SigningMessage{
			Type: Commitment,
			Com:  com})
	}
	return
}

func (sn *Node) VerifyAllProofs(chm *ChallengeMessage, proofForClient proof.Proof) {
	round := sn.Rounds[chm.Round]
	// proof from client to my root
	proof.CheckProof(sn.Suite().Hash, round.MTRoot, round.LocalMTRoot, round.Proofs["local"])
	// proof from my root to big root
	proof.CheckProof(sn.Suite().Hash, chm.MTRoot, round.MTRoot, chm.Proof)
	// proof from client to big root
	proof.CheckProof(sn.Suite().Hash, chm.MTRoot, round.LocalMTRoot, proofForClient)
}

// Create Merkle Proof for local client (timestamp server)
// Send Merkle Proof to local client (timestamp server)
func (sn *Node) SendLocalMerkleProof(chm *ChallengeMessage) error {
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
func (sn *Node) SendChildrenChallengesProofs(chm *ChallengeMessage) error {
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
		messg = &SigningMessage{Type: Challenge, Chm: &newChm}

		// send challenge message to child
		// log.Println("connection: sending children challenge proofs:", name, conn)
		if err := <-conn.Put(messg); err != nil {
			return err
		}
	}

	return nil
}

// Send children challenges
func (sn *Node) SendChildrenChallenges(chm *ChallengeMessage) error {
	for _, child := range sn.Children() {
		var messg coconet.BinaryMarshaler
		messg = &SigningMessage{Type: Challenge, Chm: chm}

		// send challenge message to child
		if err := <-child.Put(messg); err != nil {
			return err
		}
	}

	return nil
}

// initiated by root, propagated by all others
func (sn *Node) Challenge(chm *ChallengeMessage) error {
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

func (sn *Node) initResponseCrypto(Round int) {
	round := sn.Rounds[Round]
	// generate response   r = v - xc
	round.r = sn.suite.Secret()
	round.r.Mul(sn.PrivKey, round.c).Sub(round.Log.v, round.r)
	// initialize sum of children's responses
	round.r_hat = round.r
}

func (sn *Node) Respond(Round int) error {
	var err error
	round := sn.Rounds[Round]
	sn.initResponseCrypto(Round)

	// wait on responses from children
	sn.UpdateTimeout()
	messgs := sn.waitOn(sn.RmCh[Round], sn.GetTimeout(), "responses")

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
			// disregard response from children who did not commit
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
	sn.sub(round.Log.V_hat, exceptionV_hat)
	sn.sub(round.X_hat, exceptionX_hat)
	err = sn.VerifyResponses(Round)

	if !sn.IsRoot() {
		// report verify response error
		// log.Println(sn.Name(), "put up response with err", err)
		if err != nil {
			return sn.PutUp(&SigningMessage{
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
		return sn.PutUp(&SigningMessage{
			Type: Response,
			Rm:   rm})
	}
	return err
}

// Called *only* by root node after receiving all commits
func (sn *Node) FinalizeCommits() error {
	Round := sn.Round // *only* in root
	round := sn.Rounds[Round]

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

func (sn *Node) cleanXHat(Round int) {
	round := sn.Rounds[Round]
	for _, pubKey := range round.ExceptionList {
		round.X_hat.Sub(round.X_hat, pubKey)
	}
}

// Called by every node after receiving aggregate responses from descendants
func (sn *Node) VerifyResponses(Round int) error {
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

// Identify which proof corresponds to which leaf
// Needed given that the leaves are sorted before passed to the function that create
// the Merkle Tree and its Proofs
func (sn *Node) SeparateProofs(proofs []proof.Proof, leaves []hashid.HashId, Round int) {
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

// Check that starting from its own committed message each child can reach our subtrees' mtroot
// Also checks that starting from local mt root we can get to  our subtrees' mtroot <-- could be in diff fct
func (sn *Node) checkChildrenProofs(Round int) {
	round := sn.Rounds[Round]
	cmtAndLocal := make([]hashid.HashId, len(round.CMTRoots))
	copy(cmtAndLocal, round.CMTRoots)
	cmtAndLocal = append(cmtAndLocal, round.LocalMTRoot)

	proofs := make([]proof.Proof, 0)
	for _, name := range round.CMTRootNames {
		proofs = append(proofs, round.Proofs[name])
	}

	if proof.CheckLocalProofs(sn.Suite().Hash, round.MTRoot, cmtAndLocal, proofs) == true {
		log.Println("Chidlren Proofs of", sn.Name(), "successful for round "+strconv.Itoa(sn.nRounds))
	} else {
		panic("Children Proofs" + sn.Name() + " unsuccessful for round " + strconv.Itoa(sn.nRounds))
	}
}

// Returns a secret that depends on on a message and a point
func hashElGamal(suite abstract.Suite, message []byte, p abstract.Point) abstract.Secret {
	pb, _ := p.MarshalBinary()
	c := suite.Cipher(pb)
	c.Message(nil, nil, message)
	return suite.Secret().Pick(c)
}

// Called when log for round if full and ready to be hashed
func (sn *Node) HashLog(Round int) error {
	round := sn.Rounds[Round]
	var err error
	round.HashedLog, err = sn.hashLog(Round)
	return err
}

// Auxilary function to perform the actual hashing of the log
func (sn *Node) hashLog(Round int) ([]byte, error) {
	round := sn.Rounds[Round]

	h := sn.suite.Hash()
	logBytes, err := round.Log.MarshalBinary()
	if err != nil {
		return nil, err
	}
	h.Write(logBytes)
	return h.Sum(nil), nil
}
