package coco

import (
	"errors"
	"log"
	"sort"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/prifi/coconet"
	"github.com/dedis/prifi/timestamp"
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
				sn.Announce(sm.am)
			case Challenge:
				sn.Challenge(sm.chm)
			}
		}
	}
	return nil
}

// initiated by root, propagated by all others
func (sn *SigningNode) Announce(am *AnnouncementMessage) error {
	//fmt.Println(sn.Name(), "announces")
	// Inform all children of announcement
	// PutDown requires each child to have his own message
	messgs := make([]coconet.BinaryMarshaler, sn.NChildren())
	for i := range messgs {
		sm := SigningMessage{Type: Announcement, am: am}
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
func (sn *SigningNode) getDownMessgs() ([]coconet.BinaryUnmarshaler, error) {
	// grab space for children messages
	messgs := make([]coconet.BinaryUnmarshaler, sn.NChildren())
	for i := range messgs {
		messgs[i] = &SigningMessage{}
	}
	// wait for all children to commit
	var err error
	if err = sn.GetDown(messgs); err != nil {
		return nil, err
	}

	return messgs, nil
}

// Finalize commits by initiating the challenge pahse if root
// Send own commitment message up to parent if non-root
func (sn *SigningNode) actOnCommits() (err error) {
	if sn.IsRoot() {
		err = sn.FinalizeCommits()
	} else {
		// create and putup own commit message
		com := &CommitmentMessage{
			V:      sn.Log.V,
			V_hat:  sn.Log.V_hat,
			MTRoot: sn.MTRoot}
		err = sn.PutUp(SigningMessage{
			Type: Commitment,
			com:  com})
	}
	return
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
	sn.Log.V_hat = sn.Log.V
}

func (sn *SigningNode) Commit() error {
	sn.initCommitCrypto()

	// get commits from kids
	messgs, err := sn.getDownMessgs()
	if err != nil {
		return err
	}

	// Commits from children are the first Merkle Tree leaves for the round
	leaves := make([]timestamp.HashId, 0)
	for _, messg := range messgs {
		sm := messg.(*SigningMessage)
		switch sm.Type {
		default:
			// Not possible in current system where little randomness is allowed
			// In real system failing is required
			panic("Reply to announcement is not a commit")
		case Commitment:
			// fmt.Println(sm.com)
			// fmt.Println("I", sn.Name(), "commits ", sm.com.MTRoot)
			leaves = append(leaves, sm.com.MTRoot)
			sn.Log.V_hat.Add(sn.Log.V_hat, sm.com.V_hat)
		}
	}
	// keep children commits twice (in sn and in sn.Log for the moment)
	sn.CMTRoots = leaves
	// concatenate children mtroots in one binary blob for easy marshalling
	sn.Log.CMTRoots = make([]byte, 0)
	for _, leaf := range leaves {
		sn.Log.CMTRoots = append(sn.Log.CMTRoots, leaf...)
	}

	// add own local mtroot to leaves
	sn.LocalMTRoot, _ = sn.AggregateCommits()
	leaves = append(leaves, sn.LocalMTRoot)

	// add hash of whole log to leaves
	h := sn.suite.Hash()
	logBytes, err := sn.Log.MarshalBinary()
	if err != nil {
		return err
	}
	h.Write(logBytes)
	sn.HashedLog = h.Sum(nil)
	leaves = append(leaves, sn.HashedLog)

	// send compute MT root based on leaves and send it up to parent
	sort.Sort(timestamp.ByHashId(leaves))
	sn.MTRoot, _ = timestamp.ProofTree(sn.GetSuite().Hash, leaves)
	return sn.actOnCommits()
}

func (sn *SigningNode) VerifyChallenge(chm *ChallengeMessage) bool {
	return timestamp.CheckProofs(sn.GetSuite().Hash, chm.MTRoot,
		sn.LocalMTRoot, chm.Proof, chm.LevelProof)
}

// initiated by root, propagated by all others
func (sn *SigningNode) Challenge(chm *ChallengeMessage) error {
	// if sn.VerifyChallenge(chm) != true {
	// log.Println("MKT did not verify for", sn.Name())
	// panic("MKT did not verify for" + sn.Name())
	// }

	// register challenge value, which is the same for all children
	sn.c = chm.C
	nextDepth := chm.Depth + 1

	// for each child, create levelProof for this(root) level
	// embed it in SigningMessage, and send it
	for i, child := range sn.Children() {
		// proof for this level involves all leaves used to create sn.MTRoot
		// must exclude child's own committed MTRoot for each child
		levelProof := make([]timestamp.HashId, 0)
		levelProof = append(levelProof, sn.HashedLog, sn.LocalMTRoot)
		levelProof = append(levelProof, timestamp.AllButI(sn.CMTRoots, i)...)

		chm.Proof = append(chm.Proof, sn.MTRoot)
		chm.LevelProof = levelProof
		chm.Depth = nextDepth

		var messg coconet.BinaryMarshaler
		messg = SigningMessage{Type: Challenge, chm: chm}

		// send challenge message to child
		if err := child.Put(messg); err != nil {
			return err
		}
	}

	// initiate response phase
	return sn.Respond()
}

func (sn *SigningNode) initResponseCrypto() {
	// generate response   r = v - xc
	sn.r = sn.suite.Secret()
	sn.r.Mul(sn.privKey, sn.c).Sub(sn.Log.v, sn.r)
	// initialize sum of children's responses
	sn.r_hat = sn.r
}

func (sn *SigningNode) Respond() error {
	var err error
	sn.initResponseCrypto()

	// get responses from kids
	messgs, err := sn.getDownMessgs()
	if err != nil {
		return err
	}

	for _, messg := range messgs {
		sm := messg.(*SigningMessage)
		switch sm.Type {
		default:
			// Not possible in current system where little randomness is allowed
			// In real system failing is required
			panic("Reply to challenge is not a response")
		case Error:
			return sm.err.Err
		case Response:
			sn.r_hat.Add(sn.r_hat, sm.rm.R_hat)
		}
	}

	err = sn.VerifyResponses()
	if !sn.IsRoot() {
		// report verify response error
		if err != nil {
			return sn.PutUp(SigningMessage{
				Type: Error,
				err:  &ErrorMessage{Err: err}})
		}
		// create and putup own response message
		return sn.PutUp(SigningMessage{
			Type: Response,
			rm:   &ResponseMessage{sn.r_hat}})
	}
	return err
}

// Called *only* by root node after receiving all commits
func (sn *SigningNode) FinalizeCommits() error {
	// challenge = Hash(Merkle Tree Root, sn.Log.V_hat)
	sn.c = hashElGamal(sn.suite, sn.MTRoot, sn.Log.V_hat)

	err := sn.Challenge(&ChallengeMessage{
		C:      sn.c,
		Depth:  0,
		MTRoot: sn.MTRoot,
		Proof:  make([]timestamp.HashId, 0)})
	return err
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
		c2 = hashElGamal(sn.suite, sn.MTRoot, T)
	}

	// intermediary nodes check partial responses aginst their partial keys
	// the root node is also able to check against the challenge it emitted
	if !T.Equal(sn.Log.V_hat) || (sn.IsRoot() && !sn.c.Equal(c2)) {
		log.Println(sn.Name(), "reports ElGamal Collective Signature failed")
		return errors.New("Veryfing ElGamal Collective Signature failed in" + sn.Name())
	}

	log.Println(sn.Name(), "reports ElGamal Collective Signature succeeded")
	return nil
}

// Returns a secret that depends on on a message and a point
func hashElGamal(suite abstract.Suite, message []byte, p abstract.Point) abstract.Secret {
	c := suite.Cipher(p.Encode(), abstract.More{})
	c.Crypt(nil, message)
	return suite.Secret().Pick(c)
}
