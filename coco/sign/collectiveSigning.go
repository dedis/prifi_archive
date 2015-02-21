package sign

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	log "github.com/Sirupsen/logrus"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/prifi/coco/coconet"
	"github.com/dedis/prifi/coco/hashid"
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

// Block until a message from a child is received via network
func (sn *Node) waitDownOnNM(ch chan coconet.NetworkMessg, errch chan error) (
	coconet.NetworkMessg, error) {
	nm := <-ch
	err := <-errch

	return nm, err
}

// Determine type of message coming from the children
// Put them on message channels other functions can read from
func (sn *Node) getDown() {
	// update waiting time based on current depth
	sn.UpdateTimeout()
	// wait for all children to commit
	ch, errch := sn.GetDown()

	for {
		nm, err := sn.waitDownOnNM(ch, errch)
		if err == coconet.ErrorConnClosed {
			continue
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
	// set up commit and response channels for the new round
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

// Used in Commit and Respond when waiting for children Commits and Responses
// The commits and responses are read from the commit and respond channel
// as they are put there by the getDown function
func (sn *Node) waitOn(ch chan *SigningMessage, timeout time.Duration, what string) []*SigningMessage {
	nChildren := len(sn.Children())
	messgs := make([]*SigningMessage, 0)
	received := 0
	if nChildren > 0 {
		for {

			select {
			case sm := <-ch:
				messgs = append(messgs, sm)
				received += 1
				if received == nChildren {
					return messgs
				}
			case <-time.After(timeout):
				log.Warnln(sn.Name(), "timeouted on", what, timeout)
				return messgs
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
	messgs := sn.waitOn(sn.ComCh[Round], sn.Timeout(), "commits")

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
		sn.AddChildrenMerkleRoots(Round)
		sn.AddLocalMerkleRoot(Round)
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

// Figure out which kids did not submit messages
// Add default messages to messgs, one per missing child
// as to make it easier to identify and add them to exception lists in one place
func (sn *Node) FillInWithDefaultMessages(messgs []*SigningMessage) []*SigningMessage {
	children := sn.Children()

	allmessgs := make([]*SigningMessage, len(messgs))
	copy(allmessgs, messgs)

	for c := range children {
		found := false
		for _, m := range messgs {
			if m.From == c {
				found = true
				break
			}
		}

		if !found {
			allmessgs = append(allmessgs, &SigningMessage{Type: Default, From: c})
		}
	}

	return allmessgs
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
	messgs := sn.waitOn(sn.RmCh[Round], sn.Timeout(), "responses")

	// initialize exception handling
	exceptionV_hat := sn.suite.Point().Null()
	exceptionX_hat := sn.suite.Point().Null()
	round.ExceptionList = make([]abstract.Point, 0)
	nullPoint := sn.suite.Point().Null()
	allmessgs := sn.FillInWithDefaultMessages(messgs)

	var someExceptions bool
	children := sn.Children()
	for _, sm := range allmessgs {
		from := sm.From
		switch sm.Type {
		default:
			// default == no response from child
			log.Println(sn.Name(), "default in respose for child", from, sm)
			round.ExceptionList = append(round.ExceptionList, children[from].PubKey())

			// remove public keys and point commits from subtree of faild child
			someExceptions = true
			sn.add(exceptionX_hat, round.ChildX_hat[from])
			sn.add(exceptionV_hat, round.ChildV_hat[from])
			continue
		case Response:
			// disregard response from children who did not commit
			_, ok := round.ChildV_hat[from]
			if ok == true && round.ChildV_hat[from].Equal(nullPoint) {
				continue
			}

			log.Println(sn.Name(), "accepts response from", from, sm.Type)
			round.r_hat.Add(round.r_hat, sm.Rm.R_hat)

			someExceptions = true
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
	// fmt.Println(sn.Name(), exceptionX_hat, exceptionV_hat)
	if someExceptions {
		sn.sub(round.Log.V_hat, exceptionV_hat)
		sn.sub(round.X_hat, exceptionX_hat)
	}
	err = sn.VerifyResponses(Round)

	if !sn.IsRoot() {
		if sn.TestingFailures == true &&
			(sn.Host.(*coconet.FaultyHost).IsDead() ||
				sn.Host.(*coconet.FaultyHost).IsDeadFor("response")) {
			fmt.Println(sn.Name(), "dead for response")
			return nil
		}
		// report verify response error
		// log.Println(sn.Name(), "put up response with err", err)
		if err != nil {
			return sn.PutUp(&SigningMessage{
				Type: Error,
				Err:  &ErrorMessage{Err: err.Error()}})
		}

		if exceptionV_hat.Equal(sn.suite.Point().Null()) {
			exceptionV_hat = nil
		}
		if exceptionX_hat.Equal(sn.suite.Point().Null()) {
			exceptionX_hat = nil
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
		// round challenge must be recomputed given potential
		// exception list
		if sn.Type == PubKey {
			round.c = hashElGamal(sn.suite, sn.LogTest, round.Log.V_hat)
			c2 = hashElGamal(sn.suite, sn.LogTest, T)
		} else {
			round.c = hashElGamal(sn.suite, round.MTRoot, round.Log.V_hat)
			c2 = hashElGamal(sn.suite, round.MTRoot, T)
		}
	}

	// intermediary nodes check partial responses aginst their partial keys
	// the root node is also able to check against the challenge it emitted
	if !T.Equal(round.Log.V_hat) || (sn.IsRoot() && !round.c.Equal(c2)) {
		log.Errorln(sn.Name(), "reports ElGamal Collective Signature failed for Round", Round)
		return errors.New("Veryfing ElGamal Collective Signature failed in " + sn.Name() + "for round " + strconv.Itoa(Round))
	}

	log.Println(sn.Name(), "reports ElGamal Collective Signature succeeded for round", Round)
	return nil
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
