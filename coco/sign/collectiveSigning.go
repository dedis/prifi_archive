package sign

import (
	"errors"
	"io"
	"sort"
	"strconv"
	"sync/atomic"
	"time"

	log "github.com/Sirupsen/logrus"
	"golang.org/x/net/context"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/prifi/coco/coconet"
	"github.com/dedis/prifi/coco/hashid"
	"github.com/dedis/prifi/coco/test/logutils"
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
func (sn *Node) Listen() error {
	if sn.Pool() == nil {
		sn.GenSetPool()
	}
	err := sn.get()
	return err
}

func (sn *Node) Close() {
	sn.hbLock.Lock()
	if sn.heartbeat != nil {
		sn.heartbeat.Stop()
		sn.heartbeat = nil
		log.Println("after close", sn.Name(), "has heartbeat=", sn.heartbeat)
	}
	sn.hbLock.Unlock()
	sn.closed <- io.EOF
	sn.closing <- true
	log.Printf("signing node: closing: %s", sn.Name())
	sn.Host.Close()
}

func (sn *Node) multiplexOnChildren(view int, sm *SigningMessage) {
	messgs := make([]coconet.BinaryMarshaler, sn.NChildren(view))
	for i := range messgs {
		messgs[i] = sm
	}

	// ctx, _ := context.WithTimeout(context.Background(), 2000*time.Millisecond)
	ctx := context.TODO()
	if err := sn.PutDown(ctx, view, messgs); err != nil {
		log.Errorln("failed to putdown messg to children")
	}
}

func (sn *Node) childrenForNewView(parent string) []string {
	peers := sn.Peers()
	children := make([]string, 0, len(peers)-1)
	for p := range peers {
		if p == parent {
			continue
		}
		children = append(children, p)
	}

	return children
}

// Get multiplexes all messages from TCPHost using application logic
func (sn *Node) get() error {
	sn.UpdateTimeout()
	msgchan, errchan := sn.Host.Get()
	// heartbeat for intiating viewChanges, allows intial 500s setup time
	sn.hbLock.Lock()
	sn.heartbeat = time.NewTimer(500 * time.Second)
	sn.hbLock.Unlock()

	for {
		select {
		case <-sn.closing:
			sn.StopHeartbeat()
			return nil
		default:
			nm, ok1 := <-msgchan
			err, ok2 := <-errchan

			if !ok1 || !ok2 || err == coconet.ErrClosed || err == io.EOF {
				log.Errorf("getting from closed host")
				sn.Close()
				return coconet.ErrClosed
			}

			// if it is a non-fatal error try again
			if err != nil {
				log.Errorln("error getting message: continueing")
				continue
			}
			// interpret network message as Siging Message
			sm := nm.Data.(*SigningMessage)
			//log.Printf("got message: %#v with error %v\n", sm, err)
			sm.From = nm.From
			go func(sm *SigningMessage) {
				switch sm.Type {
				// if it is a bad message just ignore it
				default:
					return
				case Announcement:
					if !sn.IsParent(sm.View, sm.From) {
						log.Fatalln(sn.Name(), "received announcement from non-parent on view", sm.View)
						return
					}

					sn.ReceivedHeartbeat(sm.View)
					// log.Println("RECEIVED ANNOUNCEMENT MESSAGE")
					if err := sn.Announce(sm.View, sm.Am); err != nil {
						log.Errorln(sn.Name(), "announce error:", err)
					}

				case Challenge:
					if !sn.IsParent(sm.View, sm.From) {
						log.Fatalln(sn.Name(), "received challenge from non-parent on view", sm.View)
						return
					}

					sn.ReceivedHeartbeat(sm.View)
					if err := sn.Challenge(sm.View, sm.Chm); err != nil {
						log.Errorln(sn.Name(), "challenge error:", err)
					}

				// if it is a commitment or response it is from the child
				case Commitment:
					if !sn.IsChild(sm.View, sm.From) {
						log.Fatalln(sn.Name(), "received commitment from non-child on view", sm.View)
						return
					}

					// shove message on commit channel for its round
					round := sm.Com.Round
					sn.roundLock.Lock()
					comch := sn.ComCh[round]
					sn.roundLock.Unlock()
					comch <- sm
				case Response:
					if !sn.IsChild(sm.View, sm.From) {
						log.Fatalln(sn.Name(), "received response from non-child on view", sm.View)
						return
					}

					// shove message on response channel for its round
					round := sm.Rm.Round
					sn.roundLock.Lock()
					rmch := sn.RmCh[round]
					sn.roundLock.Unlock()
					rmch <- sm
				case ViewChange:
					// if we have already seen this view before skip it
					if int64(sm.View) <= sn.lastView {
						log.Errorf("VIEWCHANGE: already seen this view: %d <= %d", sm.View, sn.lastView)
						return
					}
					sn.lastView = int64(sm.View)
					sn.StopHeartbeat()
					// log.Printf("Host (%s) VIEWCHANGE", sn.Name())
					if err := sn.ViewChange(sm.View, sm.From, sm.Vcm); err != nil {
						if err == coconet.ErrClosed || err == io.EOF {
							sn.closed <- io.EOF
							sn.Close()
						}
						log.Errorln("view change error:", err)
					}
				case ViewAccepted:
					if int64(sm.View) < sn.lastView {
						log.Errorf("VIEW ACCEPTED: already seen this view: %d < %d", sm.View, sn.lastView)
						return
					}
					sn.StopHeartbeat()
					sn.VamChLock.Lock()
					sn.VamCh <- sm
					sn.VamChLock.Unlock()
				case ViewConfirmed:
					if int64(sm.View) < sn.lastView {
						log.Errorf("VIEW CONFIRMED: already seen this view: %d < %d", sm.View, sn.lastView)
						return
					}
					// log.Printf("Host (%s) VIEW CONFIRMED", sn.Name())
					sn.StopHeartbeat()
					sn.ViewChanged(sm.Vcfm.ViewNo, sm)
				case GroupChange:
					log.Println("Received Group Change Message")
					// if the view is uninitialized set it to our most recently seen view
					if sm.View == -1 {
						sm.View = int(sn.lastView)
					}
					if sn.RootFor(sm.View) != sn.Name() {
						log.Println("NOT ROOT: Sending up:", sm.View)
						sn.PutUp(context.TODO(), sm.View, sm)
						return
					}
					// I am the root for this
					log.Println("Starting Voting Round")
					sn.StartVotingRound(&sm.Gcm.Vr)
				case GroupChanged:
					// only the leaf that initiated the GroupChange should get a response
					vr := sm.Gcm.Vr
					if vr.Action == "remove" {
						sn.heartbeat.Stop()
						return
					}
					view := sm.View
					sn.AddParent(view, sm.From)
					log.Println("GROUP CHANGE RESPONSE:", vr)
				case Error:
					log.Println("Received Error Message:", ErrUnknownMessageType, sm, sm.Err)
				}
			}(sm)
		}
	}

}

func (sn *Node) StopHeartbeat() {
	sn.hbLock.Lock()
	if sn.heartbeat != nil {
		sn.heartbeat.Stop()
	}
	sn.hbLock.Unlock()
}

func (sn *Node) ReceivedHeartbeat(view int) {
	// XXX heartbeat should be associated with a specific view
	// if we get a heartbeat for an old view then nothing should change
	// there is a problem here where we could, if we receive a heartbeat
	// from an old view, try viewchanging into a view that we have already been to
	sn.hbLock.Lock()
	// hearbeat is nil if we have sust close the signing node
	if sn.heartbeat != nil {
		sn.heartbeat.Stop()
		sn.heartbeat = time.AfterFunc(HEARTBEAT, func() {
			log.Println(sn.Name(), "NO HEARTBEAT - try view change")
			sn.TryViewChange(view + 1)
		})
	}
	sn.hbLock.Unlock()

}

// Block until a message from a child is received via network
func (sn *Node) waitDownOnNM(ch chan coconet.NetworkMessg, errch chan error) (
	coconet.NetworkMessg, error) {
	nm := <-ch
	err := <-errch

	return nm, err
}

// Used in Commit, Respond and ViewChange when waiting for children Commits and Responses
// The commits and responses are read from the commit and respond channel
// as they are put there by the getDown function
func (sn *Node) waitOn(view int, ch chan *SigningMessage, timeout time.Duration, what string) []*SigningMessage {
	nChildren := sn.NChildren(view)
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
				log.Warnln(sn.Name(), "timeouted on", what, timeout, "got", len(messgs), "out of", nChildren, "for view", view)
				return messgs
			}
		}
	}

	return messgs
}

func (sn *Node) AddSelf(parent string) error {
	err := sn.ConnectTo(parent)
	if err != nil {
		return err
	}
	return sn.PutTo(
		context.TODO(),
		parent,
		&SigningMessage{
			Type: GroupChange,
			View: -1,
			Gcm: &GroupChangeMessage{
				Vr: VoteRequest{Name: sn.Name(), Action: "remove"}}})
}

func (sn *Node) RemoveSelf() error {
	return sn.PutUp(
		context.TODO(),
		int(sn.lastView),
		&SigningMessage{
			Type: GroupChange,
			View: -1,
			Gcm: &GroupChangeMessage{
				Vr: VoteRequest{Name: sn.Name(), Action: "remove"}}})
}

var ViewRejectedError error = errors.New("View Rejected: not all nodes accepted view")

func (sn *Node) ViewChange(view int, parent string, vcm *ViewChangeMessage) error {
	atomic.StoreInt64(&sn.ChangingView, TRUE)
	lsr := atomic.LoadInt64(&sn.LastSeenRound)
	// log.Println(sn.Name(), "VIEW CHANGE MESSAGE: new Round == , oldlsr == ", vcm.Round, lsr)

	// update max seen round
	atomic.StoreInt64(&sn.LastSeenRound, max(int64(vcm.Round), lsr))
	lsr = atomic.LoadInt64(&sn.LastSeenRound)
	// check if you are root for this view change
	iAmNextRoot := FALSE
	if sn.RootFor(vcm.ViewNo) == sn.Name() {
		iAmNextRoot = TRUE
	}

	// Create a new view, but multiplex information about it using the old view
	sn.Views().Lock()
	_, exists := sn.Views().Views[vcm.ViewNo]
	sn.Views().Unlock()
	if !exists {
		children := sn.childrenForNewView(parent)
		log.Println("CREATING NEW VIEW with ", len(sn.HostListOn(view-1)), "hosts", "on view", view)
		sn.NewView(vcm.ViewNo, parent, children, sn.HostListOn(view-1))
	}

	// Apply pending actions (add, remove) on view
	sn.ActionsLock.Lock()
	for _, action := range sn.Actions {
		log.Println(sn.Name(), "applying action")
		sn.ApplyAction(vcm.ViewNo, action)
	}
	sn.ActionsLock.Unlock()

	sn.multiplexOnChildren(vcm.ViewNo, &SigningMessage{View: view, Type: ViewChange, Vcm: vcm})

	// wait for votes from children
	messgs := sn.waitOn(vcm.ViewNo, sn.VamCh, 3*ROUND_TIME, "viewchanges for view"+strconv.Itoa(vcm.ViewNo))
	votes := 1
	for _, messg := range messgs {
		votes += messg.Vam.Votes
	}

	var err error
	if iAmNextRoot == TRUE {
		// log.Println(sn.Name(), "as root received", votes, "of", len(sn.HostList))
		if votes > len(sn.HostListOn(view))*2/3 {
			// quorum confirmed me as new root
			log.Println(sn.Name(), "quorum", votes, "of", len(sn.HostListOn(view)), "confirmed me as new root")
			vcfm := &ViewConfirmedMessage{ViewNo: vcm.ViewNo}
			sm := &SigningMessage{Type: ViewConfirmed, Vcfm: vcfm, From: sn.Name(), View: vcm.ViewNo}
			sn.multiplexOnChildren(vcm.ViewNo, sm)

			atomic.StoreInt64(&sn.ChangingView, FALSE)
			atomic.StoreInt64(&sn.ViewNo, int64(vcm.ViewNo))
			sn.viewChangeCh <- "root"
		} else {
			// log.Println(sn.Name(), " (ROOT) DID NOT RECEIVE quorum", votes, "of", len(sn.HostList))
			return ViewRejectedError
		}
	} else {
		sn.RoundsAsRoot = 0
		// create and putup messg to confirm subtree view changed
		vam := &ViewAcceptedMessage{ViewNo: vcm.ViewNo, Votes: votes}

		// log.Println(sn.Name(), "putting up on view", view, "accept for view", vcm.ViewNo)
		err = sn.PutUp(context.TODO(), vcm.ViewNo, &SigningMessage{
			View: view,
			From: sn.Name(),
			Type: ViewAccepted,
			Vam:  vam})

		return err
	}

	return err
}

func (sn *Node) ViewChanged(view int, sm *SigningMessage) {
	// log.Println(sn.Name(), "view CHANGED to", view)
	// View Changed
	atomic.StoreInt64(&sn.ChangingView, FALSE)
	// channel for getting ViewAcceptedMessages with right size buffer
	sn.VamChLock.Lock()
	sn.VamCh = make(chan *SigningMessage, sn.NChildren(view))
	sn.VamChLock.Unlock()

	sn.viewChangeCh <- "regular"

	// log.Println("in view change, children for view", view, sn.Children(view))
	sn.multiplexOnChildren(view, sm)
	// log.Println(sn.Name(), " exited view CHANGE to", view)
}

func (sn *Node) Announce(view int, am *AnnouncementMessage) error {
	if sn.IsRoot(view) && sn.FailAsRootEvery != 0 {
		if sn.RoundsAsRoot != 0 && sn.RoundsAsRoot%int64(sn.FailAsRootEvery) == 0 {
			log.Errorln(sn.Name() + "was imposed root failure on round" + strconv.Itoa(am.Round))
			log.WithFields(log.Fields{
				"file":  logutils.File(),
				"type":  "root_failure",
				"round": am.Round,
			}).Info(sn.Name() + "Root imposed failure")
			// It doesn't make sense to try view change twice
			// what we essentially end up doing is double setting sn.ViewChanged
			// it is up to our followers to time us out and go to the next leader
			// sn.TryViewChange(view + 1)
			return ChangingViewError
		}
	}

	changingView := atomic.LoadInt64(&sn.ChangingView)
	if changingView == TRUE {
		log.Println(sn.Name(), "RECEIVED annoucement on", view)
		return ChangingViewError
	}

	sn.VamChLock.Lock()
	sn.VamCh = make(chan *SigningMessage, sn.NChildren(view))
	sn.VamChLock.Unlock()

	// set up commit and response channels for the new round
	Round := am.Round
	sn.roundLock.Lock()
	sn.Rounds[Round] = NewRound()
	sn.Rounds[Round].VoteRequest = am.VoteRequest
	sn.ComCh[Round] = make(chan *SigningMessage, sn.NChildren(view))
	sn.RmCh[Round] = make(chan *SigningMessage, sn.NChildren(view))
	sn.roundLock.Unlock()

	// update max seen round
	lsr := atomic.LoadInt64(&sn.LastSeenRound)
	atomic.StoreInt64(&sn.LastSeenRound, max(int64(Round), lsr))

	// the root is the only node that keeps track of round # internally
	if sn.IsRoot(view) {
		sn.RoundsAsRoot += 1
		// sequential round number
		sn.roundLock.Lock()
		sn.Round = Round
		sn.roundLock.Unlock()

		// Create my back link to previous round
		sn.SetBackLink(Round)
		// sn.SetAccountableRound(Round)
	}

	if !sn.IsRoot(view) && sn.FailAsFollowerEvery != 0 && am.Round%sn.FailAsFollowerEvery == 0 {
		// when failure rate given fail with that probability
		if (sn.FailureRate > 0 && sn.ShouldIFail("")) || (sn.FailureRate == 0) {
			log.WithFields(log.Fields{
				"file":  logutils.File(),
				"type":  "follower_failure",
				"round": am.Round,
			}).Info(sn.Name() + "Follower imposed failure")
			return errors.New(sn.Name() + "was imposed follower failure on round" + strconv.Itoa(am.Round))
		}
	}

	// doing this before annoucing children to avoid major drama
	if !sn.IsRoot(view) && sn.ShouldIFail("commit") {
		log.Warn(sn.Name(), "not announcing or commiting for round", Round)
		return nil
	}

	// Inform all children of announcement
	messgs := make([]coconet.BinaryMarshaler, sn.NChildren(view))
	for i := range messgs {
		sm := SigningMessage{Type: Announcement, View: view, Am: am}
		messgs[i] = &sm
	}
	ctx := context.TODO()
	//ctx, _ := context.WithTimeout(context.Background(), 2000*time.Millisecond)
	if err := sn.PutDown(ctx, view, messgs); err != nil {
		return err
	}

	return sn.Commit(view, am)
}

// Create round lasting secret and commit point v and V
// Initialize log structure for the round
func (sn *Node) initCommitCrypto(Round int) {
	sn.roundLock.Lock()
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
	sn.roundLock.Unlock()
}

func (sn *Node) Commit(view int, am *AnnouncementMessage) error {
	sn.roundLock.RLock()
	Round := am.Round
	round := sn.Rounds[Round]
	comch := sn.ComCh[Round]
	sn.roundLock.RUnlock()
	// update max seen round
	lsr := atomic.LoadInt64(&sn.LastSeenRound)
	atomic.StoreInt64(&sn.LastSeenRound, max(int64(Round), lsr))

	if round == nil {
		// was not announced of this round, should retreat
		return nil
	}

	sn.initCommitCrypto(Round)

	// wait on commits from children
	sn.UpdateTimeout()
	messgs := sn.waitOn(view, comch, sn.Timeout(), "commits")

	sn.roundLock.Lock()
	delete(sn.ComCh, Round)
	sn.roundLock.Unlock()

	// prepare to handle exceptions
	round.ExceptionList = make([]abstract.Point, 0)
	round.ChildV_hat = make(map[string]abstract.Point, len(sn.Children(view)))
	round.ChildX_hat = make(map[string]abstract.Point, len(sn.Children(view)))
	children := sn.Children(view)

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

			// count children votes
			round.CountedVotes.Votes = append(round.CountedVotes.Votes, sm.Com.CountedVotes.Votes...)
			round.CountedVotes.For += sm.Com.CountedVotes.For
			round.CountedVotes.Against += sm.Com.CountedVotes.Against

		}

	}

	if sn.Type == PubKey {
		log.Println("sign.Node.Commit using PubKey")
		return sn.actOnCommits(view, Round)
	} else if sn.Type == Vote || am.VoteRequest != nil {
		log.Println("sign.Node.Commit using Vote")
		sort.Sort(ByVoteResponse(round.CountedVotes.Votes))
		sn.AddVotes(Round, am.VoteRequest)
		return sn.actOnCommits(view, Round)
	} else {
		log.Println("sign.Node.Commit using Merkle")
		sn.AddChildrenMerkleRoots(Round)
		sn.AddLocalMerkleRoot(view, Round)
		sn.HashLog(Round)
		sn.ComputeCombinedMerkleRoot(view, Round)
		return sn.actOnCommits(view, Round)
	}
}

// Finalize commits by initiating the challenge pahse if root
// Send own commitment message up to parent if non-root
func (sn *Node) actOnCommits(view, Round int) error {
	sn.roundLock.RLock()
	round := sn.Rounds[Round]
	sn.roundLock.RUnlock()
	var err error

	if sn.IsRoot(view) {
		sn.commitsDone <- Round
		err = sn.FinalizeCommits(view, Round)
	} else {
		// create and putup own commit message
		com := &CommitmentMessage{
			V:             round.Log.V,
			V_hat:         round.Log.V_hat,
			X_hat:         round.X_hat,
			MTRoot:        round.MTRoot,
			ExceptionList: round.ExceptionList,
			CountedVotes:  round.CountedVotes,
			Round:         Round}

		// ctx, _ := context.WithTimeout(context.Background(), 2000*time.Millisecond)
		// log.Println(sn.Name(), "puts up commit")
		ctx := context.TODO()
		err = sn.PutUp(ctx, view, &SigningMessage{
			View: view,
			Type: Commitment,
			Com:  com})
	}
	return err
}

// initiated by root, propagated by all others
func (sn *Node) Challenge(view int, chm *ChallengeMessage) error {
	atomic.StoreInt64(&sn.LastSeenRound, max(int64(chm.Round), atomic.LoadInt64(&sn.LastSeenRound)))
	sn.roundLock.RLock()
	round := sn.Rounds[chm.Round]
	sn.roundLock.RUnlock()

	// update max seen round
	lsr := atomic.LoadInt64(&sn.LastSeenRound)
	atomic.StoreInt64(&sn.LastSeenRound, max(int64(chm.Round), lsr))

	if round == nil {
		return nil
	}

	// register challenge
	round.c = chm.C

	// act on decision of aggregated votes
	// log.Println(sn.Name(), chm.Round, round.VoteRequest)
	if round.VoteRequest != nil {
		sn.actOnVotes(view, chm.CountedVotes, round.VoteRequest)
	}

	if sn.Type == PubKey || sn.Type == Vote || chm.CountedVotes != nil {
		if err := sn.SendChildrenChallenges(view, chm); err != nil {
			return err
		}
		return sn.Respond(view, chm.Round)
	} else {
		// messages from clients, proofs computed
		if sn.CommitedFor(round) {
			if err := sn.SendLocalMerkleProof(view, chm); err != nil {
				return err
			}

		}
		if err := sn.SendChildrenChallengesProofs(view, chm); err != nil {
			return err
		}
		return sn.Respond(view, chm.Round)
	}

}

// Figure out which kids did not submit messages
// Add default messages to messgs, one per missing child
// as to make it easier to identify and add them to exception lists in one place
func (sn *Node) FillInWithDefaultMessages(view int, messgs []*SigningMessage) []*SigningMessage {
	children := sn.Children(view)

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
			allmessgs = append(allmessgs, &SigningMessage{View: view, Type: Default, From: c})
		}
	}

	return allmessgs
}

func (sn *Node) initResponseCrypto(Round int) {
	sn.roundLock.RLock()
	round := sn.Rounds[Round]
	sn.roundLock.RUnlock()
	// generate response   r = v - xc
	round.r = sn.suite.Secret()
	round.r.Mul(sn.PrivKey, round.c).Sub(round.Log.v, round.r)
	// initialize sum of children's responses
	round.r_hat = round.r
}

func (sn *Node) Respond(view, Round int) error {
	sn.roundLock.RLock()
	round := sn.Rounds[Round]
	sn.roundLock.RUnlock()
	// update max seen round
	lsr := atomic.LoadInt64(&sn.LastSeenRound)
	atomic.StoreInt64(&sn.LastSeenRound, max(int64(Round), lsr))

	if round == nil || round.Log.v == nil {
		// If I was not announced of this round, or I failed to commit
		return nil
	}

	sn.initResponseCrypto(Round)

	// wait on responses from children
	sn.UpdateTimeout()
	sn.roundLock.Lock()
	rmch := sn.RmCh[Round]
	sn.roundLock.Unlock()
	messgs := sn.waitOn(view, rmch, sn.Timeout(), "responses")

	// initialize exception handling
	exceptionV_hat := sn.suite.Point().Null()
	exceptionX_hat := sn.suite.Point().Null()
	round.ExceptionList = make([]abstract.Point, 0)
	nullPoint := sn.suite.Point().Null()
	allmessgs := sn.FillInWithDefaultMessages(view, messgs)

	children := sn.Children(view)
	for _, sm := range allmessgs {
		from := sm.From
		switch sm.Type {
		default:
			// default == no response from child
			// log.Println(sn.Name(), "default in respose for child", from, sm)
			if children[from] != nil {
				round.ExceptionList = append(round.ExceptionList, children[from].PubKey())

				// remove public keys and point commits from subtree of faild child
				sn.add(exceptionX_hat, round.ChildX_hat[from])
				sn.add(exceptionV_hat, round.ChildV_hat[from])
			}
			continue
		case Response:
			// disregard response from children who did not commit
			_, ok := round.ChildV_hat[from]
			if ok == true && round.ChildV_hat[from].Equal(nullPoint) {
				continue
			}

			// log.Println(sn.Name(), "accepts response from", from, sm.Type)
			round.r_hat.Add(round.r_hat, sm.Rm.R_hat)

			sn.add(exceptionV_hat, sm.Rm.ExceptionV_hat)
			sn.add(exceptionX_hat, sm.Rm.ExceptionX_hat)
			round.ExceptionList = append(round.ExceptionList, sm.Rm.ExceptionList...)

		case Error:
			if sm.Err == nil {
				log.Errorln("Error message with no error")
				continue
			}

			// Report up non-networking error, probably signature failure
			log.Errorln(sn.Name(), "Error in respose for child", from, sm)
			err := errors.New(sm.Err.Err)
			sn.PutUpError(view, err)
			return err
		}
	}

	// remove exceptions from subtree that failed
	sn.sub(round.X_hat, exceptionX_hat)
	round.exceptionV_hat = exceptionV_hat

	return sn.actOnResponses(view, Round, exceptionV_hat, exceptionX_hat)
}

func (sn *Node) actOnResponses(view, Round int, exceptionV_hat abstract.Point, exceptionX_hat abstract.Point) error {
	sn.roundLock.RLock()
	round := sn.Rounds[Round]
	sn.roundLock.RUnlock()
	err := sn.VerifyResponses(view, Round)

	isroot := sn.IsRoot(view)
	// if error put it up if parent exists
	if err != nil && !isroot {
		sn.PutUpError(view, err)
		return err
	}

	// if no error send up own response
	if err == nil && !isroot {
		if round.Log.v == nil && sn.ShouldIFail("response") {
			return nil
		}

		// create and putup own response message
		rm := &ResponseMessage{
			R_hat:          round.r_hat,
			ExceptionList:  round.ExceptionList,
			ExceptionV_hat: exceptionV_hat,
			ExceptionX_hat: exceptionX_hat,
			Round:          Round}

		// ctx, _ := context.WithTimeout(context.Background(), 2000*time.Millisecond)
		ctx := context.TODO()
		err = sn.PutUp(ctx, view, &SigningMessage{
			Type: Response,
			View: view,
			Rm:   rm})
	}

	// root reports round is done
	if isroot {
		sn.done <- Round
	}

	if sn.TimeForViewChange() {
		sn.TryViewChange(view + 1)
	}

	return err
}

func (sn *Node) TryViewChange(view int) {
	// should ideally be compare and swap
	// log.Println(sn.Name(), "TRY VIEW CHANGE on", view, "with last view", atomic.LoadInt64(&sn.lastView))
	if int64(view) <= atomic.LoadInt64(&sn.lastView) {
		return
	}
	changing := atomic.LoadInt64(&sn.ChangingView)
	if changing == TRUE {
		return
	}
	atomic.StoreInt64(&sn.ChangingView, TRUE)

	// check who the new view root it
	atomic.SwapInt64(&sn.AmNextRoot, FALSE)
	var rfv string
	if rfv = sn.RootFor(view); rfv == sn.Name() {
		atomic.SwapInt64(&sn.AmNextRoot, TRUE)
	}
	// log.Println(sn.Name(), "thinks", rfv, "should be root for view", view)

	// take action if new view root
	anr := atomic.LoadInt64(&sn.AmNextRoot)

	if anr == TRUE {
		lsr := atomic.LoadInt64(&sn.LastSeenRound)
		log.Println(sn.Name(), "INITIATING VIEW CHANGE FOR VIEW:", view)
		// create new view
		nextViewNo := view
		nextParent := ""
		vcm := &ViewChangeMessage{ViewNo: nextViewNo, Round: int(lsr + 1)}
		sn.ViewChange(nextViewNo, nextParent, vcm)
	}

}

func (sn *Node) NotifyPeerOfVote(view int, vreq *VoteRequest) {
	sn.PutTo(
		context.TODO(),
		vreq.Name,
		&SigningMessage{Type: GroupChanged, View: view, Gcr: &GroupChangeResponse{Vr: *vreq}})
}

func (sn *Node) ApplyAction(view int, vreq *VoteRequest) {
	// Apply action on new view
	if vreq.Action == "add" {
		err := sn.AddPendingPeer(view, vreq.Name)
		// unable to add pending peer
		if err != nil {
			log.Errorln(err)
			return
		}
		// notify peer that they have been added for view
		sn.NotifyPeerOfVote(view, vreq)
	} else if vreq.Action == "remove" {
		log.Println(sn.Name(), "looking to remove peer")
		if ok := sn.RemovePeer(view, vreq.Name); ok {
			log.Println(sn.Name(), "REMOVED peer", vreq.Name)
		}
		sn.NotifyPeerOfVote(view, vreq)
	} else {
		log.Errorln("Vote Request contains uknown action:", vreq.Action)
	}
}

func (sn *Node) actOnVotes(view int, cv *CountedVotes, vreq *VoteRequest) {
	// more than 2/3 of all nodes must vote For, to accept vote request
	// log.Println(sn.Name(), "act on votes:", cv.For, len(sn.HostList))
	accepted := cv.For > 2*len(sn.HostListOn(view))/3
	var actionTaken string = "rejected"
	if accepted {
		actionTaken = "accepted"
	}

	// Report on vote decision
	if sn.IsRoot(view) {
		abstained := len(sn.HostListOn(view)) - cv.For - cv.Against
		log.Infoln("Vote Request for", vreq.Name, "be", vreq.Action, actionTaken)
		log.Infoln("Votes FOR:", cv.For, "; Votes AGAINST:", cv.Against, "; Absteined:", abstained)
	}

	// Act on vote Decision
	if accepted {
		sn.ActionsLock.Lock()
		sn.Actions = append(sn.Actions, vreq)
		sn.ActionsLock.Unlock()

		// propagate view change if new view leader
		sn.TryViewChange(view + 1)
	}

	// List out all votes
	// for _, vote := range round.CountedVotes.Votes {
	// 	log.Infoln(vote.Name, vote.Accepted)
	// }
}

// Called *only* by root node after receiving all commits
func (sn *Node) FinalizeCommits(view int, Round int) error {
	sn.roundLock.RLock()
	round := sn.Rounds[Round]
	sn.roundLock.RUnlock()

	// challenge = Hash(Merkle Tree Root/ Announcement Message, sn.Log.V_hat)
	if sn.Type == PubKey {
		round.c = hashElGamal(sn.suite, sn.LogTest, round.Log.V_hat)
	} else if sn.Type == Vote {
		b, err := round.CountedVotes.MarshalBinary()
		if err != nil {
			log.Fatal("Marshal Binary failed for CountedVotes")
		}
		round.c = hashElGamal(sn.suite, b, round.Log.V_hat)

	} else {
		round.c = hashElGamal(sn.suite, round.MTRoot, round.Log.V_hat)
	}

	proof := make([]hashid.HashId, 0)
	err := sn.Challenge(view, &ChallengeMessage{
		C:            round.c,
		MTRoot:       round.MTRoot,
		Proof:        proof,
		Round:        Round,
		CountedVotes: round.CountedVotes})
	return err
}

// Called by every node after receiving aggregate responses from descendants
func (sn *Node) VerifyResponses(view, Round int) error {
	sn.roundLock.RLock()
	round := sn.Rounds[Round]
	sn.roundLock.RUnlock()

	// Check that: base**r_hat * X_hat**c == V_hat
	// Equivalent to base**(r+xc) == base**(v) == T in vanillaElGamal
	Aux := sn.suite.Point()
	V_clean := sn.suite.Point()
	V_clean.Add(V_clean.Mul(nil, round.r_hat), Aux.Mul(round.X_hat, round.c))
	// T is the recreated V_hat
	T := sn.suite.Point().Null()
	T.Add(T, V_clean)
	T.Add(T, round.exceptionV_hat)

	var c2 abstract.Secret
	isroot := sn.IsRoot(view)
	if isroot {
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
	if !T.Equal(round.Log.V_hat) || (isroot && !round.c.Equal(c2)) {
		// if coco.DEBUG == true {
		panic(sn.Name() + "reports ElGamal Collective Signature failed for Round" + strconv.Itoa(Round))
		// }
		// return errors.New("Veryfing ElGamal Collective Signature failed in " + sn.Name() + "for round " + strconv.Itoa(Round))
	}

	if isroot {
		log.Println(sn.Name(), "reports ElGamal Collective Signature succeeded for round", Round, "view", view)
		nel := len(round.ExceptionList)
		nhl := len(sn.HostListOn(view))
		p := strconv.FormatFloat(float64(nel)/float64(nhl), 'f', 6, 64)
		log.Infoln(sn.Name(), "reports", nel, "out of", nhl, "percentage", p, "failed in round", Round)
		// log.Println(round.MTRoot)
	}
	return nil
}

func (sn *Node) TimeForViewChange() bool {
	lsr := atomic.LoadInt64(&sn.LastSeenRound)
	rpv := atomic.LoadInt64(&RoundsPerView)
	// if this round is last one for this view
	if lsr%rpv == 0 {
		// log.Println(sn.Name(), "TIME FOR VIEWCHANGE:", lsr, rpv)
		return true
	}
	return false
}

func (sn *Node) PutUpError(view int, err error) {
	// log.Println(sn.Name(), "put up response with err", err)
	// ctx, _ := context.WithTimeout(context.Background(), 2000*time.Millisecond)
	ctx := context.TODO()
	sn.PutUp(ctx, view, &SigningMessage{
		Type: Error,
		View: view,
		Err:  &ErrorMessage{Err: err.Error()}})
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
	sn.roundLock.Lock()
	round := sn.Rounds[Round]
	sn.roundLock.Unlock()
	var err error
	round.HashedLog, err = sn.hashLog(Round)
	return err
}

// Auxilary function to perform the actual hashing of the log
func (sn *Node) hashLog(Round int) ([]byte, error) {
	sn.roundLock.Lock()
	round := sn.Rounds[Round]
	sn.roundLock.Unlock()

	h := sn.suite.Hash()
	logBytes, err := round.Log.MarshalBinary()
	if err != nil {
		return nil, err
	}
	h.Write(logBytes)
	return h.Sum(nil), nil
}
