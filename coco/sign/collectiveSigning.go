package sign

import (
	"errors"
	"io"
	"strconv"
	"sync/atomic"

	log "github.com/Sirupsen/logrus"
	"golang.org/x/net/context"

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

// Get multiplexes all messages from TCPHost using application logic
func (sn *Node) get() error {
	sn.UpdateTimeout()
	msgchan := sn.Host.Get()
	// heartbeat for intiating viewChanges, allows intial 500s setup time
	sn.hbLock.Lock()
	// sn.heartbeat = time.NewTimer(500 * time.Second)
	sn.hbLock.Unlock()

	for {
		select {
		case <-sn.closing:
			sn.StopHeartbeat()
			return nil
		default:
			nm, ok := <-msgchan
			err := nm.Err

			// TODO: gracefull shutdown voting
			if !ok || err == coconet.ErrClosed || err == io.EOF {
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
			//log.Printf("got message: %#v with error %v\n", sm, err)
			sm := nm.Data.(*SigningMessage)
			sm.From = nm.From
			sn.updateHighestVote(sm.HighestVote, sm.From)

			log.Println(sn.Name(), "GOT ", sm.Type)
			switch sm.Type {
			// if it is a bad message just ignore it
			default:
				continue
			case Announcement:
				if !sn.IsParent(sm.View, sm.From) {
					log.Fatalln(sn.Name(), "received announcement from non-parent on view", sm.View)
					continue
				}
				sn.ReceivedHeartbeat(sm.View)

				// log.Println("RECEIVED ANNOUNCEMENT MESSAGE")
				var err error
				if sm.Am.Vote != nil {
					err = sn.Propose(sm.View, sm.Am)
				} else {
					err = sn.Announce(sm.View, sm.Am)
				}
				if err != nil {
					log.Errorln(sn.Name(), "announce error:", err)
				}

			case Challenge:
				if !sn.IsParent(sm.View, sm.From) {
					log.Fatalln(sn.Name(), "received challenge from non-parent on view", sm.View)
					continue
				}
				sn.ReceivedHeartbeat(sm.View)

				var err error
				if sm.Am.Vote != nil {
					err = sn.Accept(sm.View, sm.Chm)
				} else {
					err = sn.Challenge(sm.View, sm.Chm)
				}
				if err != nil {
					log.Errorln(sn.Name(), "challenge error:", err)
				}

			// if it is a commitment or response it is from the child
			case Commitment:
				if !sn.IsChild(sm.View, sm.From) {
					log.Fatalln(sn.Name(), "received commitment from non-child on view", sm.View)
					continue
				}

				var err error
				if sm.Am.Vote != nil {
					err = sn.Promise(sm.View, sm.Com.Round, sm)
				} else {
					err = sn.Commit(sm.View, sm.Com.Round, sm)
				}
				if err != nil {
					log.Errorln(sn.Name(), "commit error:", err)
				}
			case Response:
				if !sn.IsChild(sm.View, sm.From) {
					log.Fatalln(sn.Name(), "received response from non-child on view", sm.View)
					continue
				}

				var err error
				if sm.Am.Vote != nil {
					err = sn.Accepted(sm.View, sm.Rm.Round, sm)
				} else {
					err = sn.Respond(sm.View, sm.Rm.Round, sm)
				}
			case ViewChange:
				// if we have already seen this view before skip it
				if int64(sm.View) <= sn.lastView {
					log.Errorf("VIEWCHANGE: already seen this view: %d <= %d", sm.View, sn.lastView, sm.From)
					continue
				}
				sn.lastView = int64(sm.View)
				sn.StopHeartbeat()
				log.Printf("Host (%s) VIEWCHANGE", sn.Name(), sm.Vcm)
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
					continue
				}
				log.Printf("Host (%s) VIEWACCEPTED", sn.Name())
				sn.StopHeartbeat()
				// sn.VamChLock.Lock()
				// sn.VamCh <- sm
				// sn.VamChLock.Unlock()
			case ViewConfirmed:
				if int64(sm.View) < sn.lastView {
					log.Errorf("VIEW CONFIRMED: already seen this view: %d < %d", sm.View, sn.lastView)
					continue
				}
				// log.Printf("Host (%s) VIEW CONFIRMED", sn.Name())
				sn.StopHeartbeat()
				sn.ViewChanged(sm.Vcfm.ViewNo, sm)
			case GroupChange:
				log.Println("Received Group Change Message:", sm.Gcm.Vr, sm)
				sn.StopHeartbeat()

				// if the view is uninitialized (-1) the node trying to connect must be our peer.
				// update the signing messages view to our lastView.
				// and move the peer to our pending peers list.
				// XXX: assumes the peer isn't our actual peer
				if sm.View == -1 {
					log.Println("setting view number of votine request")
					sm.View = int(sn.lastView)
					// if the peer sent an add request
					// ad it to the pending peers list
					if sm.Gcm.Vr.Action == "add" {
						sn.AddPeerToPending(sm.From)
					}
				}
				if sn.RootFor(sm.View) != sn.Name() {
					log.Println("NOT ROOT: Sending up:", sm.View)
					sn.PutUp(context.TODO(), sm.View, sm)
					continue
				}
				// I am the root for this
				log.Println("Starting Voting Round")
				vr := sm.Gcm.Vr
				sn.StartVotingRound(vr.Name, vr.Action)
			case GroupChanged:
				sn.StopHeartbeat()
				// only the leaf that initiated the GroupChange should get a response
				log.Errorln("Received Group Changed Response: GroupChanged:", sm, sm.Gcr)
				vr := sm.Gcr.Vr
				// clear pending actions
				sn.ActionsLock.Lock()
				sn.Actions = make([]*VoteRequest, 0)
				sn.ActionsLock.Unlock()

				if vr.Action == "remove" {
					log.Println("Stopping Heartbeat")
					continue
				}
				log.Errorln("view ==", sm.View)
				view := sm.View
				log.Errorln("AddParent:", sm.From)

				sn.Views().Lock()
				_, exists := sn.Views().Views[view]
				sn.Views().Unlock()
				// also need to add self
				if !exists {
					sn.NewView(view, sm.From, nil, sm.Gcr.Hostlist)
				}
				sn.ApplyAction(view, &vr)
				// create the view
				sn.AddParent(view, sm.From)
				log.Println("GROUP CHANGE RESPONSE:", vr)
			case Error:
				log.Println("Received Error Message:", ErrUnknownMessageType, sm, sm.Err)
			}
			// }(sm)
		}
	}

}

func (sn *Node) Announce(view int, am *AnnouncementMessage) error {
	log.Println(sn.Name(), "RECEIVED annoucement on", view)

	if err := sn.TryFailure(view); err != nil {
		return err
	}

	Round := am.Round
	if err = sn.setUpRound(am); err != nil {
		return err
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

	// return sn.Commit(view, am)
	sn.PrepareForCommits(view, am)
	if len(sn.Children(view)) == 0 {
		sn.Commit(view, am.Round, nil)
	}
	return nil
}

func (sn *Node) PrepareForCommits(view int, am *AnnouncementMessage) {
	Round := am.Round

	// update max seen round
	lsr := atomic.LoadInt64(&sn.LastSeenRound)
	atomic.StoreInt64(&sn.LastSeenRound, max(int64(Round), lsr))

	sn.initCommitCrypto(Round)
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

func (sn *Node) Commit(view, Round int, sm *SigningMessage) error {
	// update max seen round
	sn.LastSeenRound = max(sn.LastSeenRound, int64(Round))

	round := sn.Rounds[Round]
	if round == nil {
		// was not announced of this round, should retreat
		return nil
	}

	if sm != nil {
		round.Commits = append(round.Commits, sm)
	}

	if len(round.Commits) != len(sn.Children(view)) {
		return nil
	}

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

	// TODO: fill in missing commit messages, and add back exception code
	for _, sm := range round.Commits {
		from := sm.From

		round.Leaves = append(round.Leaves, sm.Com.MTRoot)
		round.LeavesFrom = append(round.LeavesFrom, from)
		round.ChildV_hat[from] = sm.Com.V_hat
		round.ChildX_hat[from] = sm.Com.X_hat
		round.ExceptionList = append(round.ExceptionList, sm.Com.ExceptionList...)

		// add good child server to combined public key, and point commit
		sn.add(round.X_hat, sm.Com.X_hat)
		sn.add(round.Log.V_hat, sm.Com.V_hat)
	}

	if sn.Type == PubKey {
		log.Println("sign.Node.Commit using PubKey")
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
	round := sn.Rounds[Round]
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
		log.Println(sn.Name(), "puts up commit")
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
	round := sn.Rounds[chm.Round]

	// update max seen round
	sn.LastSeenRound = max(sn.LastSeenRound, int64(chm.Round))

	if round == nil {
		return nil
	}

	// register challenge
	round.c = chm.C

	// act on decision of aggregated votes
	// log.Println(sn.Name(), chm.Round, round.VoteRequest)
	// if round.VoteRequest != nil {
	// 	sn.actOnVotes(view, chm.CountedVotes, round.VoteRequest)
	// }

	if sn.Type == PubKey {
		log.Println(sn.Name(), "challenge: using pubkey", sn.Type, chm.CountedVotes)
		if err := sn.SendChildrenChallenges(view, chm); err != nil {
			return err
		}
	} else {
		log.Println(sn.Name(), "chalenge: using merkle proofs")
		// messages from clients, proofs computed
		if sn.CommitedFor(round) {
			if err := sn.SendLocalMerkleProof(view, chm); err != nil {
				return err
			}

		}
		if err := sn.SendChildrenChallengesProofs(view, chm); err != nil {
			return err
		}
	}

	log.Println(sn.Name(), "In challenge before response")
	sn.PrepareForResponses(view, chm.Round)
	if len(sn.Children(view)) == 0 {
		sn.Respond(view, chm.Round, nil)
	}
	log.Println(sn.Name(), "Done handling challenge message")
	return nil
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

func (sn *Node) PrepareForResponses(view, Round int) {
	lsr := atomic.LoadInt64(&sn.LastSeenRound)
	atomic.StoreInt64(&sn.LastSeenRound, max(int64(Round), lsr))

	sn.initResponseCrypto(Round)
}

func (sn *Node) initResponseCrypto(Round int) {
	round := sn.Rounds[Round]
	// generate response   r = v - xc
	round.r = sn.suite.Secret()
	round.r.Mul(sn.PrivKey, round.c).Sub(round.Log.v, round.r)
	// initialize sum of children's responses
	round.r_hat = round.r
}

func (sn *Node) Respond(view, Round int, sm *SigningMessage) error {
	log.Println(sn.Name(), "in respond")
	round := sn.Rounds[Round]

	// update max seen round
	sn.LastSeenRound = max(sn.LastSeenRound, int64(Round))

	if round == nil || round.Log.v == nil {
		// If I was not announced of this round, or I failed to commit
		return nil
	}

	if sm != nil {
		round.Responses = append(round.Responses, sm)
	}
	if len(round.Responses) != len(sn.Children(view)) {
		return nil
	}

	// initialize exception handling
	exceptionV_hat := sn.suite.Point().Null()
	exceptionX_hat := sn.suite.Point().Null()
	round.ExceptionList = make([]abstract.Point, 0)
	nullPoint := sn.suite.Point().Null()
	allmessgs := sn.FillInWithDefaultMessages(view, round.Responses)

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
	round := sn.Rounds[Round]
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
		log.Println("acting on responses: trying viewchanges")
		sn.TryViewChange(view + 1)
	}

	return err
}

func (sn *Node) TryViewChange(view int) {
	// should ideally be compare and swap
	log.Println(sn.Name(), "TRY VIEW CHANGE on", view, "with last view", atomic.LoadInt64(&sn.lastView))
	if int64(view) <= atomic.LoadInt64(&sn.lastView) {
		log.Println("view < sn.lastView")
		return
	}
	changing := atomic.LoadInt64(&sn.ChangingView)
	if changing == TRUE {
		log.Errorln("cannot try view change: already chaning view")
		return
	}
	atomic.StoreInt64(&sn.ChangingView, TRUE)

	// check who the new view root it
	atomic.SwapInt64(&sn.AmNextRoot, FALSE)
	var rfv string
	if rfv = sn.RootFor(view); rfv == sn.Name() {
		atomic.SwapInt64(&sn.AmNextRoot, TRUE)
	}
	log.Println(sn.Name(), "thinks", rfv, "should be root for view", view)

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
	// if I am peers with this
	log.Println("NOTIFYING PEER OF VOTE")
	if good, ok := sn.Pending()[vreq.Name]; !ok || !good {
		log.Println("not notifying peer of vote: not connected: ", ok, good)
		return
	}
	log.Println("successfully notifying peer of vote:", vreq.Name, vreq)
	sn.PutTo(
		context.TODO(),
		vreq.Name,
		&SigningMessage{Type: GroupChanged, View: view, Gcr: &GroupChangeResponse{Hostlist: sn.Hostlist(), Vr: *vreq}})
}

func (sn *Node) ApplyAction(view int, vreq *VoteRequest) {
	// Apply action on new view
	if vreq.Action == "add" {
		log.Println("adding pending peer:", view, vreq)
		sn.AddPeerToHostlist(view, vreq.Name)
		err := sn.AddPendingPeer(view, vreq.Name)
		// unable to add pending peer
		if err != nil {
			log.Errorln(err)
			return
		}
		// peer is notified on actOnVotes
		// notify peer that they have been added for view
		// sn.NotifyPeerOfVote(view, vreq)
	} else if vreq.Action == "remove" {
		log.Println(sn.Name(), "looking to remove peer")
		sn.RemovePeerFromHostlist(view, vreq.Name)
		if ok := sn.RemovePeer(view, vreq.Name); ok {
			log.Println(sn.Name(), "REMOVED peer", vreq.Name)
		}
		// sn.NotifyPeerOfVote(view, vreq)
	} else {
		log.Errorln("Vote Request contains uknown action:", vreq.Action)
	}
}

func (sn *Node) actOnVotes(view int, cv *CountedVotes, vreq *VoteRequest) {
	// more than 2/3 of all nodes must vote For, to accept vote request
	log.Println(sn.Name(), "act on votes:", cv.For, len(sn.HostList))
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
		log.Println("actOnVotes: vote has been accepted: trying viewchange")
		// XXX WHEN TESTING DO NOT VIEW CHANGE XXX TODO
		/*
			sn.NotifyPeerOfVote(view, vreq)
			time.Sleep(7 * time.Second) // wait for all vote responses to be propogated before trying to change view
			sn.TryViewChange(view + 1)
		*/
	}

	// List out all votes
	// for _, vote := range round.CountedVotes.Votes {
	// 	log.Infoln(vote.Name, vote.Accepted)
	// }
}

// Called *only* by root node after receiving all commits
func (sn *Node) FinalizeCommits(view int, Round int) error {
	round := sn.Rounds[Round]

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
	round := sn.Rounds[Round]

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
