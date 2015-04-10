package sign

import (
	"golang.org/x/net/context"

	log "github.com/Sirupsen/logrus"
	"github.com/dedis/prifi/coco/coconet"
)

// TODO: promise, ...
// split voting out of collective signing logic

func (sn *Node) Propose(view int, am *AnnouncementMessage) error {
	if err := sn.setUpRound(view, am); err != nil {
		return err
	}
	sn.Rounds[am.Round].Vote = am.Vote

	// Inform all children of proposal
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

	if len(sn.Children(view)) == 0 {
		sn.Promise(view, am.Round, nil)
	}
	return nil
}

func (sn *Node) Promise(view, Round int, sm *SigningMessage) error {
	// update max seen round
	sn.LastSeenRound = max(sn.LastSeenRound, Round)

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

	for _, sm := range round.Commits {
		// count children votes
		round.Vote.Count.Responses = append(round.Vote.Count.Responses, sm.Com.Vote.Count.Responses...)
		round.Vote.Count.For += sm.Com.Vote.Count.For
		round.Vote.Count.Against += sm.Com.Vote.Count.Against

	}

	return sn.actOnPromises(view, Round)
}

func (sn *Node) actOnPromises(view, Round int) error {
	round := sn.Rounds[Round]
	var err error

	if sn.IsRoot(view) {
		sn.commitsDone <- Round
	} else {
		// create and putup own commit message
		com := &CommitmentMessage{
			Vote:  round.Vote,
			Round: Round}

		// ctx, _ := context.WithTimeout(context.Background(), 2000*time.Millisecond)
		// log.Println(sn.Name(), "puts up promise")
		ctx := context.TODO()
		err = sn.PutUp(ctx, view, &SigningMessage{
			View: view,
			Type: Commitment,
			Com:  com})
	}
	return err
}

func (sn *Node) Accept(view int, chm *ChallengeMessage) error {
	// update max seen round
	sn.LastSeenRound = max(sn.LastSeenRound, chm.Round)

	round := sn.Rounds[chm.Round]
	if round == nil {
		return nil
	}

	// act on decision of aggregated votes
	// log.Println(sn.Name(), chm.Round, round.VoteRequest)
	if round.Vote != nil {
		// append vote to vote log
		// potentially initiates signing node action based on vote
		sn.actOnVotes(view, chm.Vote)
	}

	if err := sn.SendChildrenChallenges(view, chm); err != nil {
		return err
	}

	sn.initResponseCrypto(chm.Round)
	if len(sn.Children(view)) == 0 {
		sn.Respond(view, chm.Round, nil)
	}

	return nil
}

func (sn *Node) Accepted(view, Round int, sm *SigningMessage) error {
	// update max seen round
	sn.LastSeenRound = max(sn.LastSeenRound, Round)

	round := sn.Rounds[Round]
	if round == nil {
		// TODO: if combined with cosi pubkey, check for round.Log.v existing needed
		// If I was not announced of this round, or I failed to commit
		return nil
	}

	if sm != nil {
		round.Responses = append(round.Responses, sm)
	}
	if len(round.Responses) != len(sn.Children(view)) {
		return nil
	}
	// TODO: after having a chance to inspect the contents of the challenge
	// nodes can raise an alarm respond by ack/nack

	if sn.IsRoot(view) {
		sn.done <- Round
	} else {
		// create and putup own response message
		rm := &ResponseMessage{
			Vote:  round.Vote,
			Round: Round}

		// ctx, _ := context.WithTimeout(context.Background(), 2000*time.Millisecond)
		ctx := context.TODO()
		return sn.PutUp(ctx, view, &SigningMessage{
			Type: Response,
			View: view,
			Rm:   rm})
	}

	return nil
}

func (sn *Node) actOnVotes(view int, v *Vote) {
	log.Println(sn.Name(), "act on votes:")
	// TODO: percentage of nodes for quorum should be parameter
	// Basic check to validate Vote was Confirmed, can be enhanced
	// TODO: signing node can go through list of votes and verify
	accepted := v.Count.For > 2*len(sn.HostListOn(view))/3
	var actionTaken string = "rejected"
	if accepted {
		actionTaken = "accepted"
	}

	// Report on vote decision
	if sn.IsRoot(view) {
		abstained := len(sn.HostListOn(view)) - v.Count.For - v.Count.Against
		log.Infoln("Votes FOR:", v.Count.For, "; Votes AGAINST:", v.Count.Against, "; Absteined:", abstained)
	}

	// Act on vote Decision
	if accepted {
		sn.VoteLog = append(sn.VoteLog, v)

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
