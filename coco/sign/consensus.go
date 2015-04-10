package sign

// TODO: promise, ...
// split voting out of collective signing logic

func (sn *Node) Propose(view int, am *AnnouncementMessage) error {
	if err = sn.setUpRound(am); err != nil {
		return err
	}

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

	for _, sm := range round.Commits {
		// count children votes
		round.CountedVotes.Votes = append(round.CountedVotes.Votes, sm.Com.CountedVotes.Votes...)
		round.CountedVotes.For += sm.Com.CountedVotes.For
		round.CountedVotes.Against += sm.Com.CountedVotes.Against

	}

	return sn.actOnPromises()
}

//
