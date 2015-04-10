package sign

import (
	"errors"
	"strconv"
	"time"

	log "github.com/Sirupsen/logrus"
	"golang.org/x/net/context"

	"github.com/dedis/prifi/coco/coconet"
)

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

// Returns the list of children for new view (peers - parent)
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
			log.Println(sn.Name(), "NO HEARTBEAT - try view change:", view)
			sn.TryViewChange(view + 1)
		})
	}
	sn.hbLock.Unlock()

}

func (sn *Node) TryRootFailure(view int) bool {
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
			return true
		}
	}

	return false
}

func (sn *Node) TryFailure(view int) bool {
	if sn.TryRootFailure() {
		return ErrImposedFailure
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
}

func (sn *Node) setUpRound(am *AnnouncementMessage) error {
	// TODO: accept annoucements on old views?? linearizabiltity?
	if sn.ChangingView == TRUE {
		log.Println("currently chaning view")
		return ChangingViewError
	}

	Round := am.Round
	if Round <= sn.LastSeenRound {
		return ErrPastRound
	}

	// set up commit and response channels for the new round
	sn.Rounds[Round] = NewRound()
	sn.Rounds[Round].Vote = am.Vote

	// update max seen round
	sn.LastSeenRound = max(sn.LastSeenRound, int64(Round))

	// the root is the only node that keeps track of round # internally
	if sn.IsRoot(view) {
		sn.RoundsAsRoot += 1
		// TODO: is sn.Round needed if we have LastSeenRound
		sn.Round = Round

		// Create my back link to previous round
		sn.SetBackLink(Round)
		// sn.SetAccountableRound(Round)
	}

	return nil
}

// accommodate nils
func (sn *Node) add(a abstract.Point, b abstract.Point) {
	if a == nil {
		a = sn.suite.Point().Null()
	}
	if b != nil {
		a.Add(a, b)
	}

}

// accommodate nils
func (sn *Node) sub(a abstract.Point, b abstract.Point) {
	if a == nil {
		a = sn.suite.Point().Null()
	}
	if b != nil {
		a.Sub(a, b)
	}

}

func (sn *Node) subExceptions(a abstract.Point, keys []abstract.Point) {
	for _, k := range keys {
		sn.sub(a, k)
	}
}

func (sn *Node) updateHighestVote(hv int, from string) {
	if sn.HighestVote < hv {
		sn.HighestVote = hv
		sn.CatchUp(from)
	}
}

func max(a int64, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
