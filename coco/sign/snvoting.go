package sign

import (
	"sync/atomic"
	"time"

	log "github.com/Sirupsen/logrus"
	"golang.org/x/net/context"
)

func (sn *Node) ApplyVotes(ch chan *Vote) {
	go func() {
		for v := range ch {
			sn.ApplyVote(v)
		}
	}()
}

// HERE: after we change to the new view, we could send our parent
// a notification that we are ready to use the new view

func (sn *Node) ApplyVote(v *Vote) {
	atomic.StoreInt64(&sn.LastAppliedVote, int64(v.Index))

	switch v.Type {
	case ViewChangeVT:
		sn.ChangeView(v.Vcv)
	case AddVT:
		sn.AddAction(v.Av.View, v)
	case RemoveVT:
		sn.AddAction(v.Rv.View, v)
	case ShutdownVT:
		sn.Close()
	default:
	}
}

func (sn *Node) AddAction(view int, v *Vote) {
	sn.Actions[view] = append(sn.Actions[view], v)
}

func (sn *Node) AddSelf(parent string) error {
	log.Println("AddSelf: connecting to:", parent)
	err := sn.ConnectTo(parent)
	if err != nil {
		return err
	}

	log.Println("AddSelf: putting group change message to:", parent)
	return sn.PutTo(
		context.TODO(),
		parent,
		&SigningMessage{
			Type: GroupChange,
			View: -1,
			Vrm: &VoteRequestMessage{
				Vote: &Vote{
					Type: AddVT,
					Av: &AddVote{
						Name:   sn.Name(),
						Parent: parent}}}})
}

func (sn *Node) RemoveSelf() error {
	return sn.PutUp(
		context.TODO(),
		int(sn.ViewNo),
		&SigningMessage{
			Type: GroupChange,
			View: -1,
			Vrm: &VoteRequestMessage{
				Vote: &Vote{
					Type: RemoveVT,
					Rv: &RemoveVote{
						Name:   sn.Name(),
						Parent: sn.Parent(sn.ViewNo)}}}})
}

func (sn *Node) CatchUp(vi int, from string) {
	log.Println(sn.Name(), "attempting to catch up vote", vi)

	ctx := context.TODO()
	sn.PutTo(ctx, from,
		&SigningMessage{
			From:  sn.Name(),
			Type:  CatchUpReq,
			Cureq: &CatchUpRequest{Index: vi}})
}

func (sn *Node) StartGossip() {
	go func() {
		t := time.Tick(GOSSIP_TIME)
		for _ = range t {
			c := append(sn.Children(sn.ViewNo), sn.Parent(sn.ViewNo))
			from := c[sn.Rand.Int()%len(c)]
			sn.CatchUp(atomic.LoadInt64(&sn.LastAppliedVote)+1, from)
		}
	}()
}
