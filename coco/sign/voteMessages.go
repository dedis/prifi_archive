package sign

import (
	"reflect"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/nist"
	"github.com/dedis/protobuf"
)

type VoteType int

const (
	DefaultVT VoteType = iota
	ViewChangeVT
	AddVT
	RemoveVT
	ShutdownVT
)

// Multi-Purpose Vote embeds Action to be voted on, aggregated votes, and decison
// when embedded in Announce it equals Vote Request (propose)
// when embedded in Commit it equals Vote Response (promise)
// when embedded in Challenge it equals Vote Confirmed (accept)
// when embedded in Response it equals Vote Ack/ Nack (ack/ nack)
type Vote struct {
	Index int
	View  int
	Round int

	Action interface{}

	Count     *Count
	Confirmed bool
}

type ViewChangeVote struct {
	View   int    // view number we want to switch to
	Parent string // our parent currently
	Root   string // the root for the new view
	// TODO: potentially have signature of new root on proposing this view
}

type AddVote struct {
	View   int // view number when we want add to take place
	Name   string
	Parent string
}

type VoteResponse struct {
	Name     string // name of the responder
	Accepted bool
	// signature proves ownership of vote and
	// shows that it was emitted during a specifc Round
	Sig BasicSig
}

// for sorting arrays of VoteResponse
type ByVoteResponse []*VoteResponse

func (vr ByVoteResponse) Len() int           { return len(vr) }
func (vr ByVoteResponse) Swap(i, j int)      { vr[i], vr[j] = vr[j], vr[i] }
func (vr ByVoteResponse) Less(i, j int) bool { return (vr[i].Name < vr[j].Name) }

// When sent up in a Committment Message CountedVotes contains a subtree's votes
// When sent down in a Challenge Message CountedVotes contains the whole tree's votes
type Count struct {
	Responses []*VoteResponse // vote responses from descendants
	For       int             // number of votes for
	Against   int             // number of votes against
}

func (cv *Count) MarshalBinary() ([]byte, error) {
	return protobuf.Encode(cv)
}

func (cv *Count) UnmarshalBinary(data []byte) error {
	var cons = make(protobuf.Constructors)
	var point abstract.Point
	var secret abstract.Secret
	var suite = nist.NewAES128SHA256P256()
	cons[reflect.TypeOf(&point).Elem()] = func() interface{} { return suite.Point() }
	cons[reflect.TypeOf(&secret).Elem()] = func() interface{} { return suite.Secret() }
	return protobuf.DecodeWithConstructors(data, cv, cons)
}
