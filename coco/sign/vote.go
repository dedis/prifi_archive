package sign

import (
	"reflect"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/nist"
	"github.com/dedis/protobuf"
)

// For Group Evolution
// Root Server suggests adding or removing a node via a VoteRequest embedded in an AnnoucementMessage
// Follower Servers vote by filling in the CountedVotes structure embedded in Commitment Message

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

type VoteRequest struct {
	Name   string // name of server action is requested on
	Action string // "add" or "remove"
}

// When sent up in a Committment Message CountedVotes contains a subtree's votes
// When sent down in a Challenge Message CountedVotes contains the whole tree's votes
type CountedVotes struct {
	Votes   []*VoteResponse // vote responses from descendants
	For     int             // number of votes for
	Against int             // number of votes against
}

func (cv *CountedVotes) MarshalBinary() ([]byte, error) {
	return protobuf.Encode(cv)
}

func (cv *CountedVotes) UnmarshalBinary(data []byte) error {
	var cons = make(protobuf.Constructors)
	var point abstract.Point
	var secret abstract.Secret
	var suite = nist.NewAES128SHA256P256()
	cons[reflect.TypeOf(&point).Elem()] = func() interface{} { return suite.Point() }
	cons[reflect.TypeOf(&secret).Elem()] = func() interface{} { return suite.Secret() }
	return protobuf.DecodeWithConstructors(data, cv, cons)
}
