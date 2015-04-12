package sign

import (
	"reflect"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/nist"
	"github.com/dedis/prifi/coco/hashid"
	"github.com/dedis/prifi/coco/proof"
	"github.com/dedis/protobuf"
)

// All message structures defined in this package are used in the
// Collective Signing Protocol
// Over the network they are sent as byte slices, so each message
// has its own MarshlBinary and UnmarshalBinary method

type MessageType int

const (
	Unset MessageType = iota
	Announcement
	Commitment
	Challenge
	Response
	ViewChange
	ViewAccepted
	ViewConfirmed
	GroupChange
	GroupChanged
	Default // for internal use
	Error
)

func (m MessageType) String() string {
	switch m {
	case Unset:
		return "Unset"
	case Announcement:
		return "Announcement"
	case Commitment:
		return "Commitment"
	case Challenge:
		return "Challenge"
	case Response:
		return "Response"
	case ViewChange:
		return "ViewChange"
	case ViewAccepted:
		return "ViewAccepted"
	case ViewConfirmed:
		return "ViewConfirmed"
	case GroupChange:
		return "GroupChange"
	case GroupChanged:
		return "GroupChanged"
	case Default: // for internal use
		return "Default"
	case Error:
		return "Error"
	}
	return "INVALID TYPE"
}

// Signing Messages are used for all comunications between servers
// It is imporant for encoding/ decoding for type to be kept as first field
type SigningMessage struct {
	Type         MessageType
	Am           *AnnouncementMessage
	Com          *CommitmentMessage
	Chm          *ChallengeMessage
	Rm           *ResponseMessage
	Vcm          *ViewChangeMessage
	Vcfm         *ViewConfirmedMessage
	Vam          *ViewAcceptedMessage
	Vrm          *VoteRequestMessage
	Err          *ErrorMessage
	From         string
	View         int
	LastSeenVote int // highest vote ever seen and commited in log, used for catch-up
}

func NewSigningMessage() interface{} {
	return &SigningMessage{}
}

func (sm *SigningMessage) MarshalBinary() ([]byte, error) {
	return protobuf.Encode(sm)
}

func (sm *SigningMessage) UnmarshalBinary(data []byte) error {
	var cons = make(protobuf.Constructors)
	var point abstract.Point
	var secret abstract.Secret
	var suite = nist.NewAES128SHA256P256()
	cons[reflect.TypeOf(&point).Elem()] = func() interface{} { return suite.Point() }
	cons[reflect.TypeOf(&secret).Elem()] = func() interface{} { return suite.Secret() }
	return protobuf.DecodeWithConstructors(data, sm, cons)
}

// Broadcasted message initiated and signed by proposer
type AnnouncementMessage struct {
	LogTest []byte // TODO: change LogTest to Messg
	Round   int

	// VoteRequest *VoteRequest
	Vote *Vote // Vote Request (propose)
}

type CommitmentMessage struct {
	V     abstract.Point // commitment Point
	V_hat abstract.Point // product of subtree participating nodes' commitment points
	X_hat abstract.Point // product of subtree participating nodes' public keys

	MTRoot hashid.HashId // root of Merkle (sub)Tree

	// public keys of children servers that did not respond to
	// annoucement from root
	ExceptionList []abstract.Point

	// CountedVotes *CountedVotes // CountedVotes contains a subtree's votes
	Vote *Vote // Vote Response (promise)

	Round int
}

type ChallengeMessage struct {
	C abstract.Secret // challenge

	// Depth  byte
	MTRoot hashid.HashId // the very root of the big Merkle Tree
	Proof  proof.Proof   // Merkle Path of Proofs from root to us

	// CountedVotes *CountedVotes //  CountedVotes contains the whole tree's votes
	Vote *Vote // Vote Confirmerd/ Rejected (accept)

	Round int
}

type ResponseMessage struct {
	R_hat abstract.Secret // response

	// public keys of children servers that did not respond to
	// challenge from root
	ExceptionList []abstract.Point
	// cummulative point commits of nodes that failed after commit
	ExceptionV_hat abstract.Point
	// cummulative public keys of nodes that failed after commit
	ExceptionX_hat abstract.Point

	Vote *Vote // Vote Ack/Nack in thr log (ack/nack)

	Round int
}

type ErrorMessage struct {
	Err string
}

// ViewChange message is passed from the new parent to its children
//  i.e. all peers that are not its parent.
// The node that receives the ViewChange request sets the sender to be
// its parent for the new view, and forwards the message to all its children,
// so they can accept it as their new parent as well...
type ViewChangeMessage struct {
	ViewNo int
	Round  int
}

// Not a typical message of a view Change protocol
// Sent up by a node to signal to its parent that the nodes in
// its subtree have accepted the new view
type ViewAcceptedMessage struct {
	ViewNo int
	Votes  int // number of nodes in my subtree who accepted view ViewNo
}

// initiated by Root to confirm >2/3 of nodes accepted ViewNo
// TODO: maybe send equivalent of ChallengeMessage to allow verifying view confirm
type ViewConfirmedMessage struct {
	ViewNo int
}

type VoteRequestMessage struct {
	Vote *Vote
}
