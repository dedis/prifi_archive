package sign

import (
	"github.com/dedis/crypto/abstract"
)

// For Group Evolution
// Root Server suggests adding or removing a node via a VoteRequest embedded in an AnnoucementMessage
// Follower Servers vote by filling in the CountedVotes structure embedded in Commitment Message
//

// A basic, verifiable signature
type BasicSig struct {
	C abstract.Secret // challenge
	R abstract.Secret // response
}

type VoteResponse struct {
	name     string // name of the responder
	accepted bool
	// signature proves ownership of vote and
	// shows that it was emitted during a specifc Round
	sig BasicSig
}

type VoteRequest struct {
	name   string // name of server action is requested on
	action string // "add" or "remove"
}

// When sent up in a Committment Message CountedVotes contains a subtree's votes
// When sent down in a Challenge Message CountedVotes contains the whole tree's votes
type CountedVotes struct {
	Votes   []VoteResponse // vote responses from descendants
	For     int            // number of votes for
	Against int            // number of votes against
}
