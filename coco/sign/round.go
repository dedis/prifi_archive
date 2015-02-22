package sign

import "github.com/dedis/crypto/abstract"
import "github.com/dedis/prifi/coco/hashid"
import "github.com/dedis/prifi/coco/proof"

const FIRST_ROUND int = 1 // start counting rounds at 1

type Round struct {
	c abstract.Secret // round lasting challenge
	r abstract.Secret // round lasting response

	Log       SNLog // round lasting log structure
	HashedLog []byte

	r_hat abstract.Secret // aggregate of responses
	X_hat abstract.Point  // aggregate of public keys

	// own big merkle subtree
	MTRoot     hashid.HashId   // mt root for subtree, passed upwards
	Leaves     []hashid.HashId // leaves used to build the merkle subtre
	LeavesFrom []string        // child names for leaves

	// mtRoot before adding HashedLog
	LocalMTRoot hashid.HashId

	// merkle tree roots of children in strict order
	CMTRoots     []hashid.HashId
	CMTRootNames []string
	Proofs       map[string]proof.Proof

	// round-lasting public keys of children servers that did not
	// respond to latest commit or respond phase, in subtree
	ExceptionList []abstract.Point
	// combined point commits of children servers in subtree
	ChildV_hat map[string]abstract.Point
	// combined public keys of children servers in subtree
	ChildX_hat map[string]abstract.Point

	BackLink hashid.HashId
	AccRound []byte
}

func NewRound() *Round {
	round := &Round{}
	round.ExceptionList = make([]abstract.Point, 0)

	return round
}
