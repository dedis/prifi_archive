// Scalable tree protocols.
// All interaction is between immediate parent and children in a tree.
// One "round-trip" through the tree starts at (is initiated by) the root,
// propagates downward to the leaves, then back up to the root.
// Each node can tolerate a limited number of failures among its descendants,
// before it must "fail" itself (or simply pause or halt if it's the root).
package tree

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"github.com/dedis/crypto/abstract"
)





// Each node maintains _one_ tamper-evident log of events it generates.
// Each node must ensure that its event history remains linear
// (i.e., does not fork or roll back).
// One event history is shared among all trees the node participates in.
//
// Each tree requires the node to produce new events
// within certain time-windows determined by the node's ancestor(s) in the tree.
// If the next-event time windows for multiple trees overlap,
// the node can produce one event to "satisfy" several overlapping trees.
// If a node fails to produce an event for a tree in the given time window,
// the node is considered to have "failed" during the corresponding tree step.
//
// Each node, when it receives a new event from a peer,
// verifies that the new event is a strict successor to the last one,
// and does not "fork" the peer's event history for example.
// Each node's metadata included in a new event includes skip-chain info,
// allowing other nodes to verify small or large steps forward in history
// without having to store or traverse many intervening nodes in the chain.

type event struct {
	seq uint64
	id HashId
	pred []HashId
	data bytes.Buffer
}


type log struct {
	suite abstract.Suite
	cur *event		// current event under construction
}

func newLog(suite abstract.Suite) {
	l := log{}
	l.suite = suite
}

// Creates a new, un-finalized event, closing out the last current one if any.
// The caller can write bytes to the data buffer before finalizing.
func (l *log) newEvent() *event {
	e := &event{}

	// Close out the immediate predecessor event
	ip := l.cur		// immediate predecessor
	var pred []HashId
	if ip != nil {

		// Compute the immediate predecessor's event ID
		h := l.suite.Hash()
		h.Write(ip.data.Bytes())
		ip.id = HashId(h.Sum(nil))

		// Start with a copy of our predecessor's predecessor list
		pred = make([]HashId, len(ip.pred))
		copy(pred, ip.pred)

		// Incorporate immediate predecessor into predecessor list
		iplev := ip.id.Level()
		for i := 0; i <= iplev; i++ {
			if i < len(pred) {
				pred[i] = ip.id
			} else {
				pred = append(pred, ip.id)
			}
		}

		// Initialize the new event appropriately
		e.seq = ip.seq + 1
	}
	e.pred = pred

	// Write the new event's header
	binary.Write(&e.data, binary.LittleEndian, e.seq)
	binary.Write(&e.data, binary.LittleEndian, e.pred)

	l.cur = e
	return e
}



// peer represents the information each node maintains about its peers
// (parent and children) in the tree.
type peer struct {
	pub abstract.Point		// peer's public key
}

type node struct {
	suite abstract.Suite
	pri abstract.Secret		// our private key
	pub abstract.Point		// our public key

	// peers[0] is our parent, the rest are our children.
	// peers[0] is nil if we're the root of the tree.
	peers []*peer
}

func newNode(suite abstract.Suite, rand cipher.Stream,
		parpub abstract.Point) *node {

	n := &node{}
	n.suite = suite
	n.pri = suite.Secret().Pick(rand)
	n.pub = suite.Point().Mul(nil, n.pri)

	parent := (*peer)(nil)
	if parpub != nil {
		parent = &peer{parpub}
	}
	n.peers = []*peer{parent}

	return n
}

func (n *node) addChild(childpub abstract.Point) {
	n.peers = append(n.peers, &peer{childpub})
}

func (n *node) downStep() {
}

func (n *node) upStep() {
}

