package coconet

import (
	"sync"
	"time"

	"github.com/dedis/crypto/abstract"
)

// Host is an abstract node on the Host tree. The Host has a Name and can send
// and receive data from its parent. It can also send and receive from its
// children. All gets are blocking. For this reason, when starting up a Host,
// one should set up handlers for GetUp and GetDown, so this node can always be
// listening for new requests.
//
// i.e.
// ...
// hn := NewHostNode(hostname)
// hn.AddParent(parent)
// hn.AddChildren(children...)
// // if requests can be initiated by parents
// go func() {
//    for {
//        req := hn.GetUp()
//        HandleParentRequests(req)
//    }
// }
// // if requests can be initiated by children
// go func() {
//    for {
//        req := hn.GetDown()
//        HandleChildRequests(req)
//    }
// }
//
type Host interface {
	Name() string

	// Returns the internal data structure
	// Invarient: children are always in the same order
	Peers() map[string]Conn // returns the peers list: all connected nodes
	Children(view int) map[string]Conn

	AddPeers(hostnames ...string) // add a node but don't make it child or parent
	NewView(view int, parent string, children []string)

	AddParent(view int, hostname string)      // ad a parent connection
	AddChildren(view int, hostname ...string) // add child connections
	NChildren(view int) int

	IsRoot(view int) bool                // true if this host is the root of the tree
	IsParent(view int, peer string) bool // true if this peer is the parent
	IsChild(view int, peer string) bool  // true if this peer is a child

	// blocking network calls over the tree
	PutUp(view int, data BinaryMarshaler) error     // send data to parent in host tree
	PutDown(view int, data []BinaryMarshaler) error // send data to children in host tree

	Get() (chan NetworkMessg, chan error)
	// ??? Could be replaced by listeners (condition variables) that wait for a
	// change to the root status to the node (i.e. through an add parent call)
	WaitTick() // Sleeps for network implementation dependent amount of time

	Connect(view int) error // connects to parent
	Listen() error          // listen for incoming connections

	Close() // connections need to be cleaned up

	SetTimeout(time.Duration)
	Timeout() time.Duration
	DefaultTimeout() time.Duration

	PubKey() abstract.Point
	SetPubKey(abstract.Point)

	Pool() sync.Pool
	SetPool(sync.Pool)
}
