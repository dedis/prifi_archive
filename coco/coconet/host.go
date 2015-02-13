package coconet

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
	Children() []Conn

	AddPeers(hostnames ...string)   // add a node but don't make it child or parent
	AddParent(hostname string)      // ad a parent connection
	AddChildren(hostname ...string) // add child connections
	NChildren() int

	IsRoot() bool // true if this host is the root of the tree

	// blocking network calls over the tree
	PutUp(BinaryMarshaler) error       // send data to parent in host tree
	GetUp(BinaryUnmarshaler) error     // get data from parent in host tree (blocking)
	PutDown([]BinaryMarshaler) error   // send data to children in host tree
	GetDown([]BinaryUnmarshaler) error // get data from children in host tree (blocking)

	// ??? Could be replaced by listeners (condition variables) that wait for a
	// change to the root status to the node (i.e. through an add parent call)
	WaitTick() // Sleeps for network implementation dependent amount of time

	Connect() error // connects to parent
	Listen() error  // listen for incoming connections

	Close() // connections need to be cleaned up

}
