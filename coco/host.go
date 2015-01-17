package coco

import (
	"sync"
	"time"
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

	Peers() map[string]Conn // returns the peers list: all connected nodes
	AddPeers(cs ...Conn)    // add a node but don't make it child or parent
	AddParent(cs Conn)      // ad a parent connection
	AddChildren(cs ...Conn) // add child connections

	IsRoot() bool // true if this host is the root of the tree

	PutUp(interface{})      // send data to parent in host tree
	GetUp() interface{}     // get data from parent in host tree (blocking)
	PutDown(interface{})    // send data to children in host tree
	GetDown() []interface{} // get data from children in host tree (blocking)

	WaitTick() // Sleeps for network implementation dependent amount of time
}

// HostNode is a simple implementation of Host that does not specify the
// communication medium (goroutines/channels, network nodes/tcp, ...).
type HostNode struct {
	name     string          // the hostname
	parent   Conn            // the Peer representing parent, nil if root
	children map[string]Conn // a list of unique peers for each hostname
	peers    map[string]Conn
}

// NewHostNode creates a new HostNode with a given hostname.
func NewHostNode(hostname string) *HostNode {
	h := &HostNode{name: hostname,
		children: make(map[string]Conn),
		peers:    make(map[string]Conn)}
	return h
}

// AddParent adds a parent node to the HostNode.
func (h *HostNode) AddParent(c Conn) {
	if _, ok := h.peers[c.Name()]; !ok {
		h.peers[c.Name()] = c
	}
	h.parent = c
}

// AddChildren variadically adds multiple Peers as children to the HostNode.
// Only unique children will be stored.
func (h *HostNode) AddChildren(cs ...Conn) {
	for _, c := range cs {
		if _, ok := h.peers[c.Name()]; !ok {
			h.peers[c.Name()] = c
		}
		h.children[c.Name()] = c
	}
}

// Name returns the hostname of the HostNode.
func (h HostNode) Name() string {
	return h.name
}

// IsRoot returns true if the HostNode is the root of it's tree (if it has no
// parent).
func (h HostNode) IsRoot() bool {
	return h.parent == nil
}

// Peers returns the list of peers as a mapping from hostname to Conn
func (h HostNode) Peers() map[string]Conn {
	return h.peers
}

// AddPeers adds the list of peers
func (h HostNode) AddPeers(cs ...Conn) {
	for _, c := range cs {
		if _, ok := h.peers[c.Name()]; !ok {
			h.peers[c.Name()] = c
		}
	}
}

// WaitTick waits for a random amount of time.
// XXX should it wait for a network change
func (h HostNode) WaitTick() {
	time.Sleep(1 * time.Second)
}

// TODO(dyv): following methods will have to be rethought with network failures and
// latency in mind. What happens during GetDown if one node serves up old
// responses after a certain timeout?

// PutUp sends a message (an interface{} value) up to the parent through
// whatever 'network' interface the parent Peer implements.
func (h *HostNode) PutUp(data interface{}) {
	h.parent.Put(data)
}

// GetUp gets a message (an interface{} value) from the parent through
// whatever 'network' interface the parent Peer implements.
func (h *HostNode) GetUp() interface{} {
	return h.parent.Get()
}

// PutDown sends a message (an interface{} value) up to all children through
// whatever 'network' interface each child Peer implements.
func (h *HostNode) PutDown(data interface{}) {
	for _, c := range h.children {
		c.Put(data)
	}
}

// GetDown gets a message (an interface{} value) from all children through
// whatever 'network' interface each child Peer implements.
func (h *HostNode) GetDown() []interface{} {
	var mu sync.Mutex
	data := make([]interface{}, 0)
	var wg sync.WaitGroup
	for _, c := range h.children {
		wg.Add(1)
		go func(c Conn) {
			defer wg.Done()
			d := c.Get()
			mu.Lock()
			data = append(data, d)
			mu.Unlock()
		}(c)
	}
	wg.Wait()
	return data
}
