package coco

import (
	"encoding/gob"
	"errors"
	"net"
	"sync"
)

// Conn is an abstract bidirectonal connection.
type Conn interface {
	Name() string
	Put(data interface{}) // sends data through the connection
	Get() interface{}     // gets data from connection
}

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
	IsRoot() bool           // true if this host is the root of the tree
	PutUp(interface{})      // send data to parent in host tree
	GetUp() interface{}     // get data from parent in host tree (blocking)
	PutDown(interface{})    // send data to children in host tree
	GetDown() []interface{} // get data from children in host tree (blocking)
}

// HostNode is a simple implementation of Host that does not specify the
// communication medium (goroutines/channels, network nodes/tcp, ...).
type HostNode struct {
	name     string          // the hostname
	parent   Conn            // the Peer representing parent, nil if root
	children map[string]Conn // a list of unique peers for each hostname
}

// NewHostNode creates a new HostNode with a given hostname.
func NewHostNode(hostname string) *HostNode {
	h := &HostNode{name: hostname,
		children: make(map[string]Conn)}
	return h
}

// AddParent adds a parent node to the HostNode.
func (h HostNode) AddParent(c Conn) {
	h.parent = c
}

// AddChildren variadically adds multiple Peers as children to the HostNode.
// Only unique children will be stored.
func (h HostNode) AddChildren(cs ...Conn) {
	for _, c := range cs {
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

// TODO(dyv): following methods will have to be rethought with network failures and
// latency in mind. What happens during GetDown if one node serves up old
// responses after a certain timeout?

// PutUp sends a message (an interface{} value) up to the parent through
// whatever 'network' interface the parent Peer implements.
func (h HostNode) PutUp(data interface{}) {
	h.parent.Put(data)
}

// GetUp gets a message (an interface{} value) from the parent through
// whatever 'network' interface the parent Peer implements.
func (h HostNode) GetUp() interface{} {
	return h.parent.Get()
}

// PutDown sends a message (an interface{} value) up to all children through
// whatever 'network' interface each child Peer implements.
func (h HostNode) PutDown(data interface{}) {
	for _, c := range h.children {
		c.Put(data)
	}
}

// GetDown gets a message (an interface{} value) from all children through
// whatever 'network' interface each child Peer implements.
func (h HostNode) GetDown() []interface{} {
	var mu sync.Mutex
	data := make([]interface{}, len(h.children))
	var wg sync.WaitGroup
	for _, c := range h.children {
		wg.Add(1)
		go func(c Conn) {
			d := c.Get()
			mu.Lock()
			data = append(data, d)
			mu.Unlock()
		}(c)
	}
	wg.Wait()
	return data
}

// directory is a testing structure for the goConn. It allows us to simulate
// tcp network connections locally (and is easily adaptable for network
// connections). A single directory should be shared between all goConns's that
// are operating in the same network 'space'. If they are on the same tree they
// should share a directory.
type directory struct {
	sync.Mutex                             // protects accesses to channel and nameToPeer
	channel    map[string]chan interface{} // one channel per peer-to-peer connection
	nameToPeer map[string]*goConn          // keeps track of duplicate connections
}

/// newDirectory creates a new directory for registering goPeers.
func newDirectory() *directory {
	return &directory{channel: make(map[string]chan interface{}),
		nameToPeer: make(map[string]*goConn)}
}

// goConn is a Conn type for representing connections in an in-memory tree. It
// uses channels for communication.
type goConn struct {
	// the directory maps each (from,to) pair to a channel for sending
	// (from,to). When receiving one reads from the channel (from, to). Thus
	// the sender "owns" the channel.
	dir  *directory
	from string
	to   string
}

// PeerExists is an ignorable error that says that this peer has already been
// registered to this directory.
var PeerExists error = errors.New("peer already exists in given directory")

// NewGoPeer creates a goPeer registered in the given directory with the given
// hostname. It returns an ignorable PeerExists error if this peer already
// exists.
func NewGoConn(dir *directory, from, to string) (*goConn, error) {
	gp := &goConn{dir, from, to}
	gp.dir.Lock()
	fromto := from + to
	defer gp.dir.Unlock()
	if _, ok := gp.dir.channel[fromto]; ok {
		// return the already existant peer
		return gp.dir.nameToPeer[fromto], PeerExists
	}
	gp.dir.channel[fromto] = make(chan interface{})
	return gp, nil
}

// Name returns the from+to identifier of the goConn.
func (p goConn) Name() string {
	return p.from + p.to
}

// Put sends data to the goConn through the channel.
func (p goConn) Put(data interface{}) {
	fromto := p.from + p.to
	p.dir.Lock()
	ch := p.dir.channel[fromto]
	// the directory must be unlocked before sending data. otherwise the
	// receiver would not be able to access this channel from the directory
	// either.
	p.dir.Unlock()
	ch <- data
}

// Get receives data from the sender.
func (p goConn) Get() interface{} {
	// since the channel is owned by the sender, we flip around the ordering of
	// the fromto key to indicate that we want to receive from this instead of
	// send.
	tofrom := p.to + p.from
	p.dir.Lock()
	ch := p.dir.channel[tofrom]
	// as in Put directory must be unlocked to allow other goroutines to reach
	// their send lines.
	p.dir.Unlock()
	data := <-ch
	return data
}

type TcpPeer struct {
	name string
	conn net.Conn
	enc  *gob.Encoder
	dec  *gob.Decoder
}

func NewTcpPeer(hostname string) (*TcpPeer, error) {
	tp := &TcpPeer{}
	tp.name = hostname
	// connect to this peer
	conn, err := net.Dial("tcp", hostname)
	if err != nil {
		return tp, err
	}
	tp.conn = conn
	tp.enc = gob.NewEncoder(conn)
	tp.dec = gob.NewDecoder(conn)
	return tp, nil
}

func (tp TcpPeer) Name() string {
	return tp.name
}

func (tp TcpPeer) Put(data interface{}) {
	tp.enc.Encode(data)
}

func (tp TcpPeer) Get() interface{} {
	var data interface{}
	tp.dec.Decode(data)
	return data
}
