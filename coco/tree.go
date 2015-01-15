package coco

import (
	"encoding/gob"
	"errors"
	"fmt"
	"net"
	"sync"
)

// Peer is an abstract peer (network node) which is named, and we can send data
// to and get data from.
type Peer interface {
	Name() string         // the hostname of the peer
	Put(data interface{}) // sends data to the peer
	Get() interface{}     // gets data from the peer (blocking)
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
	parent   Peer            // the Peer representing parent, nil if root
	children map[string]Peer // a list of unique peers for each hostname
}

// NewHostNode creates a new HostNode with a given hostname.
func NewHostNode(hostname string) *HostNode {
	h := &HostNode{name: hostname,
		children: make(map[string]Peer)}
	return h
}

// AddParent adds a parent node to the HostNode.
func (h HostNode) AddParent(p Peer) {
	h.parent = p
}

// AddChildren variadically adds multiple Peers as children to the HostNode.
// Only unique children will be stored.
func (h HostNode) AddChildren(ps ...Peer) {
	for _, p := range ps {
		h.children[p.Name()] = p
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
		go func(c Peer) {
			d := c.Get()
			mu.Lock()
			data = append(data, d)
			mu.Unlock()
		}(c)
	}
	wg.Wait()
	return data
}

// directory is a testing structure for the GoPeer. It allows us to simulate
// tcp network connections locally (and is easily adaptable for network
// connections).
type directory struct {
	sync.Mutex
	channel    map[string]chan interface{}
	nameToPeer map[string]*goPeer
}

func newDirectory() *directory {
	return &directory{channel: make(map[string]chan interface{}),
		nameToPeer: make(map[string]*goPeer)}
}

type goPeer struct {
	dir      *directory
	hostname string
}

var PeerExists error = errors.New("peer already exists in given directory")

func NewGoPeer(dir *directory, hostname string) (*goPeer, error) {
	gp := &goPeer{dir, hostname}
	gp.dir.Lock()

	defer gp.dir.Unlock()
	if _, ok := gp.dir.channel[hostname]; ok {
		// return the already existant peer
		fmt.Println("Peer Already Exists")
		return gp.dir.nameToPeer[hostname], PeerExists
	}
	gp.dir.channel[hostname] = make(chan interface{})
	return gp, nil
}

func (p goPeer) Name() string {
	return p.hostname
}

func (p goPeer) Put(data interface{}) {
	p.dir.Lock()
	if _, ok := p.dir.channel[p.hostname]; !ok {
		p.dir.channel[p.hostname] = make(chan interface{})
	}
	ch := p.dir.channel[p.hostname]
	p.dir.Unlock()
	ch <- data
}

func (p goPeer) Get() interface{} {
	p.dir.Lock()
	defer p.dir.Unlock()
	if _, ok := p.dir.channel[p.hostname]; !ok {
		p.dir.channel[p.hostname] = make(chan interface{})
	}
	ch := p.dir.channel[p.hostname]
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
