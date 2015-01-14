package coco

import (
	"errors"
	"fmt"
	"sync"
)

// Peer is an abstract peer which we can Put to and Get from.
type Peer interface {
	Name() string // to keep track of peers in hosts
	Put(data interface{})
	Get() interface{}
}

// A Host has the ability to send messages up the tree (parents),
// get from the parents, send messages to the children, and get messages from
// the children.
type Host interface {
	Name() string
	PutUp(interface{})
	GetUp() interface{}
	PutDown(interface{})
	GetDown() []interface{}
}

// host embodies the local state of a single host in the network
// it satisfies the tree node interface.
type HostNode struct {
	name     string
	parent   Peer
	children map[string]Peer // map so we only add unique peers
}

func NewHostNode(hostname string) *HostNode {
	h := &HostNode{name: hostname,
		children: make(map[string]Peer)}
	return h
}

func (h HostNode) AddParent(p Peer) {
	h.parent = p
}

func (h HostNode) AddChildren(ps ...Peer) {
	for _, p := range ps {
		h.children[p.Name()] = p
	}
}

func (h HostNode) Name() string {
	return h.name
}

// TODO(dyv): following methods will have to be rethought with network failures and
// latency in mind. What happens during GetDown if one node serves up old
// responses?
func (h HostNode) PutUp(data interface{}) {
	h.parent.Put(data)
}
func (h HostNode) GetUp() interface{} {
	return h.parent.Get()
}

func (h HostNode) PutDown(data interface{}) {
	for _, c := range h.children {
		c.Put(data)
	}
}
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
