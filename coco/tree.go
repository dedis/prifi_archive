package coco

import (
	"crypto/cipher"
	"fmt"
	"sync"

	"github.com/dedis/crypto/abstract"
)

// Peer is an abstract peer which we can Put to and Get from.
type Peer interface {
	Put(data interface{})
	Get() interface{}
}

// A TreeNode has the ability to send messages up the tree (parents),
// get from the parents, send messages to the children, and get messages from
// the children.
type TreeNode interface {
	PutUp(interface{})
	GetUp() interface{}
	PutDown(interface{})
	GetDown() []interface{}
}

// host embodies the local state of a single host in the network
// it satisfies the tree node interface.
type Host struct {
	hostname string
	prikey   abstract.Secret
	pubkey   abstract.Point
	parent   Peer
	children []Peer
}

func NewHost(suite abstract.Suite, rand cipher.Stream, hostname string) *Host {
	h := &Host{hostname: hostname,
		prikey:   suite.Secret().Pick(rand),
		children: make([]Peer, 0)}
	h.pubkey = suite.Point().Mul(nil, h.prikey)
	return h
}

func (h Host) AddParent(p Peer) {
	h.parent = p
}

// TODO: only add new children
func (h Host) AddChildren(ps ...Peer) {
	h.children = append(h.children, ps...)
}

func (h Host) PutUp(data interface{}) {
	h.parent.Put(data)
}
func (h Host) GetUp() interface{} {
	return h.parent.Get()
}

func (h Host) PutDown(data interface{}) {
	for _, c := range h.children {
		c.Put(data)
	}
}
func (h Host) GetDown() []interface{} {
	data := make([]interface{}, len(h.children))
	var wg sync.WaitGroup
	for i, c := range h.children {
		wg.Add(1)
		go func(i int) {
			data[i] = c.Get()
		}(i)
	}
	wg.Wait()
	return data
}

// goRouter is a testing structure for the GoPeer. It allows us to simulate
// tcp network connections locally (and is easily adaptable for network
// connections).
type goRouter struct {
	sync.Mutex
	channel map[string]chan interface{}
}

func newGoRouter() *goRouter {
	return &goRouter{channel: make(map[string]chan interface{})}
}

type GoPeer struct {
	router   *goRouter
	pubkey   abstract.Point
	hostname string
}

func NewGoPeer(pubkey abstract.Point, hostname string) *GoPeer {
	gp := &GoPeer{newGoRouter(), pubkey, hostname}
	gp.router.Lock()

	defer gp.router.Unlock()
	if _, ok := gp.router.channel[hostname]; ok {
		// return the already existant peer
		fmt.Println("Peer Already Exists")
		return nil
	}
	gp.router.channel[hostname] = make(chan interface{})
	return gp
}

func (p GoPeer) Put(data interface{}) {
	p.router.Lock()
	defer p.router.Unlock()
	if _, ok := p.router.channel[p.hostname]; !ok {
		p.router.channel[p.hostname] = make(chan interface{})
	}
	ch := p.router.channel[p.hostname]
	ch <- data
}

func (p GoPeer) Get() interface{} {
	p.router.Lock()
	defer p.router.Unlock()
	if _, ok := p.router.channel[p.hostname]; !ok {
		p.router.channel[p.hostname] = make(chan interface{})
	}
	ch := p.router.channel[p.hostname]
	data := <-ch
	return data
}
