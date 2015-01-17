package coco

import (
	"encoding/gob"
	"errors"
	"net"
	"sync"
)

// Conn is an abstract bidirectonal connection. It abstracts away the network
// layer as well as the data-format for communication.
type Conn interface {
	Name() string
	Put(data interface{}) // sends data through the connection
	Get() interface{}     // gets data from connection
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
	gc := &goConn{dir, from, to}
	gc.dir.Lock()
	fromto := from + to
	defer gc.dir.Unlock()
	if _, ok := gc.dir.channel[fromto]; ok {
		// return the already existant peer
		return gc.dir.nameToPeer[fromto], PeerExists
	}
	gc.dir.channel[fromto] = make(chan interface{})
	return gc, nil
}

// Name returns the from+to identifier of the goConn.
func (c goConn) Name() string {
	return c.to
}

// Put sends data to the goConn through the channel.
func (c *goConn) Put(data interface{}) {
	fromto := c.from + c.to
	c.dir.Lock()
	ch := c.dir.channel[fromto]
	// the directory must be unlocked before sending data. otherwise the
	// receiver would not be able to access this channel from the directory
	// either.
	c.dir.Unlock()
	ch <- data
}

// Get receives data from the sender.
func (c *goConn) Get() interface{} {
	// since the channel is owned by the sender, we flip around the ordering of
	// the fromto key to indicate that we want to receive from this instead of
	// send.
	tofrom := c.to + c.from
	c.dir.Lock()
	ch := c.dir.channel[tofrom]
	// as in Put directory must be unlocked to allow other goroutines to reach
	// their send lines.
	c.dir.Unlock()
	data := <-ch
	return data
}

// TcpConn is a prototype TCP connection with gob encoding.
type TcpConn struct {
	name string
	conn net.Conn
	enc  *gob.Encoder
	dec  *gob.Decoder
}

func NewTcpConn(hostname string) (*TcpConn, error) {
	tp := &TcpConn{}
	tp.name = hostname
	// establish the connection
	conn, err := net.Dial("tcp", hostname)
	if err != nil {
		return tp, err
	}
	tp.conn = conn
	tp.enc = gob.NewEncoder(conn)
	tp.dec = gob.NewDecoder(conn)
	return tp, nil
}

func (tc TcpConn) Name() string {
	return tc.name
}

func (tc *TcpConn) Put(data interface{}) {
	tc.enc.Encode(data)
}

func (tc *TcpConn) Get() interface{} {
	var data interface{}
	tc.dec.Decode(data)
	return data
}
