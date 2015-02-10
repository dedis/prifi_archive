package coconet

import (
	"encoding/gob"
	"errors"
	"log"
	"net"
	"sync"
	"time"
)

// Conn is an abstract bidirectonal connection. It abstracts away the network
// layer as well as the data-format for communication.
type Conn interface {
	Name() string // the "to" of the connection

	Connect() error // connect with the "to"
	Close()         // clean up the connection

	Put(BinaryMarshaler) error   // sends data through the connection
	Get(BinaryUnmarshaler) error // gets data from connection
}

/* Alternative Bytes Based Conn
type Conn interface {
	Name() string
	Put([]data) error     // sends data through the connection
	Get([]data) error     // gets data from connection
	Get() ([]data, error) // -> extra allocation for every recieve
}*/

// Taken from: http://golang.org/pkg/encoding/#BinaryMarshaler
// All messages passing through our conn must implement their own  BinaryMarshaler
type BinaryMarshaler interface {
	MarshalBinary() (data []byte, err error)
}

// Taken from: http://golang.org/pkg/encoding/#BinaryMarshaler
// All messages passing through our conn must implement their own BinaryUnmarshaler
type BinaryUnmarshaler interface {
	UnmarshalBinary(data []byte) error
}

// directory is a testing structure for the goConn. It allows us to simulate
// tcp network connections locally (and is easily adaptable for network
// connections). A single directory should be shared between all goConns's that
// are operating in the same network 'space'. If they are on the same tree they
// should share a directory.
type GoDirectory struct {
	sync.Mutex                        // protects accesses to channel and nameToPeer
	channel    map[string]chan []byte // one channel per peer-to-peer connection
	nameToPeer map[string]*GoConn     // keeps track of duplicate connections
}

/// newDirectory creates a new directory for registering goPeers.
func NewGoDirectory() *GoDirectory {
	return &GoDirectory{channel: make(map[string]chan []byte),
		nameToPeer: make(map[string]*GoConn)}
}

// goConn is a Conn type for representing connections in an in-memory tree. It
// uses channels for communication.
type GoConn struct {
	// the directory maps each (from,to) pair to a channel for sending
	// (from,to). When receiving one reads from the channel (from, to). Thus
	// the sender "owns" the channel.
	dir    *GoDirectory
	from   string
	to     string
	fromto string
	tofrom string
}

// PeerExists is an ignorable error that says that this peer has already been
// registered to this directory.
var PeerExists error = errors.New("peer already exists in given directory")

// NewGoPeer creates a goPeer registered in the given directory with the given
// hostname. It returns an ignorable PeerExists error if this peer already
// exists.
func NewGoConn(dir *GoDirectory, from, to string) (*GoConn, error) {
	gc := &GoConn{dir, from, to, from + "::::" + to, to + "::::" + from}
	dir.Lock()
	fromto := gc.FromTo()
	defer dir.Unlock()
	if c, ok := dir.nameToPeer[fromto]; ok {
		// return the already existant peer\
		return c, PeerExists
	}
	dir.nameToPeer[fromto] = gc
	dir.channel[fromto] = make(chan []byte)
	return gc, nil
}

// Name returns the from+to identifier of the goConn.
func (c GoConn) Name() string {
	return c.to
}

func (c GoConn) FromTo() string {
	return c.fromto
}

func (c GoConn) ToFrom() string {
	return c.tofrom
}

func (c GoConn) Connect() error {
	return nil
}

func (c GoConn) Close() {}

// Put sends data to the goConn through the channel.
func (c *GoConn) Put(data BinaryMarshaler) error {
	fromto := c.FromTo()
	c.dir.Lock()
	ch := c.dir.channel[fromto]
	// the directory must be unlocked before sending data. otherwise the
	// receiver would not be able to access this channel from the directory
	// either.
	c.dir.Unlock()
	b, err := data.MarshalBinary()
	if err != nil {
		return err
	}
	log.Printf("Sending data: %#v\n", data)
	ch <- b
	return nil
}

// Get receives data from the sender.
func (c *GoConn) Get(bum BinaryUnmarshaler) error {
	// since the channel is owned by the sender, we flip around the ordering of
	// the fromto key to indicate that we want to receive from this instead of
	// send.
	tofrom := c.ToFrom()
	c.dir.Lock()
	ch := c.dir.channel[tofrom]
	// as in Put directory must be unlocked to allow other goroutines to reach
	// their send lines.
	c.dir.Unlock()

	data := <-ch
	log.Println("DATA:", data)
	err := bum.UnmarshalBinary(data)
	if err != nil {
		log.Println("ERROR UNMARSHALING:", err)
	}
	return err
}

// TcpConn is a prototype TCP connection with gob encoding.
type TCPConn struct {
	sync.RWMutex

	name string
	conn net.Conn
	enc  *gob.Encoder
	dec  *gob.Decoder
}

func NewTCPConnFromNet(conn net.Conn) *TCPConn {
	return &TCPConn{
		name: conn.RemoteAddr().String(),
		conn: conn,
		enc:  gob.NewEncoder(conn),
		dec:  gob.NewDecoder(conn)}

}

func NewTCPConn(hostname string) *TCPConn {
	tp := &TCPConn{}
	tp.name = hostname
	return tp
}

func (tc TCPConn) Connect() error {
	log.Println("tcpconn establishing new connection")
	// establish the connection
	conn, err := net.Dial("tcp", tc.name)
	if err != nil {
		log.Println("connection failed")
		return err
	}
	tc.conn = conn
	// gob encoders call MarshalBinary and UnmarshalBinary
	// TODO replace gob with minimal Put, Get interface
	// gob nicely handles reading from the connection
	// otherwise we would have to deal with making the tcp
	// read and write blocking rather than non-blocking.
	tc.enc = gob.NewEncoder(conn)
	tc.dec = gob.NewDecoder(conn)
	return nil
}

func (tc TCPConn) Name() string {
	return tc.name
}

// blocks until the put is availible
func (tc *TCPConn) Put(bm BinaryMarshaler) error {
	tc.RLock()
	for tc.enc == nil {
		tc.RUnlock()
		time.Sleep(time.Second)
		tc.RLock()
		//return errors.New(" connection not established")
	}
	tc.RUnlock()
	return tc.enc.Encode(bm)
}

func (tc *TCPConn) Get(bum BinaryUnmarshaler) error {
	for tc.dec == nil {
		time.Sleep(time.Second)
		//return errors.New(" connection not established")
	}
	return tc.dec.Decode(bum)
}

func (tc *TCPConn) Close() {
	if tc.conn != nil {
		tc.conn.Close()
	}
}
