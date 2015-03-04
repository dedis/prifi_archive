package coconet

// TCPHost is a simple implementation of Host that does not specify the
import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/nist"
	"github.com/dedis/prifi/coco"
)

// Default timeout for any network operation
const DefaultTCPTimeout time.Duration = 5 * time.Second

// communication medium (goroutines/channels, network nodes/tcp, ...).
type TCPHost struct {
	name   string // the hostname
	parent string // the Peer representing parent, nil if root

	childLock sync.Mutex
	children  []string // a list of unique peers for each hostname

	rlock sync.Mutex
	ready map[string]bool
	peers map[string]Conn

	mutimeout sync.Mutex
	timeout   time.Duration // general timeout for any network operation

	mupk   sync.RWMutex
	Pubkey abstract.Point // own public key

	pool sync.Pool
}

func (h *TCPHost) DefaultTimeout() time.Duration {
	return DefaultTCPTimeout
}

func (h *TCPHost) SetTimeout(t time.Duration) {
	h.mutimeout.Lock()
	h.timeout = t
	h.mutimeout.Unlock()
}

func (h *TCPHost) Timeout() time.Duration {
	var t time.Duration
	h.mutimeout.Lock()
	t = h.timeout
	h.mutimeout.Unlock()
	return t
}

// NewTCPHost creates a new TCPHost with a given hostname.
func NewTCPHost(hostname string) *TCPHost {
	h := &TCPHost{name: hostname,
		children: make([]string, 0),
		peers:    make(map[string]Conn),
		timeout:  DefaultTCPTimeout,
		ready:    make(map[string]bool)}

	return h
}

func (h *TCPHost) PubKey() abstract.Point {
	h.mupk.RLock()
	pk := h.Pubkey
	h.mupk.RUnlock()
	return pk
}

func (h *TCPHost) SetPubKey(pk abstract.Point) {
	h.mupk.Lock()
	h.Pubkey = pk
	h.mupk.Unlock()
}

type Smarsh string

func (s *Smarsh) MarshalBinary() ([]byte, error) {
	return []byte(*s), nil
}

func (s *Smarsh) UnmarshalBinary(b []byte) error {
	*s = Smarsh(b)
	return nil
}

func (h *TCPHost) Listen() error {
	var err error
	ln, err := net.Listen("tcp4", h.name)
	if err != nil {
		log.Println("failed to listen:", err)
		return err
	}

	go func() {

		for {
			conn, err := ln.Accept()
			if err != nil {
				// handle error
				log.Errorln("failed to accept connection: ", err)
				continue
			}
			if conn == nil {
				log.Errorln("!!!nil connection!!!")
				continue
			}
			// Read in name of client
			tp := NewTCPConnFromNet(conn)
			var mname Smarsh
			err = tp.Get(&mname)
			if err != nil {
				log.Errorln("ERROR ERROR ERROR: TCP HOST FAILED:", err)
				tp.Close()
				continue
			}
			name := string(mname)
			// log.Infoln("successfully received name:", name)

			// create connection
			tp.SetName(name)

			// get and set public key
			suite := nist.NewAES128SHA256P256()
			pubkey := suite.Point()
			err = tp.Get(pubkey)
			if err != nil {
				log.Errorln("unable to get pubkey from child")
				tp.Close()
				continue
			}
			tp.SetPubKey(pubkey)

			// accept children connections but no one else
			found := false
			h.childLock.Lock()
			for _, c := range h.children {
				if c == name {
					found = true
					break
				}
			}
			h.childLock.Unlock()
			if !found {
				log.Errorln("connection request not from child:", name)
				tp.Close()
				continue
			}

			h.rlock.Lock()
			h.ready[name] = true
			h.peers[name] = tp
			if coco.DEBUG {
				log.Infoln("CONNECTED TO CHILD:", tp, tp.conn)
			}
			h.rlock.Unlock()
		}
	}()
	return nil
}

func (h *TCPHost) Connect() error {
	if h.parent == "" {
		return nil
	}
	conn, err := net.Dial("tcp", h.parent)
	if err != nil {
		if coco.DEBUG {
			log.Warnln("tcphost: failed to connect to parent:", err)
		}
		return err
	}
	tp := NewTCPConnFromNet(conn)

	mname := Smarsh(h.Name())
	err = tp.Put(&mname)
	if err != nil {
		log.Errorln(err)
		return err
	}
	tp.SetName(h.parent)

	err = tp.Put(h.Pubkey)
	if err != nil {
		log.Errorln("failed to enc p key")
		return errors.New("failed to encode public key")
	}
	// log.Println("CONNECTING TO PARENT")

	h.rlock.Lock()
	h.ready[tp.Name()] = true
	h.peers[h.parent] = tp
	h.rlock.Unlock()
	if coco.DEBUG {
		log.Infoln("CONNECTED TO PARENT:", h.parent)
	}
	return nil
}

func (h *TCPHost) Close() {
	h.rlock.Lock()
	for k, p := range h.peers {
		if p != nil {
			p.Close()
		}
		h.peers[k] = nil
	}
	h.rlock.Unlock()
}

// AddParent adds a parent node to the TCPHost.
func (h *TCPHost) AddParent(c string) {
	if _, ok := h.peers[c]; !ok {
		h.peers[c] = NewTCPConn(c)
	}
	h.parent = c
}

// AddChildren variadically adds multiple Peers as children to the TCPHost.
// Only unique children will be stored.
func (h *TCPHost) AddChildren(cs ...string) {
	for _, c := range cs {
		h.rlock.Lock()
		// add a field in peers for this child
		if _, ok := h.peers[c]; !ok {
			h.peers[c] = nil
		} else {
			// skip children that we have already added
			h.rlock.Unlock()
			continue
		}
		h.rlock.Unlock()
		h.childLock.Lock()
		h.children = append(h.children, c)
		// h.childrenMap[c] = h.peers[c]
		h.childLock.Unlock()
	}
}

func (h *TCPHost) NChildren() int {
	h.childLock.Lock()
	l := len(h.children)
	h.childLock.Unlock()
	return l
}

// Name returns the hostname of the TCPHost.
func (h *TCPHost) Name() string {
	return h.name
}

// IsRoot returns true if the TCPHost is the root of it's tree (if it has no
// parent).
func (h *TCPHost) IsRoot() bool {
	return h.parent == ""
}

// Peers returns the list of peers as a mapping from hostname to Conn
func (h *TCPHost) Peers() map[string]Conn {
	return h.peers
}

func (h *TCPHost) Children() map[string]Conn {
	h.childLock.Lock()
	h.rlock.Lock()

	childrenMap := make(map[string]Conn, 0)
	for _, c := range h.children {
		if !h.ready[c] {
			continue
		}
		childrenMap[c] = h.peers[c]
	}
	h.rlock.Unlock()
	h.childLock.Unlock()

	return childrenMap
}

// AddPeers adds the list of peers
func (h *TCPHost) AddPeers(cs ...string) {
	// XXX does it make sense to add peers that are not children or parents
	for _, c := range cs {
		h.peers[c] = NewTCPConn(c)
	}
}

// WaitTick waits for a random amount of time.
// XXX should it wait for a network configuration change
func (h *TCPHost) WaitTick() {
	time.Sleep(1 * time.Second)
}

var ErrorConnClosed error = errors.New("connection closed")

// PutUp sends a message (an interface{} value) up to the parent through
// whatever 'network' interface the parent Peer implements.
func (h *TCPHost) PutUp(data BinaryMarshaler) error {
	h.rlock.Lock()
	isReady := h.ready[h.parent]
	parent := h.peers[h.parent]
	h.rlock.Unlock()
	if !isReady {
		return ConnectionNotEstablished
	} else if parent == nil && h.parent != "" {
		// not the root and I have closed my parent connection
		return ErrorConnClosed
	}
	//log.Println("Putting Up:")
	return parent.Put(data)
}

// GetUp gets a message (an interface{} value) from the parent through
// whatever 'network' interface the parent Peer implements.
func (h *TCPHost) GetUp(data BinaryUnmarshaler) error {
	h.rlock.Lock()
	isReady := h.ready[h.parent]
	parent := h.peers[h.parent]
	h.rlock.Unlock()
	if !isReady {
		return ConnectionNotEstablished
	} else if parent == nil && h.parent != "" {
		// not the root and I have closed my parent connection
		return ErrorConnClosed
	}
	return parent.Get(data)
}

var ErrorChildNotReady error = errors.New("child is not ready")

// PutDown sends a message (an interface{} value) up to all children through
// whatever 'network' interface each child Peer implements.
func (h *TCPHost) PutDown(data []BinaryMarshaler) error {
	if len(data) != len(h.children) {
		panic("number of messages passed down != number of children")
	}
	// Try to send the message to all children
	// If at least on of the attempts fails, return a non-nil error
	var err error
	h.childLock.Lock()
	children := make([]string, len(h.children))
	copy(children, h.children)
	h.childLock.Unlock()
	for i, c := range children {
		h.rlock.Lock()
		if !h.ready[c] {
			err = ErrorChildNotReady
			h.rlock.Unlock()
			continue
		}
		conn := h.peers[c]
		h.rlock.Unlock()
		if e := conn.Put(data[i]); e != nil {
			err = e
		}
	}
	return err
}

func (h *TCPHost) whenReadyGet(name string, data BinaryUnmarshaler) error {
	var c Conn
	for {
		h.rlock.Lock()
		isReady := h.ready[name]
		c = h.peers[name]
		h.rlock.Unlock()

		if isReady {
			break
		}
		// XXX see if we should change Sleep with sth else
		time.Sleep(100 * time.Millisecond)
	}

	if c == nil {
		return ErrorConnClosed
	}

	return c.Get(data)
}

// GetDown gets a message (an interface{} value) from all children through
// whatever 'network' interface each child Peer implements.
// Must be called after network topology is completely set: ie
// all children must have already been added.
func (h *TCPHost) GetDown() (chan NetworkMessg, chan error) {
	ch := make(chan NetworkMessg, 1)
	errch := make(chan error, 1)

	// copy children before ranging for thread safety
	h.childLock.Lock()
	children := make([]string, len(h.children))
	copy(children, h.children)
	h.childLock.Unlock()

	// start children threads
	go func() {
		for i, c := range children {
			go func(i int, c string) {

				for {

					data := h.pool.Get().(BinaryUnmarshaler)
					e := h.whenReadyGet(c, data)
					// check to see if the connection is Closed
					if e == ErrorConnClosed {
						errch <- errors.New("connection has been closed")
						return
					} else if e == io.EOF {
						os.Exit(1)
					}

					ch <- NetworkMessg{Data: data, From: c}
					errch <- e

				}
			}(i, c)
		}
	}()

	return ch, errch
}

func (h *TCPHost) Pool() sync.Pool {
	return h.pool
}

func (h *TCPHost) SetPool(p sync.Pool) {
	h.pool = p
}
