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

var _ Host = &TCPHost{}

// communication medium (goroutines/channels, network nodes/tcp, ...).
type TCPHost struct {
	name string // the hostname

	views *Views

	rlock sync.RWMutex
	ready map[string]bool
	peers map[string]Conn

	mutimeout sync.Mutex
	timeout   time.Duration // general timeout for any network operation

	mupk   sync.RWMutex
	Pubkey abstract.Point // own public key

	pool sync.Pool

	// channels to send on Get() and update
	msglock sync.Mutex
	msgchan chan NetworkMessg
	errchan chan error
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
		views:   NewViews(),
		peers:   make(map[string]Conn),
		timeout: DefaultTCPTimeout,
		ready:   make(map[string]bool),
		msglock: sync.Mutex{},
		msgchan: make(chan NetworkMessg, 1),
		errchan: make(chan error, 1)}

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

func (h *TCPHost) Connect(view int) error {
	parent := h.views.Parent(view)
	if parent == "" {
		return nil
	}

	// if we have already set up this connection don't do anything
	h.rlock.Lock()
	if h.ready[parent] {
		h.rlock.Unlock()
		return nil
	}
	h.rlock.Unlock()
	conn, err := net.Dial("tcp", parent)
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
	tp.SetName(parent)

	err = tp.Put(h.Pubkey)
	if err != nil {
		log.Errorln("failed to enc p key")
		return errors.New("failed to encode public key")
	}
	// log.Println("CONNECTING TO PARENT")

	h.rlock.Lock()
	h.ready[tp.Name()] = true
	h.peers[parent] = tp
	h.rlock.Unlock()
	if coco.DEBUG {
		log.Infoln("CONNECTED TO PARENT:", parent)
	}
	return nil
}

func (h *TCPHost) NewView(view int, parent string, children []string) {
	h.views.NewView(view, parent, children)
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
func (h *TCPHost) AddParent(view int, c string) {
	if _, ok := h.peers[c]; !ok {
		h.peers[c] = NewTCPConn(c)
	}
	h.views.AddParent(view, c)
}

// AddChildren variadically adds multiple Peers as children to the TCPHost.
// Only unique children will be stored.
func (h *TCPHost) AddChildren(view int, cs ...string) {
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
		h.views.AddChildren(view, c)
	}
}

func (h *TCPHost) NChildren(view int) int {
	return h.views.NChildren(view)
}

// Name returns the hostname of the TCPHost.
func (h *TCPHost) Name() string {
	return h.name
}

// IsRoot returns true if the TCPHost is the root of it's tree (if it has no
// parent).
func (h *TCPHost) IsRoot(view int) bool {
	return h.views.Parent(view) == ""
}

func (h *TCPHost) IsParent(view int, peer string) bool {
	return h.views.Parent(view) == peer
}

func (h *TCPHost) IsChild(view int, peer string) bool {
	h.rlock.Lock()
	_, ok := h.peers[peer]
	h.rlock.Unlock()
	return h.views.Parent(view) != peer && ok
}

// Peers returns the list of peers as a mapping from hostname to Conn
func (h *TCPHost) Peers() map[string]Conn {
	return h.peers
}

func (h *TCPHost) Children(view int) map[string]Conn {
	h.rlock.RLock()

	childrenMap := make(map[string]Conn, 0)
	children := h.views.Children(view)
	for _, c := range children {
		if !h.ready[c] {
			continue
		}
		childrenMap[c] = h.peers[c]
	}

	h.rlock.RUnlock()

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
func (h *TCPHost) PutUp(view int, data BinaryMarshaler) error {
	pname := h.views.Parent(view)
	h.rlock.RLock()
	isReady := h.ready[pname]
	parent := h.peers[pname]
	h.rlock.RUnlock()
	if !isReady {
		return ErrNotEstablished
	} else if parent == nil && pname != "" {
		// not the root and I have closed my parent connection
		return ErrorConnClosed
	}
	//log.Println("Putting Up:")
	return parent.Put(data)
}

var ErrorChildNotReady error = errors.New("child is not ready")

// PutDown sends a message (an interface{} value) up to all children through
// whatever 'network' interface each child Peer implements.
func (h *TCPHost) PutDown(view int, data []BinaryMarshaler) error {
	if len(data) != h.views.NChildren(view) {
		panic("number of messages passed down != number of children")
	}
	// Try to send the message to all children
	// If at least on of the attempts fails, return a non-nil error
	var err error
	children := h.views.Children(view)
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
		// TODO: exponential backoff?
		time.Sleep(100 * time.Millisecond)
	}

	if c == nil {
		return ErrorConnClosed
	}

	return c.Get(data)
}

// each connection we should realistically always be getting from
// TODO: each of these goroutines could be spawned when we initally connect to
// them instead
func (h *TCPHost) Get() (chan NetworkMessg, chan error) {
	// copy children before ranging for thread safety

	// start children threads
	for name := range h.peers {
		go func(name string) {
			for {
				data := h.pool.Get().(BinaryUnmarshaler)
				err := h.whenReadyGet(name, data)
				// check to see if the connection is Closed
				if err == ErrorConnClosed {
					// XXX: should we send to both channels
					h.msglock.Lock()
					h.msgchan <- NetworkMessg{Data: data, From: name}
					h.errchan <- errors.New("connection has been closed")
					h.msglock.Unlock()
					return
				} else if err == io.EOF {
					os.Exit(1)
				}

				h.msglock.Lock()
				h.msgchan <- NetworkMessg{Data: data, From: name}
				h.errchan <- err
				h.msglock.Unlock()

			}
		}(name)
	}
	return h.msgchan, h.errchan
}

func (h *TCPHost) Pool() sync.Pool {
	return h.pool
}

func (h *TCPHost) SetPool(p sync.Pool) {
	h.pool = p
}
