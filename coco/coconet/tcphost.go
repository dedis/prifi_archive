package coconet

// TCPHost is a simple implementation of Host that does not specify the
import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/prifi/coco"
	"golang.org/x/net/context"
)

// Ensure that TCPHost satisfies the Host interface.
var _ Host = &TCPHost{}

// TCPHost implements the Host interface.
// It uses TCPConns as its underlying connection type.
type TCPHost struct {
	name string

	views *Views

	peerLock sync.RWMutex
	// ready indicates when a connection is ready to be used.
	ready map[string]bool
	peers map[string]Conn

	pkLock sync.RWMutex
	Pubkey abstract.Point // own public key

	pool sync.Pool

	// channels to send on Get() and update
	msglock sync.Mutex
	msgchan chan NetworkMessg
	errchan chan error
	suite   abstract.Suite
}

// NewTCPHost creates a new TCPHost with a given hostname.
func NewTCPHost(hostname string) *TCPHost {
	h := &TCPHost{name: hostname,
		views:   NewViews(),
		peers:   make(map[string]Conn),
		ready:   make(map[string]bool),
		msglock: sync.Mutex{},
		msgchan: make(chan NetworkMessg, 1),
		errchan: make(chan error, 1)}

	return h
}

// SetSuite sets the suite of the TCPHost to use.
func (h *TCPHost) SetSuite(s abstract.Suite) {
	h.suite = s
}

// PubKey returns the public key of the host.
func (h *TCPHost) PubKey() abstract.Point {
	h.pkLock.RLock()
	pk := h.Pubkey
	h.pkLock.RUnlock()
	return pk
}

// SetPubKey sets the public key of the host.
func (h *TCPHost) SetPubKey(pk abstract.Point) {
	h.pkLock.Lock()
	h.Pubkey = pk
	h.pkLock.Unlock()
}

// StringMarshaler is a wrapper type to allow strings to be marshalled and unmarshalled.
type StringMarshaler string

// MarshalBinary implements the BinaryMarshaler interface for the StringMarshaler.
func (s *StringMarshaler) MarshalBinary() ([]byte, error) {
	return []byte(*s), nil
}

// UnmarshalBinary implements the BinaryUnmarshaler interface for the StringMarshaler.
func (s *StringMarshaler) UnmarshalBinary(b []byte) error {
	*s = StringMarshaler(b)
	return nil
}

// Listen listens for incoming TCP connections.
// It is a non-blocking call that runs in the background.
// It accepts incoming connections and establishes peers.
// When a peer attempts to connect it must send over its name (as a StringMarshaler),
// as well as its public key.
// Only after that point can be communicated with.
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
				log.Errorln("failed to accept connection: ", err)
				continue
			}

			// Read in name of client
			tp := NewTCPConnFromNet(conn)
			var mname StringMarshaler
			err = tp.Get(&mname)
			if err != nil {
				log.Errorln("failed to establish connection: getting name: ", err)
				tp.Close()
				continue
			}
			name := string(mname)

			// create connection
			tp.SetName(name)

			// get and set public key
			suite := h.suite
			pubkey := suite.Point()
			err = tp.Get(pubkey)
			if err != nil {
				log.Errorln("failed to establish connection: getting pubkey:", err)
				tp.Close()
				continue
			}
			tp.SetPubKey(pubkey)

			// give child the public key
			err = tp.Put(h.Pubkey)
			if err != nil {
				log.Errorln("failed to send public key:", err)
				continue
			}

			// the connection is now ready to use
			h.peerLock.Lock()
			h.ready[name] = true
			h.peers[name] = tp
			if coco.DEBUG {
				log.Infoln("CONNECTED TO CHILD:", tp, tp.conn)
			}
			h.peerLock.Unlock()
		}
	}()
	return nil
}

// Connect connects to the parent in the given view.
// It connects to the parent by establishing a TCPConn.
// It then sends its name and public key to initialize the connection.
func (h *TCPHost) Connect(view int) error {
	// Get the parent of the given view.
	parent := h.views.Parent(view)
	if parent == "" {
		return nil
	}

	// If we have already set up this connection don't do anything
	h.peerLock.RLock()
	if h.ready[parent] {
		h.peerLock.RUnlock()
		return nil
	}
	h.peerLock.RUnlock()

	// connect to the parent
	conn, err := net.Dial("tcp4", parent)
	if err != nil {
		if coco.DEBUG {
			log.Warnln("tcphost: failed to connect to parent:", err)
		}
		return err
	}
	tp := NewTCPConnFromNet(conn)

	mname := StringMarshaler(h.Name())
	err = tp.Put(&mname)
	if err != nil {
		log.Errorln(err)
		return err
	}
	tp.SetName(parent)

	// give parent the public key
	err = tp.Put(h.Pubkey)
	if err != nil {
		log.Errorln("failed to send public key")
		return err
	}

	// get and set the parents public key
	suite := h.suite
	pubkey := suite.Point()
	err = tp.Get(pubkey)
	if err != nil {
		log.Errorln("failed to establish connection: getting pubkey:", err)
		tp.Close()
		return err
	}
	tp.SetPubKey(pubkey)

	h.peerLock.Lock()
	h.ready[tp.Name()] = true
	h.peers[parent] = tp
	h.peerLock.Unlock()
	if coco.DEBUG {
		log.Infoln("CONNECTED TO PARENT:", parent)
	}
	return nil
}

// NewView creates a new view with the given view number, parent and children.
func (h *TCPHost) NewView(view int, parent string, children []string) {
	h.views.NewView(view, parent, children)
}

// Close closes all the connections currently open.
func (h *TCPHost) Close() {
	h.peerLock.Lock()
	for k, p := range h.peers {
		if p != nil {
			p.Close()
		}
		h.peers[k] = nil
	}
	h.peerLock.Unlock()
}

// AddParent adds a parent node to the TCPHost, for the given view.
func (h *TCPHost) AddParent(view int, c string) {
	if _, ok := h.peers[c]; !ok {
		h.peers[c] = NewTCPConn(c)
	}
	h.views.AddParent(view, c)
}

// AddChildren adds children to the specified view.
func (h *TCPHost) AddChildren(view int, cs ...string) {
	for _, c := range cs {
		// if the peer doesn't exist add it to peers
		if _, ok := h.peers[c]; !ok {
			h.peers[c] = NewTCPConn(c)
		}

		h.views.AddChildren(view, c)
	}
}

// NChildren returns the number of children for the specified view.
func (h *TCPHost) NChildren(view int) int {
	return h.views.NChildren(view)
}

// Name returns the hostname of the TCPHost.
func (h *TCPHost) Name() string {
	return h.name
}

// IsRoot returns true if the TCPHost is the root of it's tree for the given view..
func (h *TCPHost) IsRoot(view int) bool {
	return h.views.Parent(view) == ""
}

// IsParent returns true if the given peer is the parent for the specified view.
func (h *TCPHost) IsParent(view int, peer string) bool {
	return h.views.Parent(view) == peer
}

// IsChild returns true f the given peer is the child for the specified view.
func (h *TCPHost) IsChild(view int, peer string) bool {
	h.peerLock.Lock()
	_, ok := h.peers[peer]
	h.peerLock.Unlock()
	return h.views.Parent(view) != peer && ok
}

// Peers returns the list of peers as a mapping from hostname to Conn.
func (h *TCPHost) Peers() map[string]Conn {
	return h.peers
}

// Children returns a map of childname to Conn for the given view.
func (h *TCPHost) Children(view int) map[string]Conn {
	h.peerLock.RLock()

	childrenMap := make(map[string]Conn, 0)
	children := h.views.Children(view)
	for _, c := range children {
		if !h.ready[c] {
			continue
		}
		childrenMap[c] = h.peers[c]
	}

	h.peerLock.RUnlock()

	return childrenMap
}

// AddPeers adds the list of peers.
func (h *TCPHost) AddPeers(cs ...string) {
	// XXX does it make sense to add peers that are not children or parents
	for _, c := range cs {
		h.peers[c] = NewTCPConn(c)
	}
}

// ErrClosed indicates that the connection has been closed.
var ErrClosed = errors.New("connection closed")

// PutUp sends a message to the parent in the specified view.
func (h *TCPHost) PutUp(ctx context.Context, view int, data BinaryMarshaler) error {
	pname := h.views.Parent(view)
	done := make(chan error)

	go func() {
	retry:
		h.peerLock.RLock()
		isReady := h.ready[pname]
		parent := h.peers[pname]
		h.peerLock.RUnlock()
		if !isReady {
			time.Sleep(250 * time.Millisecond)
			goto retry
		} else if parent == nil && pname != "" {
			// not the root and I have closed my parent connection
			done <- ErrClosed
		}
		done <- parent.Put(data)
	}()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// PutDown sends a message (an interface{} value) up to all children through
// whatever 'network' interface each child Peer implements.
func (h *TCPHost) PutDown(ctx context.Context, view int, data []BinaryMarshaler) error {
	// Try to send the message to all children
	// If at least on of the attempts fails, return a non-nil error
	var err error
	children := h.views.Children(view)
	if len(data) != len(children) {
		panic("number of messages passed down != number of children")
	}
	var canceled int64
	var wg sync.WaitGroup
	for i, c := range children {
		wg.Add(1)
		go func(i int, c string) {
			defer wg.Done()
		retry:
			if atomic.LoadInt64(&canceled) == 1 {
				return
			}

			h.peerLock.RLock()
			if !h.ready[c] {
				h.peerLock.RUnlock()
				time.Sleep(250 * time.Millisecond)
				goto retry
			}
			conn := h.peers[c]
			h.peerLock.RUnlock()
			if e := conn.Put(data[i]); e != nil {
				err = e
			}
		}(i, c)
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		done <- struct{}{}
	}()

	select {
	case <-done:
	case <-ctx.Done():
		err = ctx.Err()
		atomic.StoreInt64(&canceled, 1)
	}

	return err
}

// whenReadyGet waits on the given peer and gets from them when it is ready.
func (h *TCPHost) whenReadyGet(name string, data BinaryUnmarshaler) error {
	var c Conn
	for {
		h.peerLock.Lock()
		isReady := h.ready[name]
		c = h.peers[name]
		h.peerLock.Unlock()

		if isReady {
			break
		}
		// XXX see if we should change Sleep with condition variable...
		// TODO: exponential backoff?
		time.Sleep(100 * time.Millisecond)
	}

	if c == nil {
		return ErrClosed
	}

	return c.Get(data)
}

// Get gets from all of the peers and sends the responses to a channel of
// NetworkMessg and errors that it returns.
//
// TODO: each of these goroutines could be spawned when we initally connect to
// them instead.
func (h *TCPHost) Get() (chan NetworkMessg, chan error) {
	h.peerLock.RLock()
	for name := range h.peers {
		go func(name string) {
			for {
				data := h.pool.Get().(BinaryUnmarshaler)
				err := h.whenReadyGet(name, data)
				// check to see if the connection is Closed
				h.msglock.Lock()
				h.msgchan <- NetworkMessg{Data: data, From: name}
				h.errchan <- err
				h.msglock.Unlock()

			}
		}(name)
	}
	h.peerLock.RUnlock()
	return h.msgchan, h.errchan
}

// Pool is the underlying pool of BinaryUnmarshallers to use when getting.
func (h *TCPHost) Pool() sync.Pool {
	return h.pool
}

// SetPool sets the pool of BinaryUnmarshallers when getting from channels
func (h *TCPHost) SetPool(p sync.Pool) {
	h.pool = p
}
