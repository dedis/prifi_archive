package coconet

import (
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	log "github.com/Sirupsen/logrus"

	"github.com/dedis/crypto/abstract"
	"golang.org/x/net/context"
)

func init() {
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc,
		syscall.SIGINT)
	go func() {
		<-sigc
		panic("CTRL-C")
	}()
}

// a GoHost must satisfy the host interface
var _ Host = &GoHost{}

// GoHost is an implementation of the Host interface,
// that uses GoConns as its underlying connection type.
type GoHost struct {
	name string // the hostname

	views *Views

	peerLock sync.RWMutex
	peers    map[string]Conn
	dir      *GoDirectory
	ready    map[string]bool

	suite abstract.Suite

	pkLock sync.RWMutex
	Pubkey abstract.Point // own public key

	pool sync.Pool

	msglock sync.Mutex
	msgchan chan NetworkMessg
	errchan chan error

	closed int64
}

// GetDirectory returns the underlying directory used for GoHosts.
func (h *GoHost) GetDirectory() *GoDirectory {
	return h.dir
}

// NewGoHost creates a new GoHost with the given hostname,
// and registers it in the given directory.
func NewGoHost(hostname string, dir *GoDirectory) *GoHost {
	h := &GoHost{name: hostname,
		views:   NewViews(),
		peers:   make(map[string]Conn),
		dir:     dir,
		msgchan: make(chan NetworkMessg, 10),
		errchan: make(chan error, 10)}
	h.peerLock = sync.RWMutex{}
	h.ready = make(map[string]bool)
	return h
}

// SetSuite sets the crypto suite which this Host is using.
func (h *GoHost) SetSuite(s abstract.Suite) {
	h.suite = s
}

// PubKey returns the public key of the Host.
func (h *GoHost) PubKey() abstract.Point {
	h.pkLock.RLock()
	pk := h.Pubkey
	h.pkLock.RUnlock()
	return pk
}

// SetPubKey sets the publick key of the Host.
func (h *GoHost) SetPubKey(pk abstract.Point) {
	h.pkLock.Lock()
	h.Pubkey = pk
	h.pkLock.Unlock()
}

// Connect connects to the parent of the host.
// For GoHosts this is a noop.
func (h *GoHost) Connect(view int) error {
	parent := h.views.Parent(view)
	if parent == "" {
		return nil
	}

	// if the connection has been established skip it
	h.peerLock.RLock()
	if h.ready[parent] {
		h.peerLock.RUnlock()
		log.Warnln("peer is already ready")
		return nil
	}
	h.peerLock.RUnlock()

	// get the connection to the parent
	conn := h.peers[parent]

	// send the hostname to the destination
	mname := StringMarshaler(h.Name())
	err := conn.Put(&mname)
	if err != nil {
		log.Fatal("failed to connect: putting name:", err)
	}

	// give the parent the public key
	err = conn.Put(h.Pubkey)
	if err != nil {
		log.Fatal("failed to send public key:", err)
	}

	// get the public key of the parent
	suite := h.suite
	pubkey := suite.Point()
	err = conn.Get(pubkey)
	if err != nil {
		log.Fatal("failed to establish connection: getting pubkey:", err)
	}
	conn.SetPubKey(pubkey)

	h.peerLock.Lock()
	h.ready[conn.Name()] = true
	h.peers[parent] = conn
	h.peerLock.Unlock()
	return nil
}

// Listen listens for incoming goconn connections.
// It shares the public keys and names of the hosts.
func (h *GoHost) Listen() error {
	children := h.views.Children(0)
	// listen for connection attempts from each of the children
	for _, c := range children {
		go func(c string) {
			if h.ready[c] {
				log.Fatal("listening: connection already established")
			}

			h.peerLock.Lock()
			conn := h.peers[c]
			h.peerLock.Unlock()

			var mname StringMarshaler
			err := conn.Get(&mname)
			if err != nil {
				log.Fatal("failed to establish connection: getting name:", err)
			}

			suite := h.suite
			pubkey := suite.Point()

			e := conn.Get(pubkey)
			if e != nil {
				log.Fatal("unable to get pubkey from child")
			}
			conn.SetPubKey(pubkey)

			err = conn.Put(h.Pubkey)
			if err != nil {
				log.Fatal("failed to send public key:", err)
			}

			h.peerLock.Lock()
			h.ready[c] = true
			h.peers[c] = conn
			h.peerLock.Unlock()
		}(c)
	}
	return nil
}

// NewView creates a new view with the given view number, parent, and children.
func (h *GoHost) NewView(view int, parent string, children []string) {
	h.views.NewView(view, parent, children)
}

// AddParent adds a parent node to the specified view.
func (h *GoHost) AddParent(view int, c string) {
	h.peerLock.RLock()
	if _, ok := h.peers[c]; !ok {
		h.peers[c], _ = NewGoConn(h.dir, h.name, c)
	}
	h.peerLock.RUnlock()
	h.views.AddParent(view, c)
}

// AddChildren adds children to the specified view.
func (h *GoHost) AddChildren(view int, cs ...string) {
	for _, c := range cs {
		h.peerLock.RLock()
		if _, ok := h.peers[c]; !ok {
			h.peers[c], _ = NewGoConn(h.dir, h.name, c)
		}
		h.peerLock.RUnlock()
		h.views.AddChildren(view, c)
	}
}

// Close closes the connections.
func (h *GoHost) Close() {
	log.Printf("closing gohost: %p", h)
	h.dir.Close()
	h.peerLock.RLock()
	for _, c := range h.peers {
		c.Close()
	}
	h.peerLock.RUnlock()
	atomic.SwapInt64(&h.closed, 1)
}

func (h *GoHost) Closed() bool {
	return atomic.LoadInt64(&h.closed) == 1
}

// NChildren returns the number of children specified by the given view.
func (h *GoHost) NChildren(view int) int {
	return h.views.NChildren(view)
}

// Name returns the hostname of the Host.
func (h *GoHost) Name() string {
	return h.name
}

// IsRoot returns true if this Host is the root of the specified view.
func (h *GoHost) IsRoot(view int) bool {
	return h.views.Parent(view) == ""
}

// IsParent returns true if the peer is the Parent of the specifired view.
func (h *GoHost) IsParent(view int, peer string) bool {
	return h.views.Parent(view) == peer
}

// IsChild returns true if the peer is a Child for the specified view.
func (h *GoHost) IsChild(view int, peer string) bool {
	_, ok := h.peers[peer]
	return !h.IsParent(view, peer) && ok
}

// Peers returns the list of peers as a mapping from hostname to Conn
func (h *GoHost) Peers() map[string]Conn {
	return h.peers
}

// Children returns the children in the specified view.
func (h *GoHost) Children(view int) map[string]Conn {
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

// AddPeers adds the list of peers to the host.
func (h *GoHost) AddPeers(cs ...string) {
	h.peerLock.Lock()
	for _, c := range cs {
		h.peers[c], _ = NewGoConn(h.dir, h.name, c)
	}
	h.peerLock.Unlock()
}

// PutUp sends a message to the parent on the given view, potentially timing out.
func (h *GoHost) PutUp(ctx context.Context, view int, data BinaryMarshaler) error {
	// defer fmt.Println(h.Name(), "done put up", h.parent)

	pname := h.views.Parent(view)
	done := make(chan error)
	var canceled int64
	go func() {
		for {
			if atomic.LoadInt64(&canceled) == 1 {
				return
			}
			h.peerLock.RLock()
			ready := h.ready[pname]
			parent := h.peers[pname]
			h.peerLock.RUnlock()

			if ready {
				// if closed put will return ErrClosed
				done <- parent.Put(data)
				return
			}
			time.Sleep(250 * time.Millisecond)
		}
	}()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		atomic.StoreInt64(&canceled, 1)
		return ctx.Err()
	}
}

// PutDown sends messages to its children on the given view, potentially timing out.
func (h *GoHost) PutDown(ctx context.Context, view int, data []BinaryMarshaler) error {
	var err error
	var errLock sync.Mutex
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
			for {
				if atomic.LoadInt64(&canceled) == 1 {
					return
				}
				h.peerLock.RLock()
				ready := h.ready[c]
				conn := h.peers[c]
				h.peerLock.RUnlock()

				if ready {
					e := conn.Put(data[i])
					if e != nil {
						errLock.Lock()
						err = e
						errLock.Unlock()
					}
					return
				}
				time.Sleep(250 * time.Millisecond)
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
		log.Errorln("DEADLINE EXCEEDED")
		err = ctx.Err()
		atomic.StoreInt64(&canceled, 1)
	}
	return err
}

// whenReadyGet attempts gets data from the connection once it is ready.
func (h *GoHost) whenReadyGet(name string, data BinaryUnmarshaler) error {
	// defer fmt.Println(h.Name(), "returned ready channel for", c.Name(), c)
	var c Conn
	for {
		h.peerLock.Lock()
		isReady := h.ready[name]
		c = h.peers[name]
		h.peerLock.Unlock()

		if isReady {
			break
		}
		if h.Closed() {
			return ErrClosed
		}
		time.Sleep(100 * time.Millisecond)
	}
	if c == nil {
		return ErrClosed
	}
	return c.Get(data)
}

// Get returns two channels. One of messages that are received, and another of errors
// associated with each message.
func (h *GoHost) Get() (chan NetworkMessg, chan error) {
	h.peerLock.RLock()
	for name := range h.peers {
		go func(name string) {
			for {
				data := h.pool.Get().(BinaryUnmarshaler)
				err := h.whenReadyGet(name, data)

				h.msglock.Lock()
				h.msgchan <- NetworkMessg{Data: data, From: name}
				h.errchan <- err
				h.msglock.Unlock()

				if err == ErrClosed {
					return
				}

			}
		}(name)
	}
	h.peerLock.RUnlock()
	return h.msgchan, h.errchan

}

// Pool returns the underlying pool of objects for creating new BinaryUnmarshalers,
// when Getting from network connections.
func (h *GoHost) Pool() sync.Pool {
	return h.pool
}

// SetPool sets the pool of underlying objects for creating new BinaryUnmarshalers,
// when Getting from network connections.
func (h *GoHost) SetPool(p sync.Pool) {
	h.pool = p
}
