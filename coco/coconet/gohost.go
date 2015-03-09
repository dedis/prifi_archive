package coconet

import (
	"errors"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/nist"
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

// Default timeout for any network operation
const DefaultGoTimeout time.Duration = 500 * time.Millisecond

var TimeoutError error = errors.New("Network timeout error")

// a GoHost must satisfy the host interface
var _ Host = &GoHost{}

// HostNode is a simple implementation of Host that does not specify the
// communication medium (goroutines/channels, network nodes/tcp, ...).
type GoHost struct {
	name string // the hostname

	views *Views

	plock sync.Mutex
	peers map[string]Conn
	dir   *GoDirectory

	rlock sync.RWMutex
	ready map[string]bool

	mupk   sync.RWMutex
	Pubkey abstract.Point // own public key

	mutimeout sync.Mutex
	timeout   time.Duration // general timeout for any network operation

	pool sync.Pool

	msglock sync.Mutex
	msgchan chan NetworkMessg
	errchan chan error
}

func (h *GoHost) GetDirectory() *GoDirectory {
	return h.dir
}

func (h *GoHost) DefaultTimeout() time.Duration {
	h.mutimeout.Lock()
	t := DefaultGoTimeout
	h.mutimeout.Unlock()
	return t
}

func (h *GoHost) SetTimeout(t time.Duration) {
	h.mutimeout.Lock()
	h.timeout = t
	h.mutimeout.Unlock()
}

func (h *GoHost) Timeout() time.Duration {
	var t time.Duration
	h.mutimeout.Lock()
	t = h.timeout
	h.mutimeout.Unlock()
	return t
}

// NewHostNode creates a new HostNode with a given hostname.
func NewGoHost(hostname string, dir *GoDirectory) *GoHost {
	h := &GoHost{name: hostname,
		views:   NewViews(),
		peers:   make(map[string]Conn),
		dir:     dir,
		msgchan: make(chan NetworkMessg, 0),
		errchan: make(chan error, 0)}
	h.mutimeout.Lock()
	h.timeout = DefaultGoTimeout
	h.mutimeout.Unlock()
	h.rlock = sync.RWMutex{}
	h.ready = make(map[string]bool)
	return h
}

func (h *GoHost) PubKey() abstract.Point {
	h.mupk.RLock()
	pk := h.Pubkey
	h.mupk.RUnlock()
	return pk
}

func (h *GoHost) SetPubKey(pk abstract.Point) {
	h.mupk.Lock()
	h.Pubkey = pk
	h.mupk.Unlock()
}

func (h *GoHost) Connect(view int) error {
	return nil
}

func (h *GoHost) Listen() error {
	children := h.views.Children(0)

	suite := nist.NewAES128SHA256P256()
	// each conn should have a Ready() bool, SetReady(bool)
	for _, c := range children {
		go func(c string) {
			pubkey := suite.Point()

			h.rlock.Lock()
			conn := h.peers[c]
			h.rlock.Unlock()

			e := conn.Get(pubkey)
			if e != nil {
				log.Fatal("unable to get pubkey from child")
			}
			conn.SetPubKey(pubkey)
			h.rlock.Lock()
			h.ready[c] = true
			h.rlock.Unlock()
			// fmt.Println("connection with child established")
		}(c)
	}
	return nil
}

func (h *GoHost) NewView(view int, parent string, children []string) {
	h.views.NewView(view, parent, children)
}

// AddParent adds a parent node to the HostNode.
func (h *GoHost) AddParent(view int, c string) {
	if _, ok := h.peers[c]; !ok {
		h.peers[c], _ = NewGoConn(h.dir, h.name, c)
	}
	h.views.AddParent(view, c)
	h.plock.Lock()
	h.peers[c].Put(h.PubKey()) // publick key should be put here first
	// only after putting pub key allow it to be accessed like parent
	h.plock.Unlock()

	h.rlock.Lock()
	h.ready[c] = true
	h.rlock.Unlock()

}

// AddChildren variadically adds multiple Peers as children to the HostNode.
// Only unique children will be stored.
func (h *GoHost) AddChildren(view int, cs ...string) {
	for _, c := range cs {
		if _, ok := h.peers[c]; !ok {
			h.peers[c], _ = NewGoConn(h.dir, h.name, c)
		}
		// don't allow children to be accessed before adding them
		h.views.AddChildren(view, c)
	}
}

func (h *GoHost) Close() {}

func (h *GoHost) NChildren(view int) int {
	return h.views.NChildren(view)
}

// Name returns the hostname of the HostNode.
func (h *GoHost) Name() string {
	return h.name
}

// IsRoot returns true if the HostNode is the root of it's tree (if it has no
// parent).
func (h *GoHost) IsRoot(view int) bool {
	return h.views.Parent(view) == ""
}

func (h *GoHost) IsParent(view int, peer string) bool {
	return h.views.Parent(view) == peer
}

func (h *GoHost) IsChild(view int, peer string) bool {
	_, ok := h.peers[peer]
	return !h.IsParent(view, peer) && ok
}

// Peers returns the list of peers as a mapping from hostname to Conn
func (h *GoHost) Peers() map[string]Conn {
	return h.peers
}

func (h *GoHost) Children(view int) map[string]Conn {
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
func (h *GoHost) AddPeers(cs ...string) {
	for _, c := range cs {
		h.peers[c], _ = NewGoConn(h.dir, h.name, c)
	}
}

// WaitTick waits for a random amount of time.
// XXX should it wait for a network change
func (h *GoHost) WaitTick() {
	time.Sleep(1 * time.Second)
}

// TODO(dyv): following methods will have to be rethought with network failures and
// latency in mind. What happens during GetDown if one node serves up old
// responses after a certain timeout?

// PutUp sends a message (an interface{} value) up to the parent through
// whatever 'network' interface the parent Peer implements.
func (h *GoHost) PutUp(view int, data BinaryMarshaler) error {
	// defer fmt.Println(h.Name(), "done put up", h.parent)
	// log.Printf("%s PUTTING UP up: %#v", h.Name(), data)
	pname := h.views.Parent(view)
	h.rlock.RLock()
	isReady := h.ready[pname]
	parent := h.peers[pname]
	h.rlock.RUnlock()
	if !isReady {
		return ConnectionNotEstablished
	} else if parent == nil && pname != "" {
		// not the root and I have closed my parent connection
		return ErrorConnClosed
	}
	return parent.Put(data)
}

// PutDown sends a message (an interface{} value) up to all children through
// whatever 'network' interface each child Peer implements.
func (h *GoHost) PutDown(view int, data []BinaryMarshaler) error {
	if len(data) != h.views.NChildren(view) {
		panic("number of messages passed down != number of children")
	}
	// Try to send the message to all children
	// If at least on of the attempts fails, return a non-nil error
	var err error
	i := 0
	children := h.views.Children(view)
	for _, c := range children {
		h.rlock.Lock()
		conn := h.peers[c]
		h.rlock.Unlock()
		if e := conn.Put(data[i]); e != nil {
			err = e
		}
		i++
	}
	return err
}

func (h *GoHost) whenReadyGet(c string, data BinaryUnmarshaler) error {
	// defer fmt.Println(h.Name(), "returned ready channel for", c.Name(), c)
	for {
		h.rlock.Lock()
		isReady := h.ready[c]
		h.rlock.Unlock()

		if isReady {
			// fmt.Println(h.Name(), "is ready")
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	h.plock.Lock()
	conn := h.peers[c]
	h.plock.Unlock()
	return conn.Get(data)
}

func (h *GoHost) Get() (chan NetworkMessg, chan error) {
	for name := range h.peers {
		go func(name string) {
			for {
				data := h.pool.Get().(BinaryUnmarshaler)
				err := h.whenReadyGet(name, data)

				h.msglock.Lock()
				h.msgchan <- NetworkMessg{Data: data, From: name}
				h.errchan <- err
				h.msglock.Unlock()

			}
		}(name)
	}
	return h.msgchan, h.errchan

}

func (h *GoHost) Pool() sync.Pool {
	return h.pool
}

func (h *GoHost) SetPool(p sync.Pool) {
	h.pool = p
}
