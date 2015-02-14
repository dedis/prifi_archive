package coconet

// TCPHost is a simple implementation of Host that does not specify the
import (
	"errors"
	"log"
	"net"
	"sync"
	"time"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/nist"
)

// Default timeout for any network operation
const DefaultTCPTimeout time.Duration = 500 * time.Millisecond

// communication medium (goroutines/channels, network nodes/tcp, ...).
type TCPHost struct {
	name   string // the hostname
	parent Conn   // the Peer representing parent, nil if root

	childLock sync.Mutex
	children  []string // a list of unique peers for each hostname

	rlock sync.Mutex
	ready map[string]bool
	peers map[string]Conn

	mutimeout sync.Mutex
	timeout   time.Duration // general timeout for any network operation

	mupk   sync.RWMutex
	Pubkey abstract.Point // own public key
}

func (h *TCPHost) GetDefaultTimeout() time.Duration {
	return DefaultTCPTimeout
}

func (h *TCPHost) SetTimeout(t time.Duration) {
	h.mutimeout.Lock()
	h.timeout = t
	h.mutimeout.Unlock()
}

func (h *TCPHost) GetTimeout() time.Duration {
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
		peers:    make(map[string]Conn)}

	h.timeout = DefaultTCPTimeout
	h.ready = make(map[string]bool)
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
	ln, err := net.Listen("tcp", h.name)
	if err != nil {
		log.Println("failed to listen:", err)
		return err
	}

	go func() {

		for {
			conn, err := ln.Accept()
			if err != nil {
				// handle error
				log.Println("failed to accept connection")
				continue
			}
			if conn == nil {
				log.Println("!!!nil connection!!!")
				continue
			}
			// Read in name of client
			tp := NewTCPConnFromNet(conn)
			var mname Smarsh
			err = <-tp.Get(&mname)
			if err != nil {
				log.Println("ERROR ERROR ERROR: TCP HOST FAILED:", err)
				tp.Close()
				continue
			}
			name := string(mname)

			// create connection
			tp.SetName(name)

			// get and set public key
			suite := nist.NewAES128SHA256P256()
			pubkey := suite.Point()
			err = <-tp.Get(pubkey)
			if err != nil {
				log.Fatal("unable to get pubkey from child")
			}
			tp.SetPubKey(pubkey)

			// accept children connections but no one else
			found := false
			h.childLock.Lock()
			for i, c := range h.children {
				if c == name {
					h.children[i] = tp.Name()
					found = true
				}
			}
			h.childLock.Unlock()
			if !found {
				log.Println("connection request not from child:", name)
				tp.Close()
				continue
			}

			h.rlock.Lock()
			h.ready[name] = true
			h.peers[name] = tp
			h.rlock.Unlock()
		}
	}()
	return nil
}

func (h *TCPHost) Connect() error {
	if h.parent == nil {
		return nil
	}
	conn, err := net.Dial("tcp", h.parent.Name())
	if err != nil {
		log.Println(err)
		return err
	}
	tp := NewTCPConnFromNet(conn)

	mname := Smarsh(h.Name())
	err = <-tp.Put(&mname)
	if err != nil {
		log.Println(err)
		return err
	}
	tp.SetName(h.parent.Name())

	err = <-tp.Put(h.Pubkey)
	if err != nil {
		log.Println("failed to enc p key")
		return errors.New("failed to encode public key")
	}
	// log.Println("CONNECTING TO PARENT")

	h.parent = tp

	h.rlock.Lock()
	h.ready[tp.Name()] = true
	h.peers[tp.Name()] = tp
	h.rlock.Unlock()

	// log.Println("Successfully CONNECTED TO PARENT")
	return nil
}

func (h *TCPHost) Close() {
	for _, p := range h.peers {
		p.Close()
	}
}

// AddParent adds a parent node to the TCPHost.
func (h *TCPHost) AddParent(c string) {
	if _, ok := h.peers[c]; !ok {
		h.peers[c] = NewTCPConn(c)
	}
	h.parent = h.peers[c]
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
			continue
		}
		h.rlock.Unlock()
		h.children = append(h.children, c)
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
	return h.parent == nil
}

// Peers returns the list of peers as a mapping from hostname to Conn
func (h *TCPHost) Peers() map[string]Conn {
	return h.peers
}

func (h *TCPHost) Children() []Conn {
	h.childLock.Lock()
	h.rlock.Lock()

	children := make([]Conn, len(h.children))
	for i, name := range h.children {
		children[i] = h.peers[name]
	}
	h.rlock.Unlock()
	h.childLock.Unlock()

	return children
}

// AddPeers adds the list of peers
func (h *TCPHost) AddPeers(cs ...string) {
	// XXX does it make sense to add peers that are not children or parents
	for _, c := range cs {
		h.peers[c] = NewTCPConn(c)
	}
}

// WaitTick waits for a random amount of time.
// XXX should it wait for a network change
func (h *TCPHost) WaitTick() {
	time.Sleep(1 * time.Second)
}

// TODO(dyv): following methods will have to be rethought with network failures and
// latency in mind. What happens during GetDown if one node serves up old
// responses after a certain timeout?

// PutUp sends a message (an interface{} value) up to the parent through
// whatever 'network' interface the parent Peer implements.
func (h *TCPHost) PutUp(data BinaryMarshaler) error {
	h.rlock.Lock()
	isReady := h.ready[h.parent.Name()]
	h.rlock.Unlock()
	if !isReady {
		return ConnectionNotEstablished
	}
	return <-h.parent.Put(data)
}

// GetUp gets a message (an interface{} value) from the parent through
// whatever 'network' interface the parent Peer implements.
func (h *TCPHost) GetUp(data BinaryUnmarshaler) error {
	h.rlock.Lock()
	isReady := h.ready[h.parent.Name()]
	h.rlock.Unlock()
	if !isReady {
		return ConnectionNotEstablished
	}
	return <-h.parent.Get(data)
}

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
			err = errors.New("child is not ready")
			continue
		}
		conn := h.peers[c]
		h.rlock.Unlock()
		if e := <-conn.Put(data[i]); e != nil {
			err = e
		}
	}
	return err
}

func (h *TCPHost) whenReadyGet(name string, data BinaryUnmarshaler) chan error {
	var c Conn
	for {
		h.rlock.Lock()
		isReady := h.ready[name]
		c = h.peers[name]
		h.rlock.Unlock()

		if isReady {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	return c.Get(data)
}

// GetDown gets a message (an interface{} value) from all children through
// whatever 'network' interface each child Peer implements.
func (h *TCPHost) GetDown(data []BinaryUnmarshaler) error {
	var mu sync.Mutex
	var wg sync.WaitGroup
	var err error

	// copy children before ranging for thread safety
	h.childLock.Lock()
	children := make([]string, len(h.children))
	copy(children, h.children)
	h.childLock.Unlock()

	for i, c := range children {

		wg.Add(1)
		go func(i int, c string) {
			var e error
			defer wg.Done()
			timeout := h.GetTimeout()

			select {
			case e = <-h.whenReadyGet(c, data[i]):
				if e != nil {
					setError(&mu, &err, e)
				}
				break
			case <-time.After(timeout):
				setError(&mu, &err, TimeoutError)

			}

			if e != nil {
				data[i] = nil
			}
		}(i, c)
	}

	wg.Wait()
	return err
}
