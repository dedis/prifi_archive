package coconet

import (
	"errors"
	"sync"
	"time"
)

// Default timeout for any network operation
const DefaultGoTimeout time.Duration = 500 * time.Millisecond

var TimeoutError error = errors.New("Network timeout error")

// HostNode is a simple implementation of Host that does not specify the
// communication medium (goroutines/channels, network nodes/tcp, ...).
type GoHost struct {
	name     string // the hostname
	parent   Conn   // the Peer representing parent, nil if root
	children []Conn // a list of unique peers for each hostname
	peers    map[string]Conn
	dir      *GoDirectory

	timeout time.Duration // general timeout for any network operation
}

func (h *GoHost) GetDirectory() *GoDirectory {
	return h.dir
}

// NewHostNode creates a new HostNode with a given hostname.
func NewGoHost(hostname string, dir *GoDirectory) *GoHost {
	h := &GoHost{name: hostname,
		children: make([]Conn, 0),
		peers:    make(map[string]Conn),
		dir:      dir}

	h.timeout = DefaultGoTimeout
	return h
}

func (h *GoHost) Connect() error {
	return nil
}
func (h *GoHost) Listen() error {
	return nil
}

// AddParent adds a parent node to the HostNode.
func (h *GoHost) AddParent(c string) {
	if _, ok := h.peers[c]; !ok {
		h.peers[c] = nil
	}
	h.parent, _ = NewGoConn(h.dir, h.name, c)
}

// AddChildren variadically adds multiple Peers as children to the HostNode.
// Only unique children will be stored.
func (h *GoHost) AddChildren(cs ...string) {
	for _, c := range cs {
		if _, ok := h.peers[c]; !ok {
			h.peers[c], _ = NewGoConn(h.dir, h.name, c)
		}
		h.children = append(h.children, h.peers[c])
	}
}

func (h *GoHost) Close() {}

func (h *GoHost) NChildren() int {
	return len(h.children)
}

// Name returns the hostname of the HostNode.
func (h GoHost) Name() string {
	return h.name
}

// IsRoot returns true if the HostNode is the root of it's tree (if it has no
// parent).
func (h GoHost) IsRoot() bool {
	return h.parent == nil
}

// Peers returns the list of peers as a mapping from hostname to Conn
func (h GoHost) Peers() map[string]Conn {
	return h.peers
}

func (h GoHost) Children() []Conn {
	return h.children
}

// AddPeers adds the list of peers
func (h GoHost) AddPeers(cs ...string) {
	for _, c := range cs {
		h.peers[c], _ = NewGoConn(h.dir, h.name, c)
	}
}

// WaitTick waits for a random amount of time.
// XXX should it wait for a network change
func (h GoHost) WaitTick() {
	time.Sleep(1 * time.Second)
}

// TODO(dyv): following methods will have to be rethought with network failures and
// latency in mind. What happens during GetDown if one node serves up old
// responses after a certain timeout?

// PutUp sends a message (an interface{} value) up to the parent through
// whatever 'network' interface the parent Peer implements.
func (h *GoHost) PutUp(data BinaryMarshaler) error {
	return <-h.parent.Put(data)
}

// GetUp gets a message (an interface{} value) from the parent through
// whatever 'network' interface the parent Peer implements.
func (h *GoHost) GetUp(data BinaryUnmarshaler) error {
	return <-h.parent.Get(data)
}

// PutDown sends a message (an interface{} value) up to all children through
// whatever 'network' interface each child Peer implements.
func (h *GoHost) PutDown(data []BinaryMarshaler) error {
	if len(data) != len(h.children) {
		panic("number of messages passed down != number of children")
	}
	// Try to send the message to all children
	// If at least on of the attempts fails, return a non-nil error
	var err error
	i := 0
	for _, c := range h.children {
		if e := <-c.Put(data[i]); e != nil {
			err = e
		}
		i++
	}
	return err
}

func setError(mu *sync.Mutex, err *error, e error) {
	mu.Lock()
	*err = e
	mu.Unlock()
}

// GetDown gets a message (an interface{} value) from all children through
// whatever 'network' interface each child Peer implements.
func (h *GoHost) GetDown(data []BinaryUnmarshaler) error {
	var mu sync.Mutex
	var wg sync.WaitGroup
	var err error
	i := 0
	for _, c := range h.children {
		wg.Add(1)

		go func(i int, c Conn) {
			var e error
			defer wg.Done()

			select {
			case e = <-c.Get(data[i]):
				if e != nil {
					setError(&mu, &err, e)
				}
				break
			case <-time.After(h.timeout):
				setError(&mu, &err, TimeoutError)

			}

			if e != nil {
				data[i] = nil
			}

		}(i, c)

		i++
	}
	wg.Wait()
	return err
}
