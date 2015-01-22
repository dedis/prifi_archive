package coco

// TCPHost is a simple implementation of Host that does not specify the
import (
	"log"
	"net"
	"sync"
	"time"
)

// communication medium (goroutines/channels, network nodes/tcp, ...).
type TCPHost struct {
	name     string          // the hostname
	parent   Conn            // the Peer representing parent, nil if root
	children map[string]Conn // a list of unique peers for each hostname
	peers    map[string]Conn
}

// NewTCPHost creates a new TCPHost with a given hostname.
func NewTCPHost(hostname string) *TCPHost {
	h := &TCPHost{name: hostname,
		children: make(map[string]Conn),
		peers:    make(map[string]Conn)}
	return h
}

func (h *TCPHost) Listen() error {
	ln, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Println("failed to listen:", err)
		return err
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			// handle error
			log.Println("failed to accept connection")
		}

		// accept children connections but no one else
		p, ok := h.children[conn.RemoteAddr().String()]
		if !ok {
			log.Println("connection request not from child:", conn.RemoteAddr().String())
			conn.Close()
			continue
		}
		if p != nil {
			log.Println("connection attempt from peer with connection already")
		}
		tp := NewTCPConnFromNet(conn)
		h.children[conn.RemoteAddr().String()] = tp
	}
	return nil
}

func (h *TCPHost) Connect() error {
	conn, err := net.Dial("tcp", h.parent.Name())
	if err != nil {
		return err
	}
	h.parent = NewTCPConnFromNet(conn)
	return nil
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
		if _, ok := h.peers[c]; !ok {
			h.peers[c] = NewTCPConn(c)
		}
		h.children[c] = h.peers[c]
	}
}

func (h *TCPHost) NChildren() int {
	return len(h.children)
}

// Name returns the hostname of the TCPHost.
func (h TCPHost) Name() string {
	return h.name
}

// IsRoot returns true if the TCPHost is the root of it's tree (if it has no
// parent).
func (h TCPHost) IsRoot() bool {
	return h.parent == nil
}

// Peers returns the list of peers as a mapping from hostname to Conn
func (h TCPHost) Peers() map[string]Conn {
	return h.peers
}

func (h TCPHost) Children() map[string]Conn {
	return h.children
}

// AddPeers adds the list of peers
func (h TCPHost) AddPeers(cs ...string) {
	for _, c := range cs {
		h.peers[c] = NewTCPConn(c)
	}
}

// WaitTick waits for a random amount of time.
// XXX should it wait for a network change
func (h TCPHost) WaitTick() {
	time.Sleep(1 * time.Second)
}

// TODO(dyv): following methods will have to be rethought with network failures and
// latency in mind. What happens during GetDown if one node serves up old
// responses after a certain timeout?

// PutUp sends a message (an interface{} value) up to the parent through
// whatever 'network' interface the parent Peer implements.
func (h *TCPHost) PutUp(data BinaryMarshaler) error {
	return h.parent.Put(data)
}

// GetUp gets a message (an interface{} value) from the parent through
// whatever 'network' interface the parent Peer implements.
func (h *TCPHost) GetUp(data BinaryUnmarshaler) error {
	return h.parent.Get(data)
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
	i := 0
	for _, c := range h.children {
		if e := c.Put(data[i]); e != nil {
			err = e
		}
		i++
	}
	return err
}

// GetDown gets a message (an interface{} value) from all children through
// whatever 'network' interface each child Peer implements.
func (h *TCPHost) GetDown(data []BinaryUnmarshaler) error {
	var mu sync.Mutex
	var wg sync.WaitGroup
	var err error
	i := 0
	for _, c := range h.children {
		wg.Add(1)
		go func(i int, c Conn) {
			defer wg.Done()
			e := c.Get(data[i])
			if e != nil {
				mu.Lock()
				err = e
				mu.Unlock()
			}
		}(i, c)
		i++
	}
	wg.Wait()
	return err
}
