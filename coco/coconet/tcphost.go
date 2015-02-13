package coconet

// TCPHost is a simple implementation of Host that does not specify the
import (
	"errors"
	"log"
	"net"
	"sync"
	"time"
)

// Default timeout for any network operation
const DefaultTCPTimeout time.Duration = 200500 * time.Millisecond

// communication medium (goroutines/channels, network nodes/tcp, ...).
type TCPHost struct {
	name     string // the hostname
	parent   Conn   // the Peer representing parent, nil if root
	children []Conn // a list of unique peers for each hostname
	peers    map[string]Conn

	timeout time.Duration // general timeout for any network operation
}

// NewTCPHost creates a new TCPHost with a given hostname.
func NewTCPHost(hostname string) *TCPHost {
	h := &TCPHost{name: hostname,
		children: make([]Conn, 0),
		peers:    make(map[string]Conn)}

	h.timeout = DefaultTCPTimeout
	return h
}

func (h *TCPHost) Listen() error {
	var err error
	ln, err := net.Listen("tcp", h.name)
	if err != nil {
		log.Println("failed to listen:", err)
		return err
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			// handle error
			log.Println("failed to accept connection")
			continue
		}
		if conn == nil {
			log.Println("!!!nil connection!!!")
		}
		// XXX assumes posix max hostname length
		bs := make([]byte, 300)
		n, err := conn.Read(bs)
		if err != nil {
			log.Println(err)
			conn.Close()
			continue
		}
		name := string(bs[:n])
		// accept children connections but no one else
		found := false
		for i, c := range h.children {
			c.(*TCPConn).Lock()
			if c.Name() == name {
				tp := NewTCPConnFromNet(conn)
				h.children[i].(*TCPConn).conn = tp.conn
				h.children[i].(*TCPConn).enc = tp.enc
				h.children[i].(*TCPConn).dec = tp.dec
				found = true
			}
			c.(*TCPConn).Unlock()
		}
		if !found {
			log.Println("connection request not from child:", name)
			conn.Close()
			continue
		}
	}
	return nil
}

func (h *TCPHost) Connect() error {
	if h.parent == nil {
		return nil
	}
	conn, err := net.Dial("tcp", h.parent.Name())
	if err != nil {
		return err
	}
	bs := []byte(h.Name())
	n, err := conn.Write(bs) // TODO: pass up Public Key as well
	if err != nil {
		return err
	}
	if n != len(bs) {
		return errors.New("tcp connect failed did not write full name")
	}
	h.parent = NewTCPConnFromNet(conn)
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
		if _, ok := h.peers[c]; !ok {
			h.peers[c] = NewTCPConn(c)
		}
		h.children = append(h.children, h.peers[c])
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

func (h TCPHost) Children() []Conn {
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
	return ToError(<-h.parent.Put(data))
}

// GetUp gets a message (an interface{} value) from the parent through
// whatever 'network' interface the parent Peer implements.
func (h *TCPHost) GetUp(data BinaryUnmarshaler) error {
	return ToError(<-h.parent.Get(data))
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
		if e := ToError(<-c.Put(data[i])); e != nil {
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
			var e error
			defer wg.Done()

			errchan := make(chan error, 1)
			go func(i int, c Conn) {
				e := ToError(<-c.Get(data[i]))
				errchan <- e

			}(i, c)

			select {
			case e = <-errchan:
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
