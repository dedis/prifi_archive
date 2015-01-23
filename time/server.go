package time

import (
	"fmt"
	"sync"
	"time"

	"github.com/dedis/prifi/coco"
)

var ROUND_TIME time.Duration = 1 * time.Second

// File defines the server side of the interaction between
// Servers and Clients with the purpose of timestampting client messages
// Server will probably be intergrated with the SigningNodes eventually

func (s *Server) Listen() {
	var mux sync.Mutex
	READING := 0
	PROCESSING := 1
	Queue := make([][]TimeStampMessage, 2)
	Queue[READING] = make([]TimeStampMessage, 0)
	Queue[PROCESSING] = make([]TimeStampMessage, 0)
	for _, c := range s.clients {
		go func(c *coco.GoConn) {
			for {
				tsm := TimeStampMessage{}
				c.Get(&tsm)
				fmt.Println("getting message", tsm)
				fmt.Println("deref inner message:", string(tsm.sreq.Val))
				mux.Lock()
				Queue[READING] = append(Queue[READING], tsm)
				mux.Unlock()
			}
		}(c)
	}

	fmt.Println("Before ticker")
	ticker := time.Tick(1 * time.Second)
	for _ = range ticker {
		// fmt.Println("in ticker", t)
		mux.Lock()
		READING, PROCESSING = PROCESSING, READING
		Queue[READING] = Queue[READING][:0]
		mux.Unlock()
		// aggregate messages from this round
		for _, msg := range Queue[PROCESSING] {
			// aggregate stamp requests
			fmt.Println("aggregating:", string(msg.sreq.Val))
		}
	}
	fmt.Println("out")
}

type Server struct {
	name    string
	clients map[string]*coco.GoConn

	dir *coco.GoDirectory
}

func NewServer(name string, dir *coco.GoDirectory) (s *Server) {
	s = &Server{name: name, dir: dir}
	s.clients = make(map[string]*coco.GoConn)
	return
}

func (s *Server) Name() string {
	return s.name
}

type Client struct {
	name string
	dir  *coco.GoDirectory

	servers map[string]*coco.GoConn
}

func NewClient(name string, dir *coco.GoDirectory) (c *Client) {
	c = &Client{name: name, dir: dir}
	c.servers = make(map[string]*coco.GoConn)
	return
}

func (c *Client) Name() string {
	return c.name
}

func (c *Client) Put(name string, data coco.BinaryMarshaler) {
	fmt.Println("putting ", data)
	c.servers[name].Put(data)
}
