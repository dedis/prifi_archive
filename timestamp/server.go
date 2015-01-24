package time

import (
	"fmt"
	"sync"
	"time"

	"github.com/dedis/prifi/coco"
)

// File defines the server side of the interaction between
// Servers and Clients with the purpose of timestampting client messages
// Server will probably be intergrated with the SigningNodes eventually

var ROUND_TIME time.Duration = 1 * time.Second

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

// struct to ease keeping track of who requires a reply after
// tsm is processed/ aggregated by the server
type MustReplyMessage struct {
	tsm TimeStampMessage
	to  string // name of reply destination
}

// TODO: error handling
func (s *Server) Listen() {
	var mux sync.Mutex
	READING := 0
	PROCESSING := 1
	Queue := make([][]MustReplyMessage, 2)
	Queue[READING] = make([]MustReplyMessage, 0)
	Queue[PROCESSING] = make([]MustReplyMessage, 0)
	for _, c := range s.clients {
		go func(c *coco.GoConn) {
			for {
				tsm := TimeStampMessage{}
				c.Get(&tsm)

				switch tsm.Type {
				default:
					fmt.Println("Message of unknown type")
				case StampRequestType:
					// fmt.Println("Server getting message", tsm)
					fmt.Println("Stamp Request val:", string(tsm.sreq.Val))
					mux.Lock()
					Queue[READING] = append(Queue[READING],
						MustReplyMessage{tsm: tsm, to: c.Name()})
					mux.Unlock()
				}
			}
		}(c)
	}

	fmt.Println("Before ticker")
	ticker := time.Tick(1 * time.Second)
	for _ = range ticker {
		mux.Lock()
		READING, PROCESSING = PROCESSING, READING
		Queue[READING] = Queue[READING][:0]
		mux.Unlock()
		// aggregate messages from this round
		var sig []byte
		for _, msg := range Queue[PROCESSING] {
			// aggregate stamp requests
			// fmt.Println("aggregating:", string(msg.tsm.sreq.Val))
			sig = msg.tsm.sreq.Val
		}

		for _, msg := range Queue[PROCESSING] {
			fmt.Println("Replying to", string(msg.to))
			s.Put(msg.to,
				TimeStampMessage{
					Type: StampReplyType,
					srep: &StampReply{Sig: sig}})
		}
	}
}

func (s *Server) Name() string {
	return s.name
}

func (s *Server) Put(name string, data coco.BinaryMarshaler) {
	fmt.Println("putting ", data)
	s.clients[name].Put(data)
}
