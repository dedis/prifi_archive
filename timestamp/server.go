package time

import (
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/prifi/coco"
)

// File defines the server side of the interaction between
// Servers and Clients with the purpose of timestampting client messages
// Server will probably be intergrated with the SigningNodes eventually

var ROUND_TIME time.Duration = 1 * time.Second

type Server struct {
	suite abstract.Suite

	name    string
	clients map[string]*coco.GoConn
	nRounds int
	mux     sync.Mutex

	dir *coco.GoDirectory

	coco.SigningNode

	// for aggregating messages from clients
	Queue      [][]MustReplyMessage
	READING    int
	PROCESSING int
}

func NewServer(name string, dir *coco.GoDirectory, suite abstract.Suite) (s *Server) {
	s = &Server{name: name, dir: dir}
	s.clients = make(map[string]*coco.GoConn)
	s.suite = suite

	s.READING = 0
	s.PROCESSING = 1
	return
}

// struct to ease keeping track of who requires a reply after
// tsm is processed/ aggregated by the server
type MustReplyMessage struct {
	tsm TimeStampMessage
	to  string // name of reply destination
}

// TODO: error handling
func (s *Server) Listen(isRoot bool) {
	s.Queue = make([][]MustReplyMessage, 2)
	Queue := s.Queue
	READING := s.READING
	PROCESSING := s.PROCESSING

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
					s.mux.Lock()
					Queue[READING] = append(Queue[READING],
						MustReplyMessage{tsm: tsm, to: c.Name()})
					s.mux.Unlock()
				}
			}
		}(c)
	}

	if isRoot == true {
		fmt.Println(s.Name(), "is root")
		ticker := time.Tick(1 * time.Second)
		for _ = range ticker {
			// send an announcement message to all other servers
			// s.Announce(&coco.AnnouncementMessage{LogTest: []byte("New Round")})
			s.AggregateCommits()
		}
	}
}

func (s *Server) AggregateCommits() {
	s.mux.Lock()
	// get data from s once
	Queue := s.Queue
	READING := s.READING
	PROCESSING := s.PROCESSING

	READING, PROCESSING = PROCESSING, READING
	Queue[READING] = Queue[READING][:0]

	// give up if nothing to process
	if len(Queue[PROCESSING]) == 0 {
		return
	}

	// count only productive rounds
	s.nRounds++

	// pull out to be Merkle Tree leaves
	leaves := make([]HashId, 0)
	for _, msg := range Queue[PROCESSING] {
		leaves = append(leaves, HashId(msg.tsm.sreq.Val))
	}
	s.mux.Unlock()

	// create Merkle tree for this round
	mtRoot, proofs := ProofTree(s.suite.Hash, leaves)
	if CheckProofs(s.suite.Hash, mtRoot, leaves, proofs) == true {
		fmt.Println("Proofs successful for round " + strconv.Itoa(s.nRounds))
	} else {
		panic("Proofs unsuccessful for round " + strconv.Itoa(s.nRounds))
	}

	s.mux.Lock()
	// sending replies back to clients
	for i, msg := range Queue[PROCESSING] {
		s.Put(msg.to,
			TimeStampMessage{
				Type:  StampReplyType,
				ReqNo: msg.tsm.ReqNo,
				srep:  &StampReply{Sig: mtRoot, Prf: proofs[i]}})
	}
	s.mux.Unlock()
}

func (s *Server) Name() string {
	return s.name
}

func (s *Server) Put(name string, data coco.BinaryMarshaler) {
	s.clients[name].Put(data)
}
