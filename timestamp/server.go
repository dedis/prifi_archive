package time

import (
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/dedis/prifi/coco"
)

// File defines the TSServer side of the interaction between
// TSServers and Clients with the purpose of timestampting client messages
// TSServer will probably be intergrated with the SigningNodes eventually

var ROUND_TIME time.Duration = 1 * time.Second

type TSServer struct {
	// suite abstract.Suite

	name    string
	clients map[string]*coco.GoConn
	nRounds int

	// dir *coco.GoDirectory

	sn *coco.SigningNode

	// for aggregating messages from clients
	mux        sync.Mutex
	Queue      [][]MustReplyMessage
	READING    int
	PROCESSING int
}

func NewTSServer(name string) (s *TSServer) {
	s = &TSServer{name: name}
	s.clients = make(map[string]*coco.GoConn)

	s.READING = 0
	s.PROCESSING = 1
	return
}

// struct to ease keeping track of who requires a reply after
// tsm is processed/ aggregated by the TSServer
type MustReplyMessage struct {
	tsm TimeStampMessage
	to  string // name of reply destination
}

// TODO: error handling
func (s *TSServer) Listen(role string) {
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
					// fmt.Println("TSServer getting message", tsm)
					s.mux.Lock()
					Queue[READING] = append(Queue[READING],
						MustReplyMessage{tsm: tsm, to: c.Name()})
					s.mux.Unlock()
				}
			}
		}(c)
	}

	switch role {

	case "root":
		ticker := time.Tick(1 * time.Second)
		for _ = range ticker {
			// send an announcement message to all other TSServers
			s.sn.Announce(&coco.AnnouncementMessage{LogTest: []byte("New Round")})
			s.AggregateCommits()
		}

	case "test":
		ticker := time.Tick(1 * time.Second)
		for _ = range ticker {
			s.AggregateCommits()
		}
	}

}

func (s *TSServer) AggregateCommits() {
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
	mtRoot, proofs := ProofTree(s.sn.GetSuite().Hash, leaves)
	if CheckProofs(s.sn.GetSuite().Hash, mtRoot, leaves, proofs) == true {
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

func (s *TSServer) Name() string {
	return s.name
}

func (s *TSServer) Put(name string, data coco.BinaryMarshaler) {
	s.clients[name].Put(data)
}
