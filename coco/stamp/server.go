package stamp

import (
	"log"
	"strconv"
	"sync"
	"time"

	"github.com/dedis/prifi/coco"
	"github.com/dedis/prifi/coco/coconet"
	"github.com/dedis/prifi/coco/hashid"
	"github.com/dedis/prifi/coco/proof"
	"github.com/dedis/prifi/coco/sign"
)

type Server struct {
	coco.Signer
	Clients map[string]*coconet.GoConn

	// for aggregating messages from clients
	mux        sync.Mutex
	Queue      [][]MustReplyMessage
	READING    int
	PROCESSING int

	// Leaves, Root and Proof for a round
	Leaves []hashid.HashId // can be removed after we verify protocol
	Root   hashid.HashId
	Proofs []proof.Proof

	nRounds int
}

func NewServer(signer coco.Signer) *Server {
	s := &Server{}

	s.Clients = make(map[string]*coconet.GoConn)
	s.Queue = make([][]MustReplyMessage, 2)
	s.READING = 0
	s.PROCESSING = 1

	s.Signer = signer
	s.Signer.RegisterAnnounceFunc(s.OnAnnounce())
	s.Signer.RegisterDoneFunc(s.OnDone())
	return s
}

// Listen on client connections. If role is root also send annoucement
// for all of the nRounds
func (s *Server) ListenToClients(role string, nRounds int) {
	s.mux.Lock()
	Queue := s.Queue
	READING := s.READING
	PROCESSING := s.PROCESSING
	Queue[READING] = make([]MustReplyMessage, 0)
	Queue[PROCESSING] = make([]MustReplyMessage, 0)
	s.mux.Unlock()
	for _, c := range s.Clients {
		go func(c *coconet.GoConn) {
			for {
				tsm := TimeStampMessage{}
				c.Get(&tsm)
				switch tsm.Type {
				default:
					log.Println("Message of unknown type")
				case StampRequestType:
					// fmt.Println(s.Name(), " getting message")
					s.mux.Lock()
					READING := s.READING
					Queue[READING] = append(Queue[READING],
						MustReplyMessage{Tsm: tsm, To: c.Name()})
					s.mux.Unlock()
				}
			}
		}(c)
	}
	switch role {

	case "root":
		// count only productive rounds
		ticker := time.Tick(250 * time.Millisecond)
		for _ = range ticker {
			s.nRounds++
			if s.nRounds > nRounds {
				continue
			}
			s.StartSigningRound()
		}

	case "test":
		ticker := time.Tick(250 * time.Millisecond)
		for _ = range ticker {
			s.AggregateCommits()
		}
	case "regular":
		for {
			time.Sleep(100 * time.Millisecond)
		}
	}

}

func (s *Server) OnAnnounce() coco.CommitFunc {
	return func() []byte {
		return s.AggregateCommits()
	}
}

func (s *Server) OnDone() coco.DoneFunc {
	return func(SNRoot hashid.HashId, LogHash hashid.HashId, p proof.Proof) {

		s.mux.Lock()
		for _, msg := range s.Queue[s.PROCESSING] {
			// combProof := make(proof.Proof, len(s.Proofs[i]))
			// copy(combProof, s.Proofs[i])

			// my proof to get to s.Root
			combProof := make(proof.Proof, len(p))
			copy(combProof, p)

			// combProof = append(combProof, p...) // gives us  SNRoot

			// proof.CheckProof(s.Signer.(*sign.SigningNode).GetSuite().Hash, SNRoot, s.Leaves[i], combProof)
			proof.CheckProof(s.Signer.(*sign.SigningNode).GetSuite().Hash, SNRoot, s.Root, combProof)

			respMessg := TimeStampMessage{
				Type:  StampReplyType,
				ReqNo: msg.Tsm.ReqNo,
				Srep:  &StampReply{Sig: SNRoot, Prf: combProof}}

			s.PutToClient(msg.To, respMessg)
		}
		s.mux.Unlock()
	}

}

func (s *Server) AggregateCommits() []byte {
	s.mux.Lock()
	// get data from s once to avoid refetching from structure
	Queue := s.Queue
	READING := s.READING
	PROCESSING := s.PROCESSING
	// messages read will now be processed
	READING, PROCESSING = PROCESSING, READING
	s.READING, s.PROCESSING = s.PROCESSING, s.READING
	s.Queue[READING] = s.Queue[READING][:0]

	// give up if nothing to process
	if len(Queue[PROCESSING]) == 0 {
		s.mux.Unlock()
		return make([]byte, hashid.Size)
	}

	// pull out to be Merkle Tree leaves
	s.Leaves = make([]hashid.HashId, 0)
	for _, msg := range Queue[PROCESSING] {
		s.Leaves = append(s.Leaves, hashid.HashId(msg.Tsm.Sreq.Val))
	}
	s.mux.Unlock()

	// non root servers keep track of rounds here
	if !s.IsRoot() {
		s.nRounds++
	}

	// create Merkle tree for this round's messages and check corectness
	s.Root, s.Proofs = proof.ProofTree(s.GetSuite().Hash, s.Leaves)
	if proof.CheckLocalProofs(s.GetSuite().Hash, s.Root, s.Leaves, s.Proofs) == true {
		log.Println("Local Proofs of", s.Name(), "successful for round "+strconv.Itoa(s.nRounds))
	} else {
		panic("Local Proofs" + s.Name() + " unsuccessful for round " + strconv.Itoa(s.nRounds))
	}

	return s.Root
}

// Send message to client given by name
func (s *Server) PutToClient(name string, data coconet.BinaryMarshaler) {
	s.Clients[name].Put(data)
}
