package stamp

import (
	"log"
	"net"
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
	name    string
	Clients map[string]coconet.Conn

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

	s.Clients = make(map[string]coconet.Conn)
	s.Queue = make([][]MustReplyMessage, 2)
	s.READING = 0
	s.PROCESSING = 1

	s.Signer = signer
	s.Signer.RegisterAnnounceFunc(s.OnAnnounce())
	s.Signer.RegisterDoneFunc(s.OnDone())
	h, p, err := net.SplitHostPort(s.Signer.Name())
	if err == nil {
		i, err := strconv.Atoi(p)
		if err != nil {
			log.Fatal(err)
		}
		s.name = net.JoinHostPort(h, strconv.Itoa(i+1))
	}
	return s
}

// listen for clients connections
// this server needs to be running on a different port
// than the Signer that is beneath it
func (s *Server) ListenForClients() error {
	ln, err := net.Listen("tcp", s.name)
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
			}
			bs := make([]byte, 300)
			n, err := conn.Read(bs)
			if err != nil {
				log.Println(err)
				conn.Close()
				continue
			}
			name := string(bs[:n])
			s.Clients[name] = coconet.NewTCPConnFromNet(conn)
		}
	}()
	return nil
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
		go func(c coconet.Conn) {
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
		for i, msg := range s.Queue[s.PROCESSING] {
			// proof to get from s.Root to big root
			combProof := make(proof.Proof, len(p))
			copy(combProof, p)

			// add my proof to get from a leaf message to my root s.Root
			combProof = append(combProof, s.Proofs[i]...)

			// proof that i can get from a leaf message to the big root
			proof.CheckProof(s.Signer.(*sign.SigningNode).GetSuite().Hash, SNRoot, s.Leaves[i], combProof)

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
		s.Root = make([]byte, hashid.Size)
		s.Proofs = make([]proof.Proof, 1)
		return s.Root
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
		log.Println("Local Proofs of", s.name, "successful for round "+strconv.Itoa(s.nRounds))
	} else {
		panic("Local Proofs" + s.name + " unsuccessful for round " + strconv.Itoa(s.nRounds))
	}

	return s.Root
}

// Send message to client given by name
func (s *Server) PutToClient(name string, data coconet.BinaryMarshaler) {
	s.Clients[name].Put(data)
}
