package stamp

import (
	"net"
	"strconv"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"

	"github.com/dedis/prifi/coco"
	"github.com/dedis/prifi/coco/coconet"
	"github.com/dedis/prifi/coco/hashid"
	"github.com/dedis/prifi/coco/proof"
	"github.com/dedis/prifi/coco/sign"
	"github.com/dedis/prifi/coco/test/logutils"
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

	rLock     sync.Mutex
	nRounds   int
	maxRounds int
	closeChan chan bool
}

// time we wait between rounds
var ROUND_TIME time.Duration = 5 * time.Second

func NewServer(signer coco.Signer) *Server {
	s := &Server{}

	s.Clients = make(map[string]coconet.Conn)
	s.Queue = make([][]MustReplyMessage, 2)
	s.READING = 0
	s.PROCESSING = 1

	s.Signer = signer
	s.Signer.RegisterAnnounceFunc(s.OnAnnounce())
	s.Signer.RegisterDoneFunc(s.OnDone())
	s.rLock = sync.Mutex{}

	// listen for client requests at one port higher
	// than the signing node
	h, p, err := net.SplitHostPort(s.Signer.Name())
	if err == nil {
		i, err := strconv.Atoi(p)
		if err != nil {
			log.Fatal(err)
		}
		s.name = net.JoinHostPort(h, strconv.Itoa(i+1))
	}
	s.Queue[s.READING] = make([]MustReplyMessage, 0)
	s.Queue[s.PROCESSING] = make([]MustReplyMessage, 0)
	s.closeChan = make(chan bool)
	return s
}

var clientNumber int = 0

// listen for clients connections
// this server needs to be running on a different port
// than the Signer that is beneath it
func (s *Server) Listen() error {
	// log.Println("Listening @ ", s.name)
	ln, err := net.Listen("tcp4", s.name)
	if err != nil {
		log.Println("failed to listen:", err)
		panic(err)
		//return err
	}

	go func() {
		for {
			// log.Println("LISTENING TO CLIENTS, ", s.name)
			conn, err := ln.Accept()
			if err != nil {
				// handle error
				log.Errorln("failed to accept connection")
				continue
			}
			if conn == nil {
				log.Errorln("!!!nil connection!!!")
			}

			c := coconet.NewTCPConnFromNet(conn)
			// log.Println("CLIENT TCP CONNECTION SUCCESSFULLY ESTABLISHED:", c)

			if _, ok := s.Clients[c.Name()]; !ok {
				s.Clients[c.Name()] = c

				go func(c coconet.Conn) {
					for {
						tsm := TimeStampMessage{}
						err := c.Get(&tsm)
						if err != nil {
							log.Errorln("Failed to get from child:", err)
							c.Close()
							return
						}
						switch tsm.Type {
						default:
							log.Errorf("Message of unknown type: %v\n", tsm.Type)
						case StampRequestType:
							// log.Println("RECEIVED STAMP REQUEST")
							s.mux.Lock()
							READING := s.READING
							s.Queue[READING] = append(s.Queue[READING],
								MustReplyMessage{Tsm: tsm, To: c.Name()})
							s.mux.Unlock()
						}
					}
				}(c)
			}

		}
	}()
	return nil
}

// should only be used if clients are created in batch
func (s *Server) ListenToClients() {
	for _, c := range s.Clients {
		go func(c coconet.Conn) {
			for {
				tsm := TimeStampMessage{}
				err := c.Get(&tsm)
				if err != nil {
					log.WithFields(log.Fields{
						"file": logutils.File(),
					}).Errorln("Failed To Get Message:", err)
				}
				switch tsm.Type {
				default:
					log.Errorln("Message of unknown type")
				case StampRequestType:
					// log.Println("STAMP REQUEST")
					s.mux.Lock()
					READING := s.READING
					s.Queue[READING] = append(s.Queue[READING],
						MustReplyMessage{Tsm: tsm, To: c.Name()})
					s.mux.Unlock()
				}
			}
		}(c)
	}
}

// Listen on client connections. If role is root also send annoucement
// for all of the nRounds
func (s *Server) Run(role string, nRounds int) {
	s.rLock.Lock()
	s.maxRounds = nRounds
	s.rLock.Unlock()
	switch role {

	case "root":
		// every 5 seconds start a new round
		ticker := time.Tick(ROUND_TIME * time.Second)
		for _ = range ticker {
			s.nRounds++
			if s.nRounds > nRounds {
				log.Errorln("exceeded the max round: terminating")
				break
			}

			start := time.Now()
			log.Println("stamp server starting signing round for:", s.nRounds)
			err := s.StartSigningRound()
			if err != nil {
				log.Errorln(err)
				return
			}

			lr := s.LastRound()
			if lr != s.nRounds {
				log.Errorln("Signer and Stamper rounds out of sync:")
				log.Errorln(strconv.Itoa(lr) + "," + strconv.Itoa(s.nRounds))
				return
			}

			elapsed := time.Since(start)
			log.WithFields(log.Fields{
				"file":  logutils.File(),
				"type":  "root_round",
				"round": s.nRounds,
				"time":  elapsed,
			}).Info("root round")
		}

	case "test":
		ticker := time.Tick(2000 * time.Millisecond)
		for _ = range ticker {
			s.AggregateCommits()
		}
	case "regular":
		// run until we close it
		<-s.closeChan
		log.WithFields(log.Fields{
			"file": logutils.File(),
			"type": "close",
		}).Infoln("server has closed")
	}

}

func (s *Server) OnAnnounce() coco.CommitFunc {
	return func() []byte {
		//log.Println("Aggregating Commits")
		return s.AggregateCommits()
	}
}

func (s *Server) OnDone() coco.DoneFunc {
	return func(SNRoot hashid.HashId, LogHash hashid.HashId, p proof.Proof) {
		//log.Println("calling OnDone")
		s.mux.Lock()
		for i, msg := range s.Queue[s.PROCESSING] {
			// proof to get from s.Root to big root
			combProof := make(proof.Proof, len(p))
			copy(combProof, p)

			// add my proof to get from a leaf message to my root s.Root
			combProof = append(combProof, s.Proofs[i]...)

			// proof that i can get from a leaf message to the big root
			if coco.DEBUG == true {
				proof.CheckProof(s.Signer.(*sign.Node).Suite().Hash, SNRoot, s.Leaves[i], combProof)
			}

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
	//log.Infoln("calling AggregateCommits")
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
		s.rLock.Lock()
		s.nRounds++
		mr := s.maxRounds
		s.rLock.Unlock()
		// if this is our last round then close the connections
		if s.nRounds >= mr && mr >= 0 {
			s.closeChan <- true
		}
	}

	// create Merkle tree for this round's messages and check corectness
	s.Root, s.Proofs = proof.ProofTree(s.Suite().Hash, s.Leaves)
	if coco.DEBUG == true {
		if proof.CheckLocalProofs(s.Suite().Hash, s.Root, s.Leaves, s.Proofs) == true {
			log.Println("Local Proofs of", s.name, "successful for round "+strconv.Itoa(s.nRounds))
		} else {
			panic("Local Proofs" + s.name + " unsuccessful for round " + strconv.Itoa(s.nRounds))
		}
	}

	return s.Root
}

// Send message to client given by name
func (s *Server) PutToClient(name string, data coconet.BinaryMarshaler) {
	err := s.Clients[name].Put(data)
	if err != nil && err != coconet.ConnectionNotEstablished {
		log.Warn("error putting to client:", err)
	}
}
