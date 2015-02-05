package stamp

import (
	"log"
	"strconv"
	"sync"
	"time"

	"github.com/dedis/prifi/coco/hashid"
	"github.com/dedis/prifi/coco/proof"
)

type Server struct {
	Clients map[string]*coconet.GoConn

	// for aggregating messages from clients
	mux        sync.Mutex
	Queue      [][]stamp.MustReplyMessage
	READING    int
	PROCESSING int

	RespMessgs []stamp.MustReplyMessage // responses to client stamp requests
	Proofs     []proof.Proof            // Proofs tailored specifically to clients

	// merkle tree roots
	LocalMTRoot hashid.HashId // local mt root of client messages

}

// Returns commitment contribution for a round
type CommitFunc func() []byte

// Called at the end of a round
// Allows client of Signer to receive signature, proof, and error via RPC
type DoneFunc func(signature hashid.HashId, proof proof.Proof, err error)

// todo: see where Signer should be located
type Signer interface {
	// proof can be nil for simple non Merkle Tree signatures
	// could add option field for Sign
	Sign([]byte) (hashid.HashId, proof.Proof, error)

	// registers a commitment function to be called
	// at the start of every round
	OnAnnounce(cf CommitFunc)

	OnDone(df DoneFunc)
}

func NewServer(signer Signer) *Server {
	sn := &Server{}

	sn.Clients = make(map[string]*coconet.GoConn)
	sn.Queue = make([][]stamp.MustReplyMessage, 2)
	sn.READING = 0
	sn.PROCESSING = 1
	return sn
}

// Listen on client connections. If role is root also send annoucement
// for all of the nRounds
func (sn *SigningNode) ListenToClients(role string, nRounds int) {
	sn.mux.Lock()
	Queue := sn.Queue
	READING := sn.READING
	PROCESSING := sn.PROCESSING
	Queue[READING] = make([]stamp.MustReplyMessage, 0)
	Queue[PROCESSING] = make([]stamp.MustReplyMessage, 0)
	sn.mux.Unlock()
	for _, c := range sn.Clients {
		go func(c *coconet.GoConn) {
			for {
				tsm := stamp.TimeStampMessage{}
				c.Get(&tsm)
				switch tsm.Type {
				default:
					log.Println("Message of unknown type")
				case stamp.StampRequestType:
					// fmt.Println(sn.Name(), " getting message")
					sn.mux.Lock()
					READING := sn.READING
					Queue[READING] = append(Queue[READING],
						stamp.MustReplyMessage{Tsm: tsm, To: c.Name()})
					sn.mux.Unlock()
				}
			}
		}(c)
	}
	switch role {

	case "root":
		// count only productive rounds
		ticker := time.Tick(250 * time.Millisecond)
		for _ = range ticker {
			sn.nRounds++
			if sn.nRounds > nRounds {
				continue
			}
			// send an announcement message to all other TSServers
			log.Println("I", sn.Name(), "Sending an annoucement")
			sn.Announce(&AnnouncementMessage{LogTest: []byte("New Round")})

		}

	case "test":
		ticker := time.Tick(250 * time.Millisecond)
		for _ = range ticker {
			sn.AggregateCommits()
		}
	case "regular":
		for {
			time.Sleep(100 * time.Millisecond)
		}
	}

}

func (sn *SigningNode) AggregateCommits() ([]byte, []stamp.MustReplyMessage) {
	sn.mux.Lock()
	// get data from sn once to avoid refetching from structure
	Queue := sn.Queue
	READING := sn.READING
	PROCESSING := sn.PROCESSING
	// messages read will now be processed
	READING, PROCESSING = PROCESSING, READING
	sn.READING, sn.PROCESSING = sn.PROCESSING, sn.READING
	sn.Queue[READING] = sn.Queue[READING][:0]

	// give up if nothing to process
	if len(Queue[PROCESSING]) == 0 {
		sn.mux.Unlock()
		return make([]byte, HASH_SIZE), make([]stamp.MustReplyMessage, 0)
	}

	// pull out to be Merkle Tree leaves
	leaves := make([]hashid.HashId, 0)
	for _, msg := range Queue[PROCESSING] {
		leaves = append(leaves, hashid.HashId(msg.Tsm.Sreq.Val))
	}
	sn.mux.Unlock()

	// non root servers keep track of rounds here
	if !sn.IsRoot() {
		sn.nRounds++
	}

	// create Merkle tree for this round
	mtRoot, proofs := proof.ProofTree(sn.GetSuite().Hash, leaves)
	if proof.CheckLocalProofs(sn.GetSuite().Hash, mtRoot, leaves, proofs) == true {
		log.Println("Local Proofs of", sn.Name(), "successful for round "+strconv.Itoa(sn.nRounds))
	} else {
		panic("Local Proofs" + sn.Name() + " unsuccessful for round " + strconv.Itoa(sn.nRounds))
	}

	sn.mux.Lock()
	respMessgs := make([]stamp.MustReplyMessage, 0)
	for i, msg := range Queue[PROCESSING] {
		respMessgs = append(respMessgs,
			stamp.MustReplyMessage{
				To: msg.To,
				Tsm: stamp.TimeStampMessage{
					Type:  stamp.StampReplyType,
					ReqNo: msg.Tsm.ReqNo,
					Srep:  &stamp.StampReply{Sig: mtRoot, Prf: proofs[i]}}})
	}
	sn.mux.Unlock()

	return mtRoot, respMessgs
}

// Send message to client given by name
func (sn *SigningNode) PutToClient(name string, data coconet.BinaryMarshaler) {
	sn.Clients[name].Put(data)
}
