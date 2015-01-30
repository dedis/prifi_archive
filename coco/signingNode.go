package coco

import (
	"bytes"
	"crypto/cipher"
	"log"
	"strconv"
	"sync"
	"time"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/prifi/coconet"
	"github.com/dedis/prifi/timestamp"
)

var ROUND_TIME time.Duration = 1 * time.Second

type SigningNode struct {
	coconet.Host
	suite   abstract.Suite
	pubKey  abstract.Point  // long lasting public key
	privKey abstract.Secret // long lasting private key

	c abstract.Secret // round lasting challenge
	r abstract.Secret // round lasting response

	Log SNLog // round lasting log structure

	r_hat abstract.Secret // aggregate of responses
	X_hat abstract.Point  // aggregate of public keys

	LogTest  []byte                    // for testing purposes
	peerKeys map[string]abstract.Point // map of all peer public keys

	clients map[string]*coconet.GoConn
	nRounds int

	// for aggregating messages from clients
	mux        sync.Mutex
	Queue      [][]timestamp.MustReplyMessage
	READING    int
	PROCESSING int

	// merkle tree roots
	LocalMTRoot timestamp.HashId // local mt root of client messages
	MTRoot      timestamp.HashId // mt root for subtree, passed upwards
}

func NewSigningNode(hn coconet.Host, suite abstract.Suite, random cipher.Stream) *SigningNode {
	sn := &SigningNode{Host: hn, suite: suite}
	sn.privKey = suite.Secret().Pick(random)
	sn.pubKey = suite.Point().Mul(nil, sn.privKey)
	sn.X_hat = suite.Point().Null()
	sn.peerKeys = make(map[string]abstract.Point)

	sn.clients = make(map[string]*coconet.GoConn)
	sn.Queue = make([][]timestamp.MustReplyMessage, 2)
	sn.READING = 0
	sn.PROCESSING = 1
	return sn
}

// Create new signing node that incorporates a given private key
func NewKeyedSigningNode(hn coconet.Host, suite abstract.Suite, privKey abstract.Secret) *SigningNode {
	sn := &SigningNode{Host: hn, suite: suite, privKey: privKey}
	sn.pubKey = suite.Point().Mul(nil, sn.privKey)
	sn.X_hat = suite.Point().Null()
	sn.peerKeys = make(map[string]abstract.Point)

	sn.clients = make(map[string]*coconet.GoConn)
	sn.Queue = make([][]timestamp.MustReplyMessage, 2)
	sn.READING = 0
	sn.PROCESSING = 1
	return sn
}

func (sn *SigningNode) addPeer(conn string, pubKey abstract.Point) {
	sn.Host.AddPeers(conn)
	sn.peerKeys[conn] = pubKey
}

func (sn *SigningNode) GetSuite() abstract.Suite {
	return sn.suite
}

// Listen on client connections. If role is root also send annoucement
// for all of the nRounds
func (sn *SigningNode) ListenToClients(role string, nRounds int) {
	Queue := sn.Queue
	READING := sn.READING
	PROCESSING := sn.PROCESSING

	Queue[READING] = make([]timestamp.MustReplyMessage, 0)
	Queue[PROCESSING] = make([]timestamp.MustReplyMessage, 0)
	for _, c := range sn.clients {
		go func(c *coconet.GoConn) {
			for {
				tsm := timestamp.TimeStampMessage{}
				c.Get(&tsm)
				log.Println("server got message round: ", tsm.ReqNo)
				switch tsm.Type {
				default:
					log.Println("Message of unknown type")
				case timestamp.StampRequestType:
					// fmt.Println(sn.Name(), " getting message")
					sn.mux.Lock()
					Queue[READING] = append(Queue[READING],
						timestamp.MustReplyMessage{Tsm: tsm, To: c.Name()})
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
			time.Sleep(1 * time.Second)
		}
	}

}

func (sn *SigningNode) AggregateCommits() ([]byte, []timestamp.Proof) {
	sn.mux.Lock()
	// get data from sn once to avoid refetching from structure
	Queue := sn.Queue
	READING := sn.READING
	PROCESSING := sn.PROCESSING

	// messages read will now be processed
	READING, PROCESSING = PROCESSING, READING
	Queue[READING] = Queue[READING][:0]

	// give up if nothing to process
	if len(Queue[PROCESSING]) == 0 {
		log.Println(sn.Name(), "no processing")
		sn.mux.Unlock()
		return make([]byte, 0), make([]timestamp.Proof, 0)
	}

	// pull out to be Merkle Tree leaves
	leaves := make([]timestamp.HashId, 0)
	for _, msg := range Queue[PROCESSING] {
		leaves = append(leaves, timestamp.HashId(msg.Tsm.Sreq.Val))
	}
	sn.mux.Unlock()

	// non root servers keep track of rounds here
	if !sn.IsRoot() {
		sn.nRounds++
	}

	// create Merkle tree for this round
	mtRoot, proofs := timestamp.ProofTree(sn.GetSuite().Hash, leaves)
	if timestamp.CheckProofs(sn.GetSuite().Hash, mtRoot, leaves, proofs) == true {
		log.Println("Local Proofs of", sn.Name(), "successful for round "+strconv.Itoa(sn.nRounds))
	} else {
		panic("Local Proofs" + sn.Name() + " unsuccessful for round " + strconv.Itoa(sn.nRounds))
	}

	sn.mux.Lock()
	// sending replies back to clients
	// log.Println("		Putting to clients")
	for i, msg := range Queue[PROCESSING] {
		log.Printf("sending back: %v\n", msg.Tsm.ReqNo)
		sn.PutToClient(msg.To,
			timestamp.TimeStampMessage{
				Type:  timestamp.StampReplyType,
				ReqNo: msg.Tsm.ReqNo,
				Srep:  &timestamp.StampReply{Sig: mtRoot, Prf: proofs[i]}})
	}
	// log.Println("		Done Putting to clients")
	sn.mux.Unlock()

	return mtRoot, proofs
}

// Send message to client given by name
func (sn *SigningNode) PutToClient(name string, data coconet.BinaryMarshaler) {
	sn.clients[name].Put(data)
}

// used for testing purposes
func (sn *SigningNode) Write(data interface{}) []byte {
	buf := bytes.Buffer{}
	abstract.Write(&buf, &data, sn.suite)
	return buf.Bytes()
}

// used for testing purposes
func (sn *SigningNode) Read(data []byte) (interface{}, error) {
	buf := bytes.NewBuffer(data)
	messg := TestMessage{}
	if err := abstract.Read(buf, &messg, sn.suite); err != nil {
		return nil, err
	}
	return messg, nil
}
