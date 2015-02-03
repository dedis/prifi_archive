package sign

import (
	"bytes"
	"crypto/cipher"
	"log"
	"strconv"
	"sync"
	"time"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/prifi/coco/coconet"
	"github.com/dedis/prifi/coco/stamp"
)

var ROUND_TIME time.Duration = 1 * time.Second

type SigningNode struct {
	coconet.Host
	suite   abstract.Suite
	pubKey  abstract.Point  // long lasting public key
	privKey abstract.Secret // long lasting private key

	c abstract.Secret // round lasting challenge
	r abstract.Secret // round lasting response

	Log       SNLog // round lasting log structure
	HashedLog []byte

	r_hat abstract.Secret // aggregate of responses
	X_hat abstract.Point  // aggregate of public keys

	LogTest  []byte                    // for testing purposes
	peerKeys map[string]abstract.Point // map of all peer public keys

	clients map[string]*coconet.GoConn
	nRounds int

	// for aggregating messages from clients
	mux        sync.Mutex
	Queue      [][]stamp.MustReplyMessage
	READING    int
	PROCESSING int

	RespMessgs []stamp.MustReplyMessage // responses to client stamp requests
	Proofs     []stamp.Proof            // Proofs tailored specifically to clients

	// merkle tree roots
	LocalMTRoot stamp.HashId // local mt root of client messages
	MTRoot      stamp.HashId // mt root for subtree, passed upwards

	// merkle tree roots of children in strict order
	CMTRoots []stamp.HashId
}

func NewSigningNode(hn coconet.Host, suite abstract.Suite, random cipher.Stream) *SigningNode {
	sn := &SigningNode{Host: hn, suite: suite}
	sn.privKey = suite.Secret().Pick(random)
	sn.pubKey = suite.Point().Mul(nil, sn.privKey)
	sn.X_hat = suite.Point().Null()
	sn.peerKeys = make(map[string]abstract.Point)

	sn.clients = make(map[string]*coconet.GoConn)
	sn.Queue = make([][]stamp.MustReplyMessage, 2)
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
	sn.Queue = make([][]stamp.MustReplyMessage, 2)
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
	sn.mux.Lock()
	Queue := sn.Queue
	READING := sn.READING
	PROCESSING := sn.PROCESSING
	Queue[READING] = make([]stamp.MustReplyMessage, 0)
	Queue[PROCESSING] = make([]stamp.MustReplyMessage, 0)
	sn.mux.Unlock()
	for _, c := range sn.clients {
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
	leaves := make([]stamp.HashId, 0)
	for _, msg := range Queue[PROCESSING] {
		leaves = append(leaves, stamp.HashId(msg.Tsm.Sreq.Val))
	}
	sn.mux.Unlock()

	// non root servers keep track of rounds here
	if !sn.IsRoot() {
		sn.nRounds++
	}

	// create Merkle tree for this round
	mtRoot, proofs := stamp.ProofTree(sn.GetSuite().Hash, leaves)
	if stamp.CheckLocalProofs(sn.GetSuite().Hash, mtRoot, leaves, proofs) == true {
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
