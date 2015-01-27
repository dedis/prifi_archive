package coco

import (
	"bytes"
	"crypto/cipher"
	"fmt"
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

	v abstract.Secret // round lasting secret
	V abstract.Point  // round lasting commitment point
	c abstract.Secret // round lasting challenge
	r abstract.Secret // round lasting response

	V_hat abstract.Point  // aggregate of commit points
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
}

func NewSigningNode(hn coconet.Host, suite abstract.Suite, random cipher.Stream) *SigningNode {
	sn := &SigningNode{Host: hn, suite: suite}
	sn.privKey = suite.Secret().Pick(random)
	sn.pubKey = suite.Point().Mul(nil, sn.privKey)
	sn.X_hat = suite.Point().Null()
	sn.peerKeys = make(map[string]abstract.Point)

	sn.clients = make(map[string]*coconet.GoConn)
	sn.READING = 0
	sn.PROCESSING = 1
	return sn
}

func NewKeyedSigningNode(hn coconet.Host, suite abstract.Suite, privKey abstract.Secret) *SigningNode {
	sn := &SigningNode{Host: hn, suite: suite, privKey: privKey}
	sn.pubKey = suite.Point().Mul(nil, sn.privKey)
	sn.X_hat = suite.Point().Null()
	sn.peerKeys = make(map[string]abstract.Point)

	sn.clients = make(map[string]*coconet.GoConn)
	sn.READING = 0
	sn.PROCESSING = 1
	return sn
}

func (sn *SigningNode) addPeer(conn string, pubKey abstract.Point) {
	sn.Host.AddPeers(conn)
	sn.peerKeys[conn] = pubKey
}

func (sn *SigningNode) Write(data interface{}) []byte {
	buf := bytes.Buffer{}
	abstract.Write(&buf, &data, sn.suite)
	return buf.Bytes()
}

func (sn *SigningNode) Read(data []byte) (interface{}, error) {
	buf := bytes.NewBuffer(data)
	messg := TestMessage{}
	if err := abstract.Read(buf, &messg, sn.suite); err != nil {
		return nil, err
	}
	return messg, nil
}

func (sn *SigningNode) GetSuite() abstract.Suite {
	return sn.suite
}

func (sn *SigningNode) ListenToClients(role string) {
	sn.Queue = make([][]timestamp.MustReplyMessage, 2)
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

				switch tsm.Type {
				default:
					fmt.Println("Message of unknown type")
				case timestamp.StampRequestType:
					// fmt.Println("TSServer getting message", tsm)
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
		ticker := time.Tick(1 * time.Second)
		for _ = range ticker {
			// send an announcement message to all other TSServers
			sn.Announce(&AnnouncementMessage{LogTest: []byte("New Round")})
			sn.AggregateCommits()
		}

	case "test":
		ticker := time.Tick(1 * time.Second)
		for _ = range ticker {
			sn.AggregateCommits()
		}
	}

}

func (sn *SigningNode) AggregateCommits() {
	sn.mux.Lock()
	// get data from s once
	Queue := sn.Queue
	READING := sn.READING
	PROCESSING := sn.PROCESSING

	READING, PROCESSING = PROCESSING, READING
	Queue[READING] = Queue[READING][:0]

	// give up if nothing to process
	if len(Queue[PROCESSING]) == 0 {
		return
	}

	// count only productive rounds
	sn.nRounds++

	// pull out to be Merkle Tree leaves
	leaves := make([]timestamp.HashId, 0)
	for _, msg := range Queue[PROCESSING] {
		leaves = append(leaves, timestamp.HashId(msg.Tsm.Sreq.Val))
	}
	sn.mux.Unlock()

	// create Merkle tree for this round
	mtRoot, proofs := timestamp.ProofTree(sn.GetSuite().Hash, leaves)
	if timestamp.CheckProofs(sn.GetSuite().Hash, mtRoot, leaves, proofs) == true {
		fmt.Println("Proofs successful for round " + strconv.Itoa(sn.nRounds))
	} else {
		panic("Proofs unsuccessful for round " + strconv.Itoa(sn.nRounds))
	}

	sn.mux.Lock()
	// sending replies back to clients
	for i, msg := range Queue[PROCESSING] {
		sn.PutToClient(msg.To,
			timestamp.TimeStampMessage{
				Type:  timestamp.StampReplyType,
				ReqNo: msg.Tsm.ReqNo,
				Srep:  &timestamp.StampReply{Sig: mtRoot, Prf: proofs[i]}})
	}
	sn.mux.Unlock()
}

func (sn *SigningNode) PutToClient(name string, data coconet.BinaryMarshaler) {
	sn.clients[name].Put(data)
}
