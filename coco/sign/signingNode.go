package sign

import (
	"bytes"
	"crypto/cipher"
	"time"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/prifi/coco/coconet"
	"github.com/dedis/prifi/coco/hashid"
)

var ROUND_TIME time.Duration = 1 * time.Second

type SigningNode struct {
	coconet.Host
	suite   abstract.Suite
	PubKey  abstract.Point  // long lasting public key
	PrivKey abstract.Secret // long lasting private key

	c abstract.Secret // round lasting challenge
	r abstract.Secret // round lasting response

	Log       SNLog // round lasting log structure
	HashedLog []byte

	r_hat abstract.Secret // aggregate of responses
	X_hat abstract.Point  // aggregate of public keys

	LogTest  []byte                    // for testing purposes
	peerKeys map[string]abstract.Point // map of all peer public keys

	nRounds int

	// own big merkle subtree root
	MTRoot hashid.HashId // mt root for subtree, passed upwards

	// merkle tree roots of children in strict order
	CMTRoots []hashid.HashId
}

func NewSigningNode(hn coconet.Host, suite abstract.Suite, random cipher.Stream) *SigningNode {
	sn := &SigningNode{Host: hn, suite: suite}
	sn.PrivKey = suite.Secret().Pick(random)
	sn.PubKey = suite.Point().Mul(nil, sn.PrivKey)
	sn.X_hat = suite.Point().Null()
	sn.peerKeys = make(map[string]abstract.Point)

	return sn
}

// Create new signing node that incorporates a given private key
func NewKeyedSigningNode(hn coconet.Host, suite abstract.Suite, PrivKey abstract.Secret) *SigningNode {
	sn := &SigningNode{Host: hn, suite: suite, PrivKey: PrivKey}
	sn.PubKey = suite.Point().Mul(nil, sn.PrivKey)
	sn.X_hat = suite.Point().Null()
	sn.peerKeys = make(map[string]abstract.Point)

	return sn
}

func (sn *SigningNode) AddPeer(conn string, PubKey abstract.Point) {
	sn.Host.AddPeers(conn)
	sn.peerKeys[conn] = PubKey
}

func (sn *SigningNode) GetSuite() abstract.Suite {
	return sn.suite
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
