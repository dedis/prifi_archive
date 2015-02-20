package sign

import (
	"crypto/cipher"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/prifi/coco"
	"github.com/dedis/prifi/coco/coconet"
)

var ROUND_TIME time.Duration = 1 * time.Second

type Type int // used by other modules as sign.Type

const (
	// Default Signature involves creating Merkle Trees
	MerkleTree = iota
	// Basic Signature removes all Merkle Trees
	// Collective public keys are still created and can be used
	PubKey
)

type Node struct {
	coconet.Host

	// Set to true if FaultyHosts are used instead of Hosts
	// Signing Node must test this field to know if it must simulate failure
	TestingFailures bool // false by default

	Type   Type
	Height int

	suite   abstract.Suite
	PubKey  abstract.Point  // long lasting public key
	PrivKey abstract.Secret // long lasting private key

	nRounds int
	Rounds  map[int]*Round
	Round   int // *only* used by Root( by annoucer)

	CommitFunc coco.CommitFunc
	DoneFunc   coco.DoneFunc

	// NOTE: reuse of channels via round-number % Max-Rounds-In-Mermory can be used
	roundLock sync.Mutex
	ComCh     map[int]chan *SigningMessage // a channel for each round's commits
	RmCh      map[int]chan *SigningMessage // a channel for each round's responses
	LogTest   []byte                       // for testing purposes
	peerKeys  map[string]abstract.Point    // map of all peer public keys
}

func (sn *Node) RegisterAnnounceFunc(cf coco.CommitFunc) {
	sn.CommitFunc = cf
}

func (sn *Node) RegisterDoneFunc(df coco.DoneFunc) {
	sn.DoneFunc = df
}

func (sn *Node) StartSigningRound() {
	// send an announcement message to all other TSServers
	log.Println("I", sn.Name(), "Sending an annoucement")
	sn.Announce(&AnnouncementMessage{LogTest: []byte("New Round"), Round: sn.nRounds})
	sn.nRounds++
}

func NewNode(hn coconet.Host, suite abstract.Suite, random cipher.Stream) *Node {
	sn := &Node{Host: hn, suite: suite}
	sn.PrivKey = suite.Secret().Pick(random)
	sn.PubKey = suite.Point().Mul(nil, sn.PrivKey)

	sn.peerKeys = make(map[string]abstract.Point)
	sn.ComCh = make(map[int]chan *SigningMessage, 0)
	sn.RmCh = make(map[int]chan *SigningMessage, 0)
	sn.Rounds = make(map[int]*Round)

	sn.TestingFailures = false
	return sn
}

// Create new signing node that incorporates a given private key
func NewKeyedNode(hn coconet.Host, suite abstract.Suite, PrivKey abstract.Secret) *Node {
	sn := &Node{Host: hn, suite: suite, PrivKey: PrivKey}
	sn.PubKey = suite.Point().Mul(nil, sn.PrivKey)

	sn.peerKeys = make(map[string]abstract.Point)
	sn.ComCh = make(map[int]chan *SigningMessage, 0)
	sn.RmCh = make(map[int]chan *SigningMessage, 0)
	sn.Rounds = make(map[int]*Round)

	sn.TestingFailures = false
	return sn
}

func (sn *Node) AddPeer(conn string, PubKey abstract.Point) {
	sn.Host.AddPeers(conn)
	sn.peerKeys[conn] = PubKey
}

func (sn *Node) Suite() abstract.Suite {
	return sn.suite
}

func (sn *Node) UpdateTimeout(t ...time.Duration) {
	if len(t) > 0 {
		sn.SetTimeout(t[0])
	} else {
		tt := time.Duration(sn.Height)*sn.DefaultTimeout() + 1000*time.Millisecond
		sn.SetTimeout(tt)
	}
}

func (sn *Node) setPool() {
	var p sync.Pool
	p.New = NewSigningMessage
	sn.Host.SetPool(p)
}

// accommodate nils
func (sn *Node) add(a abstract.Point, b abstract.Point) {
	if a == nil {
		a = sn.suite.Point().Null()
	}
	if b != nil {
		a.Add(a, b)
	}

}

// accommodate nils
func (sn *Node) sub(a abstract.Point, b abstract.Point) {
	if a == nil {
		a = sn.suite.Point().Null()
	}
	if b != nil {
		a.Sub(a, b)
	}

}
