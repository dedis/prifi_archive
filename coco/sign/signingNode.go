package sign

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/prifi/coco"
	"github.com/dedis/prifi/coco/coconet"
	"github.com/dedis/prifi/coco/hashid"
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

	nRounds       int
	Rounds        map[int]*Round
	Round         int // *only* used by Root( by annoucer)
	LastSeenRound int // largest round number I have seen

	CommitFunc coco.CommitFunc
	DoneFunc   coco.DoneFunc

	// NOTE: reuse of channels via round-number % Max-Rounds-In-Mermory can be used
	roundLock sync.Mutex
	ComCh     map[int]chan *SigningMessage // a channel for each round's commits
	RmCh      map[int]chan *SigningMessage // a channel for each round's responses
	LogTest   []byte                       // for testing purposes
	peerKeys  map[string]abstract.Point    // map of all peer public keys

	closed      chan error // error sent when connection closed
	done        chan int   // round number sent when round done
	commitsDone chan int   // round number sent when announce/commit phase done
}

func (sn *Node) RegisterAnnounceFunc(cf coco.CommitFunc) {
	sn.CommitFunc = cf
}

func (sn *Node) RegisterDoneFunc(df coco.DoneFunc) {
	sn.DoneFunc = df
}

func (sn *Node) StartSigningRound() error {
	// send an announcement message to all other TSServers
	sn.nRounds++
	log.Infoln("root starting signing round for round: ", sn.nRounds)

	go func() {
		sn.Announce(&AnnouncementMessage{LogTest: []byte("New Round"), Round: sn.nRounds})
	}()

	// 1st Phase succeeded or connection error
	select {
	case rn := <-sn.commitsDone:
		if rn != sn.nRounds {
			log.Fatal("1st Phase round number mix up")
			return errors.New("1st Phase round number mix up")
		}
		break
	case err := <-sn.closed:
		return err
	}

	// 2nd Phase succeeded or connection error
	select {
	case rn := <-sn.done:
		if rn != sn.nRounds {
			log.Fatal("2nd Phase round number mix up")
			return errors.New("2nd Phase round number mix up")
		}
		return nil
	case err := <-sn.closed:
		return err
	}
}

func NewNode(hn coconet.Host, suite abstract.Suite, random cipher.Stream) *Node {
	sn := &Node{Host: hn, suite: suite}
	sn.PrivKey = suite.Secret().Pick(random)
	sn.PubKey = suite.Point().Mul(nil, sn.PrivKey)

	sn.peerKeys = make(map[string]abstract.Point)
	sn.ComCh = make(map[int]chan *SigningMessage, 0)
	sn.RmCh = make(map[int]chan *SigningMessage, 0)
	sn.Rounds = make(map[int]*Round)

	sn.closed = make(chan error, 2)
	sn.done = make(chan int, 10)
	sn.commitsDone = make(chan int, 10)

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

	sn.closed = make(chan error, 2)
	sn.done = make(chan int, 10)
	sn.commitsDone = make(chan int, 10)

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

func (sn *Node) Done() chan int {
	return sn.done
}

func (sn *Node) LastRound() int {
	return sn.LastSeenRound
}

func intToByteSlice(Round int) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, Round)
	return buf.Bytes()
}

// *only* called by root node
func (sn *Node) SetAccountableRound(Round int) {
	// Create my back link to previous round
	sn.SetBackLink(Round)

	h := sn.suite.Hash()
	h.Write(intToByteSlice(Round))
	h.Write(sn.Rounds[Round].BackLink)
	sn.Rounds[Round].AccRound = h.Sum(nil)

	// here I could concatenate sn.Round after the hash for easy keeping track of round
	// todo: check this
}

func (sn *Node) UpdateTimeout(t ...time.Duration) {
	if len(t) > 0 {
		sn.SetTimeout(t[0])
	} else {
		tt := time.Duration(sn.Height)*sn.DefaultTimeout() + sn.DefaultTimeout()
		sn.SetTimeout(tt)
	}
}

func (sn *Node) SetBackLink(Round int) {
	prevRound := Round - 1
	sn.Rounds[Round].BackLink = hashid.HashId(make([]byte, hashid.Size))
	if prevRound >= FIRST_ROUND {
		// My Backlink = Hash(prevRound, sn.Rounds[prevRound].BackLink, sn.Rounds[prevRound].MTRoot)
		h := sn.suite.Hash()
		h.Write(intToByteSlice(prevRound))
		h.Write(sn.Rounds[prevRound].BackLink)
		h.Write(sn.Rounds[prevRound].MTRoot)
		sn.Rounds[Round].BackLink = h.Sum(nil)
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

func max(a int, b int) int {
	if a > b {
		return a
	}
	return b
}
