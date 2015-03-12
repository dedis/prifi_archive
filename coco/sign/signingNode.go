package sign

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"hash/fnv"
	"math/rand"
	"strconv"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/prifi/coco"
	"github.com/dedis/prifi/coco/coconet"
	"github.com/dedis/prifi/coco/hashid"
	"github.com/dedis/prifi/coco/test/logutils"
)

type Type int // used by other modules as sign.Type

const (
	// Default Signature involves creating Merkle Trees
	MerkleTree = iota
	// Basic Signature removes all Merkle Trees
	// Collective public keys are still created and can be used
	PubKey
)

var _ coco.Signer = &Node{}

type Node struct {
	coconet.Host

	// Signing Node will Fail at FailureRate probability
	FailureRate int
	Rand        *rand.Rand

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
	roundLock sync.RWMutex
	ComCh     map[int]chan *SigningMessage // a channel for each round's commits
	RmCh      map[int]chan *SigningMessage // a channel for each round's responses
	LogTest   []byte                       // for testing purposes
	peerKeys  map[string]abstract.Point    // map of all peer public keys

	closed      chan error // error sent when connection closed
	done        chan int   // round number sent when round done
	commitsDone chan int   // round number sent when announce/commit phase done

	timeout  time.Duration
	timeLock sync.RWMutex
}

func (sn *Node) SetFailureRate(v int) {
	sn.FailureRate = v
}

func (sn *Node) RegisterAnnounceFunc(cf coco.CommitFunc) {
	sn.CommitFunc = cf
}

func (sn *Node) RegisterDoneFunc(df coco.DoneFunc) {
	sn.DoneFunc = df
}

func (sn *Node) logFirstPhase(firstRoundTime time.Duration) {
	log.WithFields(log.Fields{
		"file":  logutils.File(),
		"type":  "root_announce",
		"round": sn.nRounds,
		"time":  firstRoundTime,
	}).Info("done with root announce round " + strconv.Itoa(sn.nRounds))
}

func (sn *Node) logSecondPhase(secondRoundTime time.Duration) {
	log.WithFields(log.Fields{
		"file":  logutils.File(),
		"type":  "root_challenge",
		"round": sn.nRounds,
		"time":  secondRoundTime,
	}).Info("done with root challenge round " + strconv.Itoa(sn.nRounds))
}

func (sn *Node) logTotalTime(totalTime time.Duration) {
	log.WithFields(log.Fields{
		"file":  logutils.File(),
		"type":  "root_challenge",
		"round": sn.nRounds,
		"time":  totalTime,
	}).Info("done with root challenge round " + strconv.Itoa(sn.nRounds))
}

var MAX_WILLING_TO_WAIT time.Duration = 50 * time.Second

func (sn *Node) StartSigningRound() error {
	// send an announcement message to all other TSServers
	sn.nRounds++
	log.Infoln("root starting signing round for round: ", sn.nRounds)

	first := time.Now()
	total := time.Now()
	var firstRoundTime time.Duration
	var totalTime time.Duration
	go func() {
		err := sn.Announce(0, &AnnouncementMessage{LogTest: []byte("New Round"), Round: sn.nRounds})
		if err != nil {
			log.Println("Signature fails if at least one node says it failed")
			log.Errorln(err)
		}
	}()

	// 1st Phase succeeded or connection error
	select {
	case rn := <-sn.commitsDone:
		// check for correctness
		if rn != sn.nRounds {
			log.Fatal("1st Phase round number mix up")
			return errors.New("1st Phase round number mix up")
		}

		// log time it took for first round to complete
		firstRoundTime = time.Since(first)
		sn.logFirstPhase(firstRoundTime)
		break

	case err := <-sn.closed:
		return err
	case <-time.After(MAX_WILLING_TO_WAIT):
		log.Fatal("Really bad. Round did not finish commit phase and did not report network errors." + strconv.Itoa(sn.nRounds))
		return errors.New("Really bad. Round did not finish commit phase and did not report network errors.")
	}

	// 2nd Phase succeeded or connection error
	select {
	case rn := <-sn.done:
		// check for correctness
		if rn != sn.nRounds {
			log.Fatal("2nd Phase round number mix up")
			return errors.New("2nd Phase round number mix up")
		}

		// log time it took for second round to complete
		totalTime = time.Since(total)
		sn.logSecondPhase(totalTime - firstRoundTime)
		sn.logTotalTime(totalTime)
		return nil
	case err := <-sn.closed:
		return err
	case <-time.After(MAX_WILLING_TO_WAIT):
		log.Fatal("Really bad. Round did not finish respond phase and did not report network errors.")
		return errors.New("Really bad. Round did not finish respond phase and did not report network errors.")
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

	sn.FailureRate = 0
	h := fnv.New32a()
	h.Write([]byte(hn.Name()))
	seed := h.Sum32()
	sn.Rand = rand.New(rand.NewSource(int64(seed)))
	sn.Host.SetSuite(suite)
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

	sn.FailureRate = 0
	h := fnv.New32a()
	h.Write([]byte(hn.Name()))
	seed := h.Sum32()
	sn.Rand = rand.New(rand.NewSource(int64(seed)))
	sn.Host.SetSuite(suite)
	return sn
}

func (sn *Node) ShouldIFail(phase string) bool {
	if sn.FailureRate > 0 {
		// If we were manually set to always fail
		if sn.Host.(*coconet.FaultyHost).IsDead() ||
			sn.Host.(*coconet.FaultyHost).IsDeadFor(phase) {
			// log.Println(sn.Name(), "dead for "+phase)
			return true
		}

		// If we were only given a probability of failing
		if p := sn.Rand.Int() % 100; p < sn.FailureRate {
			// log.Println(sn.Name(), "died for "+phase, "p", p, "with prob ", sn.FailureRate)
			return true
		}

	}

	return false
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

func (sn *Node) CommitedFor(round *Round) bool {
	if round.Log.v != nil {
		return true
	}
	return false
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
	sn.SetPool(p)
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

func (sn *Node) subExceptions(a abstract.Point, keys []abstract.Point) {
	for _, k := range keys {
		sn.sub(a, k)
	}
}

func (sn *Node) SetTimeout(t time.Duration) {
	sn.timeLock.Lock()
	sn.timeout = t
	sn.timeLock.Unlock()
}

func (sn *Node) Timeout() time.Duration {
	sn.timeLock.RLock()
	t := sn.timeout
	sn.timeLock.RUnlock()
	return t
}

func (sn *Node) DefaultTimeout() time.Duration {
	return 5 * time.Second
}

func max(a int, b int) int {
	if a > b {
		return a
	}
	return b
}
