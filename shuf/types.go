package shuf

import (
	"github.com/dedis/crypto/abstract"
	"time"
)

// Messages exchanged during a shuffle
type Msg struct {
	LeftProofs  []Proof
	RightProofs []Proof
	ShufProofs  []Proof
	X           []abstract.Point
	Y           []abstract.Point
	NewX        []abstract.Point
	Round       int
}

// Information collectively aggreed upon beforehand
type UserInfo struct {
	Suite        abstract.Suite
	PrivKey      func(int) abstract.Secret // restricted domain when networked
	PubKey       []abstract.Point
	NumNodes     int
	NumClients   int
	NumRounds    int
	ResendTime   time.Duration
	MsgsPerGroup int
}

// Information required to run the shuffle
type Info struct {
	UserInfo
	Routes      [][][]int             // (node, round) -> []to
	Active      [][]int               // node -> active rounds (collection rounds 2x)
	EncryptKeys [][][2]abstract.Point // (node, round / (2*neffLen)) -> left+right pubkeys
	GroupKeys   [][]abstract.Point    // (node, round / (2*neffLen)) -> group key
	NumGroups   int
	NeffLen     int
	Cache       Cache
}

// Proof of either a shuffle, decryption, or encryption
type Proof struct {
	X     []abstract.Point // old X
	Y     []abstract.Point // old Y
	Proof []byte
}

type Cache struct {
	X      []abstract.Point
	Y      []abstract.Point
	Proofs []Proof
}
