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
	Round       int32
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
	Timeout      time.Duration
}

// Information required to run the shuffle
// Implicitly, level = round / (2*neffLen)
type Info struct {
	UserInfo
	Routes      [][][]int             // (node, round) -> []to
	Active      [][]int32             // node -> active rounds
	EncryptKeys [][][2]abstract.Point // (groupid, level) -> left+right pubkeys
	GroupKeys   [][]abstract.Point    // (groupid, level) -> group key
	StartNodes  []int                 // client % numgroups -> node
	NodeGroup   [][]int               // (node, level) -> groupid
	NumGroups   int
	NeffLen     int
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
