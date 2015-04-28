package shuf

import (
	"github.com/dedis/crypto/abstract"
	"time"
)

// Messages exchanged during a shuffle
type Msg struct {
	LeftProofs  []DecProof
	RightProofs []DecProof
	ShufProofs  []ShufProof
	SplitProof  *SplitProof
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
	MaxResends   int
	Split        Splitter
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

// Record of division between halves
type SplitProof struct {
	X []abstract.Point // old X
	Y []abstract.Point // old Y
}

// Proof of decryption and re-encryption
type DecProof struct {
	Y     []abstract.Point // old Y
	Proof [][]byte         // proofs that new Y comes from old Y

}

// Proof of a shuffle
type ShufProof struct {
	X     []abstract.Point // old X
	Y     []abstract.Point // old Y
	Proof []byte
}

// Data stored between rounds
type Cache struct {
	NewX   []abstract.Point // stored NewX
	X      []abstract.Point // stored X
	Y      []abstract.Point // stored Y
	Proofs []DecProof       // stored proof
}
