package shuffle

import (
	"time"
)

// Any node that participates in the shuffle
// Nil newNode means end of shuffle
type Shuffler interface {
	ShuffleStep(msg [][]byte, node int, inf *SharedInfo) (
		newMsg [][]byte, newNode *int)
}

// Any node that forwards to a Shuffler (including clients)
// Empty node means it's sent from a client
// Empty result means it's the end of the protocol
type Crosser interface {
	NextNode(msg []byte, node *int, inf *SharedInfo) *int
}

// Information collectively aggreed upon beforehand
type SharedInfo struct {
	Seed       []byte
	NumNodes   int
	NumGroups  int
	NumRounds  int
	MsgSize    int
	ResendTime time.Duration
	RoundTime  time.Duration
}
