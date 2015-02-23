package shuf

import (
	"time"
)

// Shuffle methods
type Shuffle interface {
	ShuffleStep(msg [][]byte, node int, inf *Info) (newMsg [][]byte, newNode *int)
	InitialNode(msg []byte, inf *Info) int
}

// Information collectively aggreed upon beforehand
type Info struct {
	Seed       int64
	NumNodes   int
	NumGroups  int
	NumRounds  int
	MsgSize    int
	ResendTime time.Duration
	RoundTime  time.Duration
}
