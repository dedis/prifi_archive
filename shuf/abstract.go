package shuf

import (
	"time"
)

type RouteInstr struct {
	To   *int
	Msgs [][]byte
}

// Shuffle methods
type Shuffle interface {
	ShuffleStep(msg [][]byte, node int, inf *Info) []RouteInstr
	InitialNode(msg []byte, client int, inf *Info) int
}

// Information collectively aggreed upon beforehand
type Info struct {
	NumNodes    int
	NumClients  int
	MsgSize     int
	NumRounds   int
	ResendTime  time.Duration
	CollectTime time.Duration
}
