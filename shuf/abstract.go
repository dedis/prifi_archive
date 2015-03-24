package shuf

import (
	"time"
)

type NodeId struct {
	Physical int
	Virtual  int
}

type RouteInstr struct {
	To   *NodeId
	Msgs [][]byte
}

// Shuffle methods
type Shuffle interface {
	ShuffleStep(msg [][]byte, node NodeId, round int, inf *Info) []RouteInstr
	InitialNode(msg []byte, client int, inf *Info) NodeId
}

// Information collectively aggreed upon beforehand
type Info struct {
	NumNodes    int
	NumClients  int
	MsgSize     int
	NumRounds   int
	TotalTime   time.Duration
	ResendTime  time.Duration
	CollectTime time.Duration
}
