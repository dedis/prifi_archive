package shuf

import (
	"github.com/dedis/crypto/abstract"
	"time"
)

type Elgamal struct {
	X      []abstract.Point
	Y      []abstract.Point
	Shared abstract.Point
}

type NodeId struct {
	Physical int
	Virtual  int
}

type RouteInstr struct {
	To    *NodeId
	Pairs Elgamal
}

// Shuffle methods
type Shuffle interface {
	ShuffleStep(pairs Elgamal,
		node NodeId, round int, inf *Info) []RouteInstr
	InitialNode(client int, inf *Info) NodeId
	MergeGamal(apairs *Elgamal, bpairs Elgamal) *Elgamal
}

// Information collectively aggreed upon beforehand
type Info struct {
	Suite       abstract.Suite
	PrivKey     func(int) abstract.Secret // restricted domain when networked
	NumNodes    int
	NumClients  int
	MsgSize     int
	NumRounds   int
	TotalTime   time.Duration
	ResendTime  time.Duration
	CollectTime time.Duration
}

func defaultMergeGamal(apairs *Elgamal, bpairs Elgamal) *Elgamal {
	if apairs == nil {
		return &bpairs
	} else {
		newgamal := new(Elgamal)
		newgamal.X = append(apairs.X, bpairs.X...)
		newgamal.Y = append(apairs.Y, bpairs.Y...)
		newgamal.Shared = bpairs.Shared
		return newgamal
	}
}

func decryptPairs(pairs Elgamal, inf *Info, node int) Elgamal {
	negKey := inf.Suite.Secret().Neg(inf.PrivKey(node))
	for i := range pairs.X {
		pairs.Y[i] = inf.Suite.Point().Add(inf.Suite.Point().Mul(pairs.X[i], negKey), pairs.Y[i])
	}
	if pairs.Shared != nil {
		pairs.Shared = inf.Suite.Point().Add(inf.Suite.Point().Mul(nil, negKey), pairs.Shared)
	}
	return pairs
}
