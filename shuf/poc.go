package shuf

import (
	"github.com/dedis/crypto/abstract"
	"math/rand"
)

// Identity shuffle
type IdShuffle struct{}

func (i IdShuffle) ShuffleStep(pairs Elgamal, node NodeId,
	round int, inf *Info) []RouteInstr {
	pairs = decryptPairs(pairs, inf, node.Physical)
	next := node.Physical + 1
	if next >= inf.NumNodes {
		return []RouteInstr{RouteInstr{nil, pairs}}
	} else {
		return []RouteInstr{RouteInstr{&NodeId{next, next}, pairs}}
	}
}

func (id IdShuffle) InitialNode(client int, inf *Info) NodeId {
	return NodeId{0, 0}
}

func (id IdShuffle) MergeGamal(apairs *Elgamal, bpairs Elgamal) *Elgamal {
	return defaultMergeGamal(apairs, bpairs)
}

// Random, but insecure shuffle
type DumbShuffle struct {
	Seed int64
}

func (d DumbShuffle) InitialNode(client int, inf *Info) NodeId {
	return NodeId{0, 0}
}

func (d DumbShuffle) ShuffleStep(pairs Elgamal, node NodeId,
	round int, inf *Info) []RouteInstr {
	newX := make([]abstract.Point, len(pairs.X))
	newY := make([]abstract.Point, len(pairs.Y))
	rand.Seed(d.Seed)
	p := rand.Perm(len(newX))
	for i := range p {
		newX[i] = pairs.X[p[i]]
		newY[i] = pairs.Y[p[i]]
	}
	newpairs := Elgamal{newX, newY, nil}
	newpairs = decryptPairs(newpairs, inf, node.Physical)

	next := node.Physical + 1
	if next >= inf.NumNodes {
		return []RouteInstr{RouteInstr{nil, newpairs}}
	} else {
		return []RouteInstr{RouteInstr{&NodeId{next, next}, newpairs}}
	}
}

func (id DumbShuffle) MergeGamal(apairs *Elgamal, bpairs Elgamal) *Elgamal {
	return defaultMergeGamal(apairs, bpairs)
}
