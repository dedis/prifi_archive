package shuf

import (
	"github.com/dedis/crypto/shuffle"
	"math/rand"
)

func NewSubsetShuffle(seed int64, size int) *SubsetShuffle {
	s := new(SubsetShuffle)
	s.Directions = make([]int, size)
	rand.Seed(seed)
	p := rand.Perm(size)
	for i := range p {
		if i < size-1 {
			s.Directions[p[i]] = p[i+1]
		} else {
			s.Directions[p[i]] = -1
		}
	}
	return s
}

type SubsetShuffle struct {
	Directions []int
}

func (s SubsetShuffle) ShuffleStep(pairs Elgamal,
	node NodeId, round int, inf *Info) []RouteInstr {

	xx, yy, _ := shuffle.Shuffle(inf.Suite, nil, pairs.Shared, pairs.X, pairs.Y, inf.Suite.Cipher(nil))
	pairs.X = xx
	pairs.Y = yy
	pairs = decryptPairs(pairs, inf, node.Physical)

	p := s.Directions[node.Physical]
	if p > 0 {
		return []RouteInstr{RouteInstr{&NodeId{p, p}, pairs}}
	} else {
		return []RouteInstr{RouteInstr{nil, pairs}}
	}
}

func (id SubsetShuffle) InitialNode(client int, inf *Info) NodeId {
	return NodeId{0, 0}
}

func (id SubsetShuffle) MergeGamal(apairs *Elgamal, bpairs Elgamal) *Elgamal {
	return defaultMergeGamal(apairs, bpairs)
}
