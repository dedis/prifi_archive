package shuf

import (
	"github.com/dedis/crypto/abstract"
	"math/rand"
)

// Identity shuffle
type IdShuffle struct{}

func (id IdShuffle) ShuffleStep(pairs Elgamal, node int,
	round int, inf *Info, H abstract.Point) RouteInstr {
	newY, _, _, err := DecryptPairs(pairs, inf, node, H)
	if err != nil {
		panic(err.Error())
	}
	instr := RouteInstr{NewPairs: Elgamal{pairs.X, newY}}
	next := node + 1
	if next < inf.NumNodes {
		instr.To = []int{next}
	}
	return instr
}

func (id IdShuffle) Setup(msg abstract.Point, client int,
	inf *Info) (Elgamal, abstract.Point, int) {
	X, Y, H := OnionEncrypt([]abstract.Point{msg}, inf, xrange(inf.NumNodes))
	elg := Elgamal{X, Y}
	return elg, H, 0
}

func (id IdShuffle) ActiveRounds(node int, inf *Info) []int {
	return []int{node}
}

// Random, but unverified shuffle
type DumbShuffle struct {
	Seed int64
}

func (d DumbShuffle) Setup(msg abstract.Point, client int,
	inf *Info) (Elgamal, abstract.Point, int) {
	X, Y, H := OnionEncrypt([]abstract.Point{msg}, inf, xrange(inf.NumNodes))
	elg := Elgamal{X, Y}
	return elg, H, 0
}

func (d DumbShuffle) ShuffleStep(pairs Elgamal, node int,
	round int, inf *Info, H abstract.Point) RouteInstr {

	// Create new pairs from a random permutation
	X := make([]abstract.Point, len(pairs.X))
	Y := make([]abstract.Point, len(pairs.Y))
	rand.Seed(d.Seed)
	p := rand.Perm(len(pairs.X))
	for i := range p {
		X[i] = pairs.X[p[i]]
		Y[i] = pairs.Y[p[i]]
	}
	shufPairs := Elgamal{X, Y}
	pairs.Y, _, _, _ = DecryptPairs(shufPairs, inf, node, H)
	pairs.X = X

	// Direct it to the next in line
	instr := RouteInstr{NewPairs: pairs}
	next := node + 1
	if next < inf.NumNodes {
		instr.To = []int{next}
	}
	return instr
}

func (d DumbShuffle) ActiveRounds(node int, inf *Info) []int {
	return []int{node}
}
