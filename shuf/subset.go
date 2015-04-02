package shuf

import (
	"fmt"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/proof"
	"github.com/dedis/crypto/shuffle"
	"math/rand"
)

type SubsetShuffle struct {
	directions []int // map from node to next node (-1 means end)
	rounds     []int // map from node to round responsibility (or -1)
	flow       []int // path through the nodes
	start      int   //starting node
}

func NewSubsetShuffle(seed int64, size int, total int) *SubsetShuffle {
	s := new(SubsetShuffle)
	s.directions = make([]int, total)
	s.rounds = make([]int, total)
	for r := range s.rounds {
		s.rounds[r] = -1
	}
	rand.Seed(seed)
	s.flow = deal(total, size)
	s.start = s.flow[0]
	for i, ip := range s.flow {
		s.rounds[ip] = i
		if i < size-1 {
			s.directions[ip] = s.flow[i+1]
		} else {
			s.directions[ip] = -1
		}
	}
	return s
}

func (s SubsetShuffle) ActiveRounds(node int, inf *Info) []int {
	if s.rounds[node] >= 0 {
		return []int{s.rounds[node]}
	} else {
		return nil
	}
}

func (s SubsetShuffle) ShuffleStep(pairs Elgamal,
	node int, round int, inf *Info, H abstract.Point) RouteInstr {

	c := inf.Suite.Cipher(nil)
	xx, yy, prover := shuffle.Shuffle(inf.Suite, nil, H, pairs.X, pairs.Y, c)
	prf, err := proof.HashProve(inf.Suite, "PairShuffle", c, prover)
	if err != nil {
		fmt.Printf("Error creating proof: %s\n", err.Error())
	}
	pairs.X = xx
	pairs.Y = yy
	pairs, H = decryptPairs(pairs, inf, node, H)
	instr := RouteInstr{Pairs: pairs, H: H, Proof: prf}

	p := s.directions[node]
	if p > 0 {
		instr.To = []int{p}
	}
	return instr
}

func (s SubsetShuffle) Setup(msg abstract.Point, client int,
	inf *Info) (Elgamal, abstract.Point, int) {
	X, Y, H := onionEncrypt([]abstract.Point{msg}, inf, s.flow)
	elg := Elgamal{X, Y}
	return elg, H, s.start
}

func (s SubsetShuffle) VerifyShuffle(newPairs, oldPairs Elgamal,
	H abstract.Point, inf *Info, prf []byte) error {
	verifier := shuffle.Verifier(inf.Suite, nil, H, oldPairs.X, oldPairs.Y, newPairs.X, newPairs.Y)
	return proof.HashVerify(inf.Suite, "PairShuffle", verifier, prf)
}
