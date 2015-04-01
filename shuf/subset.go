package shuf

import (
	"fmt"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/proof"
	"github.com/dedis/crypto/shuffle"
	"math/rand"
)

type SubsetShuffle struct {
	Directions []int
}

func NewSubsetShuffle(seed int64, size int, total int) *SubsetShuffle {
	s := new(SubsetShuffle)
	s.Directions = make([]int, size)
	rand.Seed(seed)
	p := deal(total, size)
	for i := range p {
		if i < size-1 {
			s.Directions[p[i]] = p[i+1]
		} else {
			s.Directions[p[i]] = -1
		}
	}
	return s
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

	p := s.Directions[node]
	if p > 0 {
		instr.To = []int{p}
	}
	return instr
}

func (s SubsetShuffle) InitialNode(client int, inf *Info) int {
	return 0
}

func (s SubsetShuffle) VerifyShuffle(newPairs, oldPairs Elgamal,
	H abstract.Point, inf *Info, prf []byte) error {
	verifier := shuffle.Verifier(inf.Suite, nil, H, oldPairs.X, oldPairs.Y, newPairs.X, newPairs.Y)
	return proof.HashVerify(inf.Suite, "PairShuffle", verifier, prf)
}
