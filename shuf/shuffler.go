package shuf

import (
	"fmt"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/proof"
	"github.com/dedis/crypto/shuffle"
)

// Generic interface for methods of dividing pairs in two halves
type Shuffler interface {
	Shuffle(x, y []abstract.Point, h abstract.Point) ([]abstract.Point, []abstract.Point, ShufProof)
	Verify(h abstract.Point, x, y, xbar, ybar []abstract.Point, p []byte) error
}

// Neff Shuffle
type Neff struct {
	Inf *Info
}

func (n Neff) Verify(h abstract.Point, x, y, xbar, ybar []abstract.Point, p []byte) error {
	verifier := shuffle.Verifier(n.Inf.Suite, nil, h, x, y, xbar, ybar)
	return proof.HashVerify(n.Inf.Suite, "PairShuffle", verifier, p)
}

// Perform a Neff shuffle and prove it
func (n Neff) Shuffle(x, y []abstract.Point, h abstract.Point) (
	[]abstract.Point, []abstract.Point, ShufProof) {
	rnd := n.Inf.Suite.Cipher(abstract.RandomKey)
	xx, yy, prover := shuffle.Shuffle(n.Inf.Suite, nil, h, x, y, rnd)
	prf, err := proof.HashProve(n.Inf.Suite, "PairShuffle", rnd, prover)
	if err != nil {
		fmt.Printf("Error creating proof: %s\n", err.Error())
	}
	return xx, yy, ShufProof{x, y, prf}
}

// Random swapping between left and right sets
type Biffle struct {
	Inf *Info
}
