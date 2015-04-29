package shuf

import (
	"fmt"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/proof"
	"github.com/dedis/crypto/random"
	"github.com/dedis/crypto/shuffle"
)

// Generic interface for random pair routing
type Shuffler interface {
	Shuffle(x, y []abstract.Point, h abstract.Point) ([]abstract.Point, []abstract.Point, ShufProof)
	Verify(h abstract.Point, x, y, xbar, ybar []abstract.Point, p [][]byte) error
}

// Neff Shuffle
type Neff struct {
	Inf *Info
}

// Verify a Neff shuffle proof
func (n Neff) Verify(h abstract.Point, x, y, xbar, ybar []abstract.Point, p [][]byte) error {
	verifier := shuffle.Verifier(n.Inf.Suite, nil, h, x, y, xbar, ybar)
	return proof.HashVerify(n.Inf.Suite, "PairShuffle", verifier, p[0])
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
	return xx, yy, ShufProof{x, y, [][]byte{prf}}
}

// Random swapping between left and right sets
type Biffle struct {
	Inf *Info
}

// Create the predicate for Biffle proofs
func bifflePred() proof.Predicate {

	// Branch 0 of either/or proof (for bit=0)
	rep000 := proof.Rep("Xbar0-X0", "beta0", "G")
	rep001 := proof.Rep("Ybar0-Y0", "beta0", "H")
	rep010 := proof.Rep("Xbar1-X1", "beta1", "G")
	rep011 := proof.Rep("Ybar1-Y1", "beta1", "H")

	// Branch 1 of either/or proof (for bit=1)
	rep100 := proof.Rep("Xbar0-X1", "beta1", "G")
	rep101 := proof.Rep("Ybar0-Y1", "beta1", "H")
	rep110 := proof.Rep("Xbar1-X0", "beta0", "G")
	rep111 := proof.Rep("Ybar1-Y0", "beta0", "H")

	and0 := proof.And(rep000, rep001, rep010, rep011)
	and1 := proof.And(rep100, rep101, rep110, rep111)

	or := proof.Or(and0, and1)
	return or
}

// Perform a binary shuffle
func (b Biffle) Shuffle(x, y []abstract.Point, h abstract.Point) (
	[]abstract.Point, []abstract.Point, ShufProof) {

	Xbar := make([]abstract.Point, len(x))
	Ybar := make([]abstract.Point, len(y))
	rnd := b.Inf.Suite.Cipher(abstract.RandomKey)
	half := len(x) / 2
	sec := map[string]abstract.Secret{}
	pred := bifflePred()
	proofs := make([][]byte, half)

	for i := range Xbar[:half] {

		// Pick a fresh ElGamal blinding factor for each pair
		var beta [2]abstract.Secret
		for j := 0; j < 2; j++ {
			beta[j] = b.Inf.Suite.Secret().Pick(rnd)
		}

		bit := int(random.Byte(rnd) & 1)
		Xbar[i] = x[bit*half+i]
		Xbar[i] = b.Inf.Suite.Point().Add(Xbar[i], b.Inf.Suite.Point().Mul(nil, beta[bit]))
		Ybar[i] = y[bit*half+i]
		Ybar[i] = b.Inf.Suite.Point().Add(Ybar[i], b.Inf.Suite.Point().Mul(h, beta[bit]))

		notbit := bit ^ 1
		j := i + half
		Xbar[j] = x[notbit*half+i]
		Xbar[j] = b.Inf.Suite.Point().Add(Xbar[j], b.Inf.Suite.Point().Mul(nil, beta[notbit]))
		Ybar[j] = y[notbit*half+i]
		Ybar[j] = b.Inf.Suite.Point().Add(Ybar[j], b.Inf.Suite.Point().Mul(h, beta[notbit]))

		sec["beta0"] = beta[0]
		sec["beta1"] = beta[1]
		points := b.bifflePoints(i, h, x, y, Xbar, Ybar)
		choice := map[proof.Predicate]int{pred: bit}
		prover := pred.Prover(b.Inf.Suite, sec, points, choice)
		prf, proofErr := proof.HashProve(b.Inf.Suite, "Biffle", rnd, prover)
		if proofErr != nil {
			panic(proofErr)
		}
		proofs[i] = prf
	}
	return Xbar, Ybar, ShufProof{x, y, proofs}
}

// Constuct public key hash for biffle proof
func (b Biffle) bifflePoints(i int, H abstract.Point,
	X, Y, Xbar, Ybar []abstract.Point) map[string]abstract.Point {
	j := len(X)/2 + i
	return map[string]abstract.Point{
		"G":        nil,
		"H":        H,
		"Xbar0-X0": b.Inf.Suite.Point().Sub(Xbar[i], X[i]),
		"Ybar0-Y0": b.Inf.Suite.Point().Sub(Ybar[i], Y[i]),
		"Xbar1-X1": b.Inf.Suite.Point().Sub(Xbar[j], X[j]),
		"Ybar1-Y1": b.Inf.Suite.Point().Sub(Ybar[j], Y[j]),
		"Xbar0-X1": b.Inf.Suite.Point().Sub(Xbar[i], X[j]),
		"Ybar0-Y1": b.Inf.Suite.Point().Sub(Ybar[i], Y[j]),
		"Xbar1-X0": b.Inf.Suite.Point().Sub(Xbar[j], X[i]),
		"Ybar1-Y0": b.Inf.Suite.Point().Sub(Ybar[j], Y[i])}
}

// Verify a biffle proof
func (b Biffle) Verify(h abstract.Point, x, y, xbar, ybar []abstract.Point, p [][]byte) error {
	half := len(x) / 2
	or := bifflePred()
	for i := range x[:half] {
		points := b.bifflePoints(i, h, x, y, xbar, ybar)
		verifier := or.Verifier(b.Inf.Suite, points)
		err := proof.HashVerify(b.Inf.Suite, "Biffle", verifier, p[i])
		if err != nil {
			return err
		}
	}
	return nil
}
