package shuf

import (
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/proof"
)

// Encrypt a message with the given public key
func (inf *Info) Encrypt(msgs []abstract.Point, h abstract.Point) (x, y []abstract.Point) {
	rnd := inf.Suite.Cipher(abstract.RandomKey)
	x = make([]abstract.Point, len(msgs))
	y = make([]abstract.Point, len(msgs))
	r := inf.Suite.Secret().Pick(rnd)
	for m := range msgs {
		y[m] = inf.Suite.Point().Mul(h, r)
		y[m] = inf.Suite.Point().Add(y[m], msgs[m])
		x[m] = inf.Suite.Point().Mul(nil, r)
	}
	return x, y
}

// Decrypt a list of pairs with associated proof, potentially adding new encryption
func (inf *Info) Decrypt(x, y, newX, newY []abstract.Point, node int,
	encryptFor abstract.Point, rnd abstract.Cipher) (DecProof, error) {

	negKey := inf.Suite.Secret().Neg(inf.PrivKey(node))
	proofs := make([][]byte, len(x))
	sec := map[string]abstract.Secret{"-h": negKey}
	pub := map[string]abstract.Point{"B": encryptFor}

	var p proof.Predicate
	if encryptFor != nil {
		p = proof.Rep("Y'-Y", "-h", "X", "r", "B")
	} else {
		p = proof.Rep("Y'-Y", "-h", "r")
	}

	for i := range x {
		pub["X"] = x[i]
		r := inf.Suite.Secret().Pick(rnd)
		sec["r"] = r
		newY[i] = inf.Suite.Point().Mul(x[i], negKey)
		newY[i] = newY[i].Add(newY[i], y[i])
		newY[i] = newY[i].Add(newY[i], inf.Suite.Point().Mul(encryptFor, r))
		pub["Y'-Y"] = inf.Suite.Point().Sub(newY[i], y[i])
		newX[i] = newX[i].Add(newX[i], inf.Suite.Point().Mul(nil, r))
		prover := p.Prover(inf.Suite, sec, pub, nil)
		proof, proofErr := proof.HashProve(inf.Suite, "Decrypt", rnd, prover)
		proofs[i] = proof
		if proofErr != nil {
			return DecProof{}, proofErr
		}
	}
	return DecProof{y, proofs}, nil
}

// The combined public key for a bunch of nodes
func (inf *Info) PublicKey(nodes []int) abstract.Point {
	h := inf.Suite.Point().Null()
	for _, i := range nodes {
		h = inf.Suite.Point().Add(inf.PubKey[i], h)
	}
	return h
}

// Verify that the shuffle history from a node is correct
func (inf *Info) VerifyShuffles(hist []ShufProof, x, y []abstract.Point, h abstract.Point) error {
	if len(hist) < 1 {
		return nil
	}

	// Check everything but the last proof
	for p := 0; p < len(hist)-1; p++ {
		e := inf.Shuffle.Verify(h, hist[p].X, hist[p].Y, hist[p+1].X, hist[p+1].Y, hist[p].Proof)
		if e != nil {
			return e
		}
	}

	// Check the last proof
	p := hist[len(hist)-1]
	e := inf.Shuffle.Verify(h, p.X, p.Y, x, y, p.Proof)
	if e != nil {
		return e
	}
	return nil
}

// Verify that the decrypt history from a node is correct
func (inf *Info) VerifyDecrypts(history []DecProof, X []abstract.Point,
	newY []abstract.Point, encryptFor abstract.Point) error {
	if len(history) < 1 {
		return nil
	}
	pub := map[string]abstract.Point{"B": encryptFor}
	var p proof.Predicate
	if encryptFor != nil {
		p = proof.Rep("Y'-Y", "-h", "X", "r", "B")
	} else {
		p = proof.Rep("Y'-Y", "-h", "r")
	}
	for i := range X {
		pub["X"] = X[i]

		// Check everything but the last proof
		for prf := 0; prf < len(history)-1; prf++ {
			pub["Y'-Y"] = inf.Suite.Point().Sub(history[prf+1].Y[i], history[prf].Y[i])
			verifier := p.Verifier(inf.Suite, pub)
			e := proof.HashVerify(inf.Suite, "Decrypt", verifier, history[prf].Proof[i])
			if e != nil {
				return e
			}
		}

		// Check the last proof
		prf := history[len(history)-1]
		pub["Y'-Y"] = inf.Suite.Point().Sub(newY[i], prf.Y[i])
		verifier := p.Verifier(inf.Suite, pub)
		e := proof.HashVerify(inf.Suite, "Decrypt", verifier, prf.Proof[i])
		if e != nil {
			return e
		}
	}
	return nil
}
