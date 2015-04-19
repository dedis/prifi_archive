package shuf

import (
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/proof"
	"github.com/dedis/crypto/shuffle"
	"math/rand"
	"strconv"
	"time"
)

// List of El Gamal pairs
type Elgamal struct {
	X []abstract.Point
	Y []abstract.Point
}

// Instructions during a shuffle
type RouteInstr struct {
	To           []int            // Where to send the pairs next
	ShufPairs    Elgamal          // Neff shuffled pairs
	PlainY       []abstract.Point // Ys decrypted
	NewPairs     Elgamal          // What to pass on
	ShufProof    []byte           // Proof of the Neff shuffle
	DecryptProof []byte           // Proof of decryption
	H            abstract.Point   // H decrypted
}

// A proof to be verified
type Proof struct {
	ShufProof    []byte
	DecryptProof []byte
	OldPairs     Elgamal
	ShufPairs    Elgamal
	PlainY       []abstract.Point
	H            abstract.Point
}

// Shuffle methods
type Shuffle interface {
	ShuffleStep(pairs Elgamal,
		node int, round int, inf *Info, H abstract.Point) RouteInstr
	Setup(msg abstract.Point, client int, inf *Info) (Elgamal, abstract.Point, int)
	ActiveRounds(node int, inf *Info) []int
}

// Information collectively aggreed upon beforehand
type Info struct {
	Suite        abstract.Suite
	PrivKey      func(int) abstract.Secret // restricted domain when networked
	PubKey       []abstract.Point
	NumNodes     int
	NumClients   int
	MsgSize      int
	NumRounds    int
	ResendTime   time.Duration
	MsgsPerGroup int
	ProofSize    int
}

// Encrypt a message that will follow the path given by 'nodes'
func OnionEncrypt(msgs []abstract.Point, inf *Info,
	nodes []int) (X, Y []abstract.Point, H abstract.Point) {
	rnd := inf.Suite.Cipher(abstract.RandomKey)
	X = make([]abstract.Point, len(msgs))
	Y = make([]abstract.Point, len(msgs))
	r := inf.Suite.Secret().Pick(rnd)
	H = inf.Suite.Point().Null()
	for i := len(nodes) - 1; i >= 0; i-- {
		H = inf.Suite.Point().Add(inf.PubKey[nodes[i]], H)
	}
	for m := range msgs {
		Y[m] = inf.Suite.Point().Mul(H, r)
		Y[m] = inf.Suite.Point().Add(Y[m], msgs[m])
		X[m] = inf.Suite.Point().Mul(nil, r)
	}
	return X, Y, H
}

// Decrypt a list of pairs, removing the node's part of the shared parameter
func DecryptPairs(pairs Elgamal, inf *Info, node int,
	H abstract.Point) ([]abstract.Point, abstract.Point, []byte, error) {

	newY := make([]abstract.Point, len(pairs.Y))
	negKey := inf.Suite.Secret().Neg(inf.PrivKey(node))
	var p proof.Predicate
	sec := map[string]abstract.Secret{"-h": negKey, "1": inf.Suite.Secret().One()}
	pub := map[string]abstract.Point{}
	for i := range pairs.X {
		xname := "X" + strconv.Itoa(i)
		mname := "M" + strconv.Itoa(i)
		yname := "Y" + strconv.Itoa(i)
		pub[xname] = pairs.X[i]
		pub[yname] = pairs.Y[i]
		if p == nil {
			p = proof.Rep(mname, "-h", xname, "1", yname)
		} else {
			p = proof.And(p, proof.Rep(mname, "-h", xname, "1", yname))
		}
		newY[i] = inf.Suite.Point().Add(inf.Suite.Point().Mul(pairs.X[i], negKey), pairs.Y[i])
		pub[mname] = newY[i]
	}
	var newH abstract.Point
	if H != nil {
		newH = inf.Suite.Point().Add(inf.Suite.Point().Mul(nil, negKey), H)
	}
	rand := inf.Suite.Cipher(nil)
	prover := p.Prover(inf.Suite, sec, pub, nil)
	proof, proofErr := proof.HashProve(inf.Suite, "", rand, prover)
	return newY, newH, proof, proofErr
}

// Verify a decryption and shuffle
func VerifyProof(inf *Info, p Proof) error {

	// Verify the shuffle
	verifier := shuffle.Verifier(inf.Suite, nil, p.H,
		p.OldPairs.X, p.OldPairs.Y, p.ShufPairs.X, p.ShufPairs.Y)
	e1 := proof.HashVerify(inf.Suite, "PairShuffle", verifier, p.ShufProof)
	if e1 != nil {
		return e1
	}

	// Verify the decryption
	var pred proof.Predicate
	pub := map[string]abstract.Point{}
	for i := range p.PlainY {
		xname := "X" + strconv.Itoa(i)
		mname := "M" + strconv.Itoa(i)
		yname := "Y" + strconv.Itoa(i)
		pub[xname] = p.ShufPairs.X[i]
		pub[yname] = p.ShufPairs.Y[i]
		pub[mname] = p.PlainY[i]
		if pred == nil {
			pred = proof.Rep(mname, "-h", xname, "1", yname)
		} else {
			pred = proof.And(pred, proof.Rep(mname, "-h", xname, "1", yname))
		}
	}
	verifier2 := pred.Verifier(inf.Suite, pub)
	return proof.HashVerify(inf.Suite, "", verifier2, p.DecryptProof)
}

// Generic deal function
func deal(total, size int) []int {
	result := make([]int, size)
	hash := make(map[int]*int)
	idx := 0
	for lim := total; lim > total-size; lim-- {
		i := rand.Intn(lim)
		if hash[i] != nil {
			result[idx] = *hash[i]
		} else {
			result[idx] = i
		}
		top := lim - 1
		if hash[top] != nil {
			hash[i] = hash[top]
		} else {
			hash[i] = &top
		}
		idx++
	}
	return result
}

// Create a range slice
func xrange(extent int) []int {
	result := make([]int, extent)
	for i := range result {
		result[i] = i
	}
	return result
}

// Break a slice into chunks of the given size
func chunks(in []int, size int) [][]int {
	result := make([][]int, len(in)/size)
	for c := range result {
		result[c] = make([]int, size)
		for i := 0; i < size; i++ {
			result[c][i] = in[c*size+i]
		}
	}
	return result
}
