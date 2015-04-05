package shuf

import (
	"github.com/dedis/crypto/abstract"
	"math/rand"
	"time"
)

// List of El Gamal pairs
type Elgamal struct {
	X []abstract.Point
	Y []abstract.Point
}

// Where to send a list of pairs next
type RouteInstr struct {
	To    []int
	Pairs Elgamal
	Proof []byte
	H     abstract.Point
}

// Shuffle methods
type Shuffle interface {
	ShuffleStep(pairs Elgamal,
		node int, round int, inf *Info, H abstract.Point) RouteInstr
	Setup(msg abstract.Point, client int, inf *Info) (Elgamal, abstract.Point, int)
	ActiveRounds(node int, inf *Info) []int
	VerifyShuffle(newPairs, oldPairs Elgamal, H abstract.Point, inf *Info, prf []byte) error
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
func decryptPairs(pairs Elgamal, inf *Info, node int,
	H abstract.Point) (Elgamal, abstract.Point) {
	negKey := inf.Suite.Secret().Neg(inf.PrivKey(node))
	for i := range pairs.X {
		pairs.Y[i] = inf.Suite.Point().Add(inf.Suite.Point().Mul(pairs.X[i], negKey), pairs.Y[i])
	}
	if H != nil {
		H = inf.Suite.Point().Add(inf.Suite.Point().Mul(nil, negKey), H)
	}
	return pairs, H
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
