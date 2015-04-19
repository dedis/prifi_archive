package shuf

import (
	"fmt"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/proof"
	"github.com/dedis/crypto/shuffle"
)

type NeffShuffle struct{}

func (n NeffShuffle) ShuffleStep(pairs Elgamal,
	node int, round int, inf *Info, H abstract.Point) RouteInstr {

	// Shuffle it and decrypt it
	rand := inf.Suite.Cipher(nil)
	xx, yy, prover :=
		shuffle.Shuffle(inf.Suite, nil, H, pairs.X, pairs.Y, rand)
	prf, err := proof.HashProve(inf.Suite, "PairShuffle", rand, prover)
	if err != nil {
		fmt.Printf("Error creating proof: %s\n", err.Error())
	}
	shufPairs := Elgamal{xx, yy}
	var prf2 []byte
	var err2 error
	var newH abstract.Point
	pairs.Y, newH, prf2, err2 = DecryptPairs(shufPairs, inf, node, H)
	pairs.X = xx
	if err2 != nil {
		fmt.Printf("Error creating proof2: %s\n", err.Error())
	}

	// Send it on its way
	instr := RouteInstr{
		ShufPairs:    shufPairs,
		PlainY:       pairs.Y,
		NewPairs:     pairs,
		H:            newH,
		ShufProof:    prf,
		DecryptProof: prf2,
	}
	next := node + 1
	if next < inf.NumNodes {
		instr.To = []int{next}
	}
	return instr
}

func (n NeffShuffle) Setup(msg abstract.Point, client int,
	inf *Info) (Elgamal, abstract.Point, int) {
	X, Y, H := OnionEncrypt([]abstract.Point{msg}, inf, xrange(inf.NumNodes))
	elg := Elgamal{X, Y}
	return elg, H, 0
}

func (n NeffShuffle) ActiveRounds(node int, inf *Info) []int {
	return []int{node}
}
