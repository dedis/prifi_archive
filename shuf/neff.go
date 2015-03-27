package shuf

import (
	"github.com/dedis/crypto/shuffle"
)

type NeffShuffle struct{}

func (s NeffShuffle) ShuffleStep(pairs Elgamal,
	node NodeId,
	round int, inf *Info) []RouteInstr {

	// Verify that the previous shuffle was okay
	// if oldx != nil {
	// 	verifier := Verifier(s.Suite, nil, oldShared, oldx, oldy, x, y)
	// 	err = proof.HashVerify(suite, "PairShuffle", verifier, proof)
	// 	if err != nil {
	// 		panic("Shuffle verify failed: " + err.Error())
	// 	}
	// }

	// Shuffle it and decrypt it
	xx, yy, _ := shuffle.Shuffle(inf.Suite, nil, pairs.Shared, pairs.X, pairs.Y, inf.Suite.Cipher(nil))
	pairs.X = xx
	pairs.Y = yy
	pairs = decryptPairs(pairs, inf, node.Physical)
	instr := RouteInstr{Pairs: pairs}

	next := node.Physical + 1
	if next < inf.NumNodes {
		instr.To = &NodeId{next, next}
	}
	return []RouteInstr{instr}
}

func (id NeffShuffle) InitialNode(client int, inf *Info) NodeId {
	return NodeId{0, 0}
}

func (id NeffShuffle) MergeGamal(apairs *Elgamal, bpairs Elgamal) *Elgamal {
	return defaultMergeGamal(apairs, bpairs)
}
