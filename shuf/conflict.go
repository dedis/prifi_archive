package shuf

// import (
// 	"fmt"
// 	"github.com/dedis/crypto/abstract"
// 	"github.com/dedis/crypto/proof"
// 	"github.com/dedis/crypto/shuffle"
// 	"math/rand"
// )
//
// // Potentially conflicting shuffle
// type ConflictSwap Butterfly
//
// 	vnode := node.Virtual
//
// 	if round >= len(s.Left) {
// 		return []RouteInstr{RouteInstr{nil, pairs}}
// 	}
//
// 	var X [2]abstract.Point
// 	var Y [2]abstract.Point
// 	for i := range X {
// 		X[i] = inf.Suite.Point().Null()
// 		Y[i] = inf.Suite.Point().Null()
// 	}
//
// 	for i := range pairs.X {
// 		switch s.rnd.Intn(1) {
// 		case 0:
// 			X[0] = inf.Suite.Point().Add(X[0], pairs.X[i])
// 			Y[0] = inf.Suite.Point().Add(Y[0], pairs.Y[i])
// 		case 1:
// 			X[1] = inf.Suite.Point().Add(X[1], pairs.X[i])
// 			Y[1] = inf.Suite.Point().Add(Y[1], pairs.Y[i])
// 		}
// 	}
//
// 	// Testing: everything works perfectly
// 	// X[0] = inf.Suite.Point().Add(X[0], pairs.X[0])
// 	// Y[0] = inf.Suite.Point().Add(Y[0], pairs.Y[0])
// 	// X[1] = inf.Suite.Point().Add(X[1], pairs.X[1])
// 	// Y[1] = inf.Suite.Point().Add(Y[1], pairs.Y[1])
//
// 	left := new(Elgamal)
// 	left.X = []abstract.Point{X[0]}
// 	left.Y = []abstract.Point{Y[0]}
//
// 	right := new(Elgamal)
// 	right.X = []abstract.Point{X[1]}
// 	right.Y = []abstract.Point{Y[1]}
//
// 	var pleft int = s.Left[round][vnode]
// 	var pright int = s.Right[round][vnode]
// 	return []RouteInstr{
// 		RouteInstr{&NodeId{s.Physical[pleft], pleft}, *left},
// 		RouteInstr{&NodeId{s.Physical[pright], pright}, *right},
// 	}
// }
//
// func (cs ConflictSwap) InitialNode(client int, inf *Info) NodeId {
// 	v := client % (inf.NumClients / 2)
// 	return NodeId{cs.Physical[v], v}
// }
//
// func (id ConflictSwap) MergeGamal(apairs *Elgamal, bpairs Elgamal) *Elgamal {
// 	return defaultMergeGamal(apairs, bpairs)
// }
