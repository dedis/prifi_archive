package shuf

import (
	"fmt"
	"github.com/dedis/crypto/abstract"
	// "github.com/dedis/crypto/shuffle"
)

// This is currently just marshalling points in and out of binary
// Don't look at this code (or the stuff in testverify) yet

type NeffShuffle struct {
	Suite   abstract.Suite
	PubKey  func(int) abstract.Point
	PrivKey func(int) abstract.Secret // restricted domain when networked
}

func (s NeffShuffle) ShuffleStep(msgs [][]byte, node NodeId,
	round int, inf *Info) []RouteInstr {

	// Decode the ElGamal pairs
	X := make([]abstract.Point, len(msgs))
	Y := make([]abstract.Point, len(msgs))
	for i := range X {
		X[i] = s.Suite.Point()
		Y[i] = s.Suite.Point()
		X[i].UnmarshalBinary(msgs[i][:X[i].MarshalSize()])
		Y[i].UnmarshalBinary(msgs[i][X[i].MarshalSize():])
	}

	// Shuffle the pairs
	// XX, YY, P = shuffle.Shuffle(s.Suite.Group, s.G, h, X, Y, s.Cipher(nil))

	// Encode them again
	newmsgs := make([][]byte, len(msgs))
	for i := range X {
		xbytes, err1 := X[i].MarshalBinary()
		ybytes, err2 := Y[i].MarshalBinary()
		if err1 != nil {
			fmt.Printf("Error: %v\n", err1.Error())
		}
		if err2 != nil {
			fmt.Printf("Error: %v\n", err2.Error())
		}
		newmsgs[i] = append(xbytes, ybytes...)
	}

	next := node.Physical + 1
	var nextP *NodeId
	if next < inf.NumNodes {
		nextP = &NodeId{next, next}
	}
	return []RouteInstr{RouteInstr{nextP, newmsgs}}
}

func (id NeffShuffle) InitialNode(msg []byte, client int, inf *Info) NodeId {
	return NodeId{0, 0}
}
