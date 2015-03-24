package shuf

import (
	"fmt"
	"math/rand"
)

func xorInto(a []byte, b []byte) {
	for i := range a {
		a[i] ^= b[i]
	}
}

// New potentially conflicting shuffle
type ConflictSwap struct {
	Left     [][]int    // Pointer to the virtual node at left
	Right    [][]int    // Pointer to the virtual node at right
	Physical []int      // Mapping from virtual to physical nodes
	rnd      *rand.Rand // Random number generator
}

func (s ConflictSwap) ShuffleStep(msgs [][]byte, node NodeId,
	round int, inf *Info) []RouteInstr {
	vnode := node.Virtual

	fmt.Printf("Shuffe for round %v, vnode %v\n", round, vnode)
	if round >= len(s.Left) {
		return []RouteInstr{RouteInstr{nil, msgs}}
	}

	leftBytes := make([]byte, inf.MsgSize)
	rightBytes := make([]byte, inf.MsgSize)
	switch s.rnd.Intn(1) {
	case 0:
		xorInto(leftBytes, msgs[0])
	case 1:
		xorInto(rightBytes, msgs[0])
	}
	switch s.rnd.Intn(1) {
	case 0:
		xorInto(leftBytes, msgs[1])
	case 1:
		xorInto(rightBytes, msgs[1])
	}
	var pleft int = s.Left[round][vnode]
	var pright int = s.Right[round][vnode]
	fmt.Printf("On %v, left to %v, right to %v\n", vnode, pleft, pright)
	return []RouteInstr{
		RouteInstr{&NodeId{s.Physical[pleft], pleft}, [][]byte{leftBytes}},
		RouteInstr{&NodeId{s.Physical[pright], pright}, [][]byte{rightBytes}},
	}
}

func (cs ConflictSwap) InitialNode(msg []byte, client int, inf *Info) NodeId {
	v := client % (inf.NumClients / 2)
	return NodeId{cs.Physical[v], v}
}

type npair struct {
	val       int
	remaining int
}

// Constructs a ConflictSwap with:
// 2N messages and clients
// N virtual nodes
// an arbitrary number of real nodes
// a random mapping of real nodes to virtual nodes
func CSwap(inf *Info, seed int64) *ConflictSwap {
	numvnodes := inf.NumClients / 2
	cs := new(ConflictSwap)
	cs.rnd = rand.New(rand.NewSource(seed))
	cs.Left = make([][]int, inf.NumRounds)
	cs.Right = make([][]int, inf.NumRounds)
	cs.Physical = make([]int, numvnodes)

	// Assign real nodes to virtual nodes randomly
	for i := 0; i < numvnodes; i++ {
		cs.Physical[i] = cs.rnd.Intn(inf.NumNodes)
	}

	// Create butterfly network
	for r := 0; r < inf.NumRounds; r++ {

		// Create Left and Right paths
		cs.Left[r] = make([]int, numvnodes)
		cs.Right[r] = make([]int, numvnodes)

		// remaining possible edges for each vnode
		incoming := make([]npair, numvnodes)
		inLen := numvnodes
		outgoing := make([]npair, numvnodes)
		outLen := numvnodes
		for i := range incoming {
			incoming[i] = npair{i, 2}
			outgoing[i] = npair{i, 2}
		}

		// assign until everything is used up
		for inLen > 0 {
			i := cs.rnd.Intn(inLen)
			fmt.Printf("Picked %v of %v\n", i, numvnodes)
			incoming[i].remaining--
			from := incoming[i].val
			lr := incoming[i].remaining
			if incoming[i].remaining == 0 {
				incoming[i] = incoming[inLen-1]
				inLen--
			}

			j := cs.rnd.Intn(outLen)
			outgoing[j].remaining--
			to := outgoing[j].val
			if outgoing[j].remaining == 0 {
				outgoing[i] = outgoing[outLen-1]
				outLen--
			}

			switch lr {
			case 0:
				cs.Left[r][from] = to
			case 1:
				cs.Right[r][from] = to
			}
		}
	}
	fmt.Printf("Left: %v\n", cs.Left)
	fmt.Printf("Right: %v\n", cs.Right)
	return cs
}
