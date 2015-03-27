package shuf

import (
	"github.com/dedis/crypto/abstract"
	"math/rand"
)

// New potentially conflicting shuffle
type Butterfly struct {
	Left     [][]int    // Pointer to the virtual node at left
	Right    [][]int    // Pointer to the virtual node at right
	Physical []int      // Mapping from virtual to physical nodes
	rnd      *rand.Rand // Random number generator
}

func (s Butterfly) ShuffleStep(msgs Elgamal, node NodeId,
	round int, inf *Info) []RouteInstr {

	// problem: we shouldn't decrypt it multiple times.
	// not quite sure how to encrypt it

	vnode := node.Virtual
	// msgs = decryptPairs(msgs, inf, node.Physical)

	if round >= len(s.Left) {
		return []RouteInstr{RouteInstr{nil, msgs}}
	}

	var X [2]abstract.Point
	var Y [2]abstract.Point

	for i, p := range s.rnd.Perm(2) {
		X[p] = msgs.X[i]
		Y[p] = msgs.Y[i]
	}

	left := new(Elgamal)
	left.X = []abstract.Point{X[0]}
	left.Y = []abstract.Point{Y[0]}

	right := new(Elgamal)
	right.X = []abstract.Point{X[1]}
	right.Y = []abstract.Point{Y[1]}

	var pleft int = s.Left[round][vnode]
	var pright int = s.Right[round][vnode]
	return []RouteInstr{
		RouteInstr{&NodeId{s.Physical[pleft], pleft}, *left},
		RouteInstr{&NodeId{s.Physical[pright], pright}, *right},
	}
}

func (cs Butterfly) InitialNode(client int, inf *Info) NodeId {
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
func NewButterfly(inf *Info, seed int64) *Butterfly {
	numvnodes := inf.NumClients / 2
	cs := new(Butterfly)
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
			// fmt.Printf("Picked %v of %v\n", i, numvnodes)
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
	// fmt.Printf("Left: %v\n", cs.Left)
	// fmt.Printf("Right: %v\n", cs.Right)
	return cs
}

func (id Butterfly) MergeGamal(apairs *Elgamal, bpairs Elgamal) *Elgamal {
	return defaultMergeGamal(apairs, bpairs)
}
