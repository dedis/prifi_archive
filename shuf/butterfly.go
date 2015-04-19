package shuf

import (
	"fmt"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/proof"
	"github.com/dedis/crypto/shuffle"
	"math/rand"
)

// List of nodes for onion encryption on both sides
type groupJump struct {
	left  []int
	right []int
}

// Where to forward after each round
type roundInstr struct {
	nextNeff  []int              // map from round to next node (or -1)
	nextGroup map[int]*groupJump // map from round to groupJump (or nil)
}

// Butterfly network of neff subgroups
type Butterfly struct {
	directions []roundInstr // map from node to roundInstr
	rounds     [][]int      // map from node to rounds responsible
	startGroup [][]int      // map from (client % numGroups) to starting group
	numGroups  int          // number of groups in each level
}

func (s Butterfly) ActiveRounds(node int, inf *Info) []int {
	return s.rounds[node]
}

func (s Butterfly) Setup(msg abstract.Point, client int, inf *Info) (Elgamal, abstract.Point, int) {
	g := client % s.numGroups
	X, Y, H := OnionEncrypt([]abstract.Point{msg}, inf, s.startGroup[g])
	elg := Elgamal{X, Y}
	return elg, H, s.startGroup[g][0]
}

func (s Butterfly) ShuffleStep(pairs Elgamal, node int,
	round int, inf *Info, H abstract.Point) RouteInstr {

	// Shuffle it and decrypt it
	rnd := inf.Suite.Cipher(nil)
	xx, yy, prover :=
		shuffle.Shuffle(inf.Suite, nil, H, pairs.X, pairs.Y, rnd)
	prf, err := proof.HashProve(inf.Suite, "PairShuffle", rnd, prover)
	if err != nil {
		fmt.Printf("Error creating proof: %s\n", err.Error())
	}
	shufPairs := Elgamal{xx, yy}
	var prf2 []byte
	var err2 error
	pairs.Y, H, prf2, err2 = DecryptPairs(shufPairs, inf, node, H)
	pairs.X = xx
	if err2 != nil {
		fmt.Printf("Error creating proof2: %s\n", err.Error())
	}

	// Send it on its way
	instr := RouteInstr{
		ShufPairs:    shufPairs,
		NewPairs:     pairs,
		PlainY:       pairs.Y,
		H:            H,
		ShufProof:    prf,
		DecryptProof: prf2,
	}
	ri := s.directions[node]
	if ri.nextNeff[round] >= 0 {
		instr.To = []int{ri.nextNeff[round]}
	} else if ri.nextGroup[round] != nil {
		gj := ri.nextGroup[round]
		instr.To = []int{gj.left[0], gj.right[0]}

		// Add more onion encryption
		var newY, newX []abstract.Point
		newX, newY, instr.H = OnionEncrypt(pairs.Y, inf, gj.left)
		instr.NewPairs = Elgamal{newX, newY}
	}
	return instr
}

// Constructs a Butterfly network
func NewButterfly(inf *Info, seed int64) *Butterfly {

	// Initiailization
	rand.Seed(seed)
	b := new(Butterfly)
	b.numGroups = (inf.NumClients / inf.MsgsPerGroup)
	neffLen := inf.NumNodes / b.numGroups
	b.directions = make([]roundInstr, inf.NumNodes)
	for n := range b.directions {
		b.directions[n] = roundInstr{
			nextNeff:  make([]int, inf.NumRounds),
			nextGroup: make(map[int]*groupJump),
		}
	}
	b.rounds = make([][]int, inf.NumNodes)
	for n := range b.rounds {
		b.rounds[n] = make([]int, 0)
	}

	// Establish the butterfly connections
	oldEnders := make([]int, b.numGroups)
	for level := 0; level < inf.NumRounds/neffLen; level++ {
		groups := chunks(rand.Perm(inf.NumNodes), neffLen)
		if level == 0 {
			b.startGroup = groups
		} else {
			p := rand.Perm(b.numGroups)
			for i, e := range oldEnders {
				b.directions[e].nextGroup[(level+1)*neffLen-1] = &groupJump{
					left:  groups[i],
					right: groups[p[i]],
				}
			}
		}
		for gi, g := range groups {
			for i := 0; i < len(g)-1; i++ {
				b.rounds[g[i]] = append(b.rounds[g[i]], level*neffLen+i)
				b.directions[g[i]].nextNeff[level*neffLen+i] = g[i+1]
			}
			lst := g[len(g)-1]
			b.rounds[lst] = append(b.rounds[lst], (level+1)*neffLen-1)
			b.directions[lst].nextNeff[(level+1)*neffLen-1] = -1
			oldEnders[gi] = g[len(g)-1]
		}
	}
	return b
}
