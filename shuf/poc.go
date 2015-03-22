package shuf

import (
	"math/rand"
)

// Identity shuffle
type IdShuffle struct{}

func (i IdShuffle) ShuffleStep(msgs [][]byte, node int,
	round int, inf *Info) []RouteInstr {
	return []RouteInstr{RouteInstr{nil, msgs}}
}

func (id IdShuffle) InitialNode(msg []byte, client int, inf *Info) int {
	return 0
}

// Random, but insecure shuffle
type DumbShuffle struct {
	Seed int64
}

func (d DumbShuffle) InitialNode(msg []byte, client int, inf *Info) int {
	return 0
}

func (d DumbShuffle) ShuffleStep(msgs [][]byte, node int,
	round int, inf *Info) []RouteInstr {
	newMsgs := make([][]byte, len(msgs))
	rand.Seed(d.Seed)
	p := rand.Perm(len(msgs))
	for i := range p {
		newMsgs[i] = msgs[p[i]]
	}
	return []RouteInstr{RouteInstr{nil, newMsgs}}
}
