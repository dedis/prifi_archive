package shuf

import (
	"math/rand"
)

// Identity shuffle
type IdShuffle struct{}

func (i IdShuffle) ShuffleStep(msgs [][]byte, node int,
	inf *Info) ([][]byte, *int) {
	return msgs, nil
}

func (id IdShuffle) InitialNode(msg []byte, inf *Info) int {
	return 0
}

// Random, but insecure shuffle
type DumbShuffle struct{}

func (d DumbShuffle) InitialNode(msg []byte, inf *Info) int {
	return 0
}

func (d DumbShuffle) ShuffleStep(msgs [][]byte, node int,
	inf *Info) ([][]byte, *int) {
	newMsgs := make([][]byte, len(msgs))
	rand.Seed(inf.Seed)
	p := rand.Perm(len(msgs))
	for i := range p {
		newMsgs[i] = msgs[p[i]]
	}
	return newMsgs, nil
}
