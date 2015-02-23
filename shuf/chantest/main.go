package main

import (
	"fmt"
	"github.com/dedis/prifi/shuf"
	"github.com/dedis/prifi/shuf/gochan"
	"math/rand"
	"time"
)

// Identity shuffle
type idShuffle struct{}

func (i idShuffle) ShuffleStep(msgs [][]byte, node int,
	inf *shuf.Info) ([][]byte, *int) {
	return msgs, nil
}

func (id idShuffle) InitialNode(msg []byte, inf *shuf.Info) int {
	return 0
}

// Hey, it's progress
type dumbShuffle struct{}

func (d dumbShuffle) InitialNode(msg []byte, inf *shuf.Info) int {
	return 0
}

func (d dumbShuffle) ShuffleStep(msgs [][]byte, node int,
	inf *shuf.Info) ([][]byte, *int) {
	newMsgs := make([][]byte, len(msgs))
	rand.Seed(inf.Seed)
	p := rand.Perm(len(msgs))
	for i := range p {
		newMsgs[i] = msgs[p[i]]
	}
	return newMsgs, nil
}

func main() {

	defaultOpts := shuf.Info{
		Seed:        2,
		NumNodes:    1,
		NumGroups:   1,
		NumRounds:   1,
		MsgSize:     1,
		ResendTime:  time.Second,
		CollectTime: time.Second}

	messages := make([][]byte, 2)
	messages[0] = []byte("hello")
	messages[1] = []byte("world")
	fmt.Printf("Starting with %v\n", messages)

	var s dumbShuffle

	gochan.ChanShuffle(s, &defaultOpts, messages)
	time.Sleep(time.Second * 2)
}
