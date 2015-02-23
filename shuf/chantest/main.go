package main

import (
	"fmt"
	"github.com/dedis/prifi/shuf"
	"github.com/dedis/prifi/shuf/gochan"
	"time"
)

type idShuffle struct{}

func (i idShuffle) ShuffleStep(msg [][]byte, node int,
	inf *shuf.Info) ([][]byte, *int) {
	return msg, nil
}

func (id idShuffle) InitialNode(msg []byte, inf *shuf.Info) int {
	return 0
}

func main() {

	defaultOpts := shuf.Info{
		Seed:       nil,
		NumNodes:   1,
		NumGroups:  1,
		NumRounds:  1,
		MsgSize:    1,
		ResendTime: time.Second,
		RoundTime:  time.Second}

	messages := make([][]byte, 1)
	messages[0] = make([]byte, 1)
	messages[0][0] = 'h'

	var s idShuffle

	gochan.ChanShuffle(s, &defaultOpts, messages)
	time.Sleep(time.Second * 5)
	fmt.Printf("done\n")
}
