package main

import (
	"fmt"
	"github.com/dedis/prifi/shuffle"
	"github.com/dedis/prifi/shuffle/goroutine"
	"time"
)

type idShuffle struct{}

func (i idShuffle) ShuffleStep(msg [][]byte, node int,
	inf *shuffle.SharedInfo) ([][]byte, *int) {
	return msg, nil
}

func (id idShuffle) NextNode(msg []byte, node *int, inf *shuffle.SharedInfo) *int {
	if node == nil {
		i := 0
		return &i
	} else {
		return nil
	}
}

func main() {

	defaultOpts := shuffle.SharedInfo{
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

	goroutine.ChanShuffle(s, s, &defaultOpts, messages)
	time.Sleep(time.Second * 5)
	fmt.Printf("done")
}
