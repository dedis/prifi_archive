package main

import (
	"fmt"
	"github.com/dedis/prifi/shuf"
	"github.com/dedis/prifi/shuf/gochan"
	"time"
)

func main() {

	defaultOpts := shuf.Info{
		NumNodes:    1,
		NumClients:  2,
		MsgSize:     5,
		NumRounds:   1,
		ResendTime:  time.Second,
		CollectTime: time.Second}

	messages := make([][]byte, 2)
	messages[0] = []byte("hello")
	messages[1] = []byte("world")
	fmt.Printf("Starting with %v\n", messages)

	s := shuf.IdShuffle{}
	// s := shuf.DumbShuffle{2}

	gochan.ChanShuffle(s, &defaultOpts, messages)
	time.Sleep(time.Second * 2)
}
