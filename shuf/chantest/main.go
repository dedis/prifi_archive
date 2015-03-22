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
		NumClients:  4,
		MsgSize:     5,
		NumRounds:   1,
		ResendTime:  time.Second,
		CollectTime: time.Second}

	messages := make([][]byte, 4)
	messages[0] = []byte("hello")
	messages[1] = []byte("world")
	messages[2] = []byte("11111")
	messages[3] = []byte("22222")
	fmt.Printf("Starting with %v\n", messages)

	// s := shuf.IdShuffle{}
	// s := shuf.DumbShuffle{2}
	s := shuf.CSwap(&defaultOpts, 2)

	gochan.ChanShuffle(s, &defaultOpts, messages)
	time.Sleep(time.Second * 2)
}
