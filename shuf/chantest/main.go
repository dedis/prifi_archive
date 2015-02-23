package main

import (
	"fmt"
	"github.com/dedis/prifi/shuf"
	"github.com/dedis/prifi/shuf/gochan"
	"time"
)

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

	var s shuf.DumbShuffle

	gochan.ChanShuffle(s, &defaultOpts, messages)
	time.Sleep(time.Second * 2)
}
