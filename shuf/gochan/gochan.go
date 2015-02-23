package gochan

import (
	"fmt"
	"github.com/dedis/prifi/shuf"
	"time"
)

// TODO: make sure there's no duplicates
// TODO: probably need a lock on collection slice

type initMsg struct {
	msg []byte
	ack *bool
}

func ChanShuffle(s shuf.Shuffle, inf *shuf.Info, msgs [][]byte) {

	// Fake internet
	shuffleChans := make([]chan [][]byte, inf.NumNodes)
	initChans := make([]chan initMsg, inf.NumNodes)
	result := make([]chan [][]byte, len(msgs))
	for i := range result {
		result[i] = make(chan [][]byte)
	}

	// Start the Shufflers
	for i := range shuffleChans {
		shuffleChans[i] = make(chan [][]byte)
		initChans[i] = make(chan initMsg)

		// Shuffling step
		go func(i int) {
			for {
				input := <-shuffleChans[i]
				output, next := s.ShuffleStep(input, i, inf)
				if next == nil {
					for m := range result {
						go func(m int) {
							result[m] <- output
						}(m)
					}
					break
				} else {
					shuffleChans[*next] <- output
				}
			}
		}(i)

		// Collection step
		go func(i int) {
			collection := make([][]byte, 0)
			collect := true
			go func(i int) {
				for collect {
					cm := <-initChans[i]
					collection = append(collection, cm.msg)
					*(cm.ack) = true
				}
			}(i)
			time.Sleep(inf.CollectTime)
			collect = false
			shuffleChans[i] <- collection
		}(i)

	}

	// All clients send their messages
	for m := range msgs {
		go func(m int) {
			ack := false
			msg := initMsg{msg: msgs[m], ack: &ack}
			sendTo := s.InitialNode(msgs[m], inf)
			initChans[sendTo] <- msg
			time.Sleep(inf.ResendTime)
			if ack {
				fmt.Printf("Client %v acknowledged\n", m)
				fmt.Printf("Client %v received: %v\n", m, <-result[m])
			} else {
				fmt.Printf("Client %v not Acknowledged\n", m)
			}
		}(m)
	}

}
