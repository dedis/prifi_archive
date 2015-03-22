package gochan

import (
	"fmt"
	"github.com/dedis/prifi/shuf"
	"time"
)

// Each node waits for CollectTime, gathering messages from clients
// When a node sees a message it ACKS it. Clients resend after ResendTime if no ACK
// Nodes call ShuffleStep, and distribute the RouteInstrs
// If any RouteInstr has a nil To field, distributes to that node's slot in result

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
	result := make([]chan [][]byte, inf.NumNodes)
	for i := range result {
		result[i] = make(chan [][]byte)
		shuffleChans[i] = make(chan [][]byte)
		initChans[i] = make(chan initMsg)
	}

	// Start the Shufflers
	for i := range shuffleChans {

		// Shuffling step
		go func(i int) {
			for round := 0; ; round++ {
				input := <-shuffleChans[i]
				instrs := s.ShuffleStep(input, i, round, inf)
				for _, ins := range instrs {
					if ins.To == nil {
						result[i] <- ins.Msgs
					} else {
						shuffleChans[*(ins.To)] <- ins.Msgs
					}
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
			sendTo := s.InitialNode(msgs[m], m, inf)
			initChans[sendTo] <- msg
			time.Sleep(inf.ResendTime)
			if ack {
				fmt.Printf("Client %v acknowledged\n", m)
			} else {
				fmt.Printf("Client %v not Acknowledged\n", m)
			}
		}(m)
	}

	// Print out the order as it comes in
	for i := range result {
		fmt.Printf("Index %v: %v\n", i, <-result[i])
	}

}
