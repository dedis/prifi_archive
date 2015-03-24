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

type crossMsg struct {
	msgs  [][]byte
	virt  int
	round int
	ack   *bool
}

type shufMsg struct {
	msgs  [][]byte
	virt  int
	round int
}

func ChanShuffle(s shuf.Shuffle, inf *shuf.Info, msgs [][]byte) {

	// Fake internet
	shuffleChans := make([]chan shufMsg, inf.NumNodes)
	crossChans := make([]chan crossMsg, inf.NumNodes)
	result := make([]chan [][]byte, inf.NumNodes)
	for i := range result {
		result[i] = make(chan [][]byte)
		shuffleChans[i] = make(chan shufMsg)
		crossChans[i] = make(chan crossMsg)
	}

	// Start the Shufflers
	for i := range shuffleChans {

		// Shuffling step
		go func(i int) {
			for {
				input := <-shuffleChans[i]
				instrs := s.ShuffleStep(input.msgs, shuf.NodeId{i, input.virt}, input.round, inf)
				for _, ins := range instrs {
					if ins.To == nil {
						// fmt.Printf("Node %v completed in round %v\n", i, input.round)
						result[i] <- ins.Msgs
					} else {
						// fmt.Printf("Node %v sends to %v in round %v\n", i, ins.To.Virtual, input.round)

						// notice when not ACKed
						go func(ins shuf.RouteInstr, round int) {
							ack := false
							m := crossMsg{ins.Msgs, ins.To.Virtual, input.round + 1, &ack}
							for !ack {
								crossChans[ins.To.Physical] <- m
								time.Sleep(inf.ResendTime)
								// if !ack {
								// 	fmt.Printf("Node %v round %v not yet ACKed; retrying\n", i, input.round+1)
								// }
							}
						}(ins, input.round)
					}
				}
			}
		}(i)

		// Collection step
		go func(i int) {
			for round := 0; ; round++ {
				// fmt.Printf("Collecting for node %v, round %v\n", i, round)
				collection := make(map[int][][]byte)
				collect := true
				go func(i int, round int) {
					for collect {
						cm := <-crossChans[i]
						// fmt.Printf("Got something in node %v, round %v with round %v\n", i, round, cm.round)
						if cm.round == round {
							if collection[cm.virt] == nil {
								collection[cm.virt] = make([][]byte, 0)
							}
							collection[cm.virt] = append(collection[cm.virt], cm.msgs...)
							*(cm.ack) = true
						}
					}
				}(i, round)
				time.Sleep(inf.CollectTime)
				collect = false
				go func(round int) {
					// fmt.Printf("Round %v node %v: sending collection %v\n", round, i, collection)
					for k, v := range collection {
						shuffleChans[i] <- shufMsg{v, k, round}
					}
				}(round)
			}
		}(i)

	}

	// All clients send their messages
	for m := range msgs {
		go func(m int) {
			ack := false
			sendTo := s.InitialNode(msgs[m], m, inf)
			msg := crossMsg{[][]byte{msgs[m]}, sendTo.Virtual, 0, &ack}
			crossChans[sendTo.Physical] <- msg
			time.Sleep(inf.ResendTime)
			if !ack {
				// We're only running one iteration, so resending won't help
				fmt.Printf("Client %v not Acknowledged\n", m)
			}
		}(m)
	}

	// Print out the order as it comes in
	for i := range result {
		go func() {
			fmt.Printf("Index %v: %v\n", i, <-result[i])
		}()
	}

}
