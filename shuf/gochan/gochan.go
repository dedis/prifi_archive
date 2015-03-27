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
	msgs  shuf.Elgamal
	virt  int
	round int
	ack   *bool
}

type shufMsg struct {
	msgs  shuf.Elgamal
	virt  int
	round int
}

// what should emptyGamal and mergeGamal actually do?

func ChanShuffle(s shuf.Shuffle, inf *shuf.Info, pairs []shuf.Elgamal) {

	// Fake internet
	shuffleChans := make([]chan shufMsg, inf.NumNodes)
	crossChans := make([]chan crossMsg, inf.NumNodes)
	result := make([]chan shuf.Elgamal, inf.NumNodes)
	for i := range result {
		result[i] = make(chan shuf.Elgamal)
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
						result[i] <- ins.Pairs
					} else {
						// fmt.Printf("Node %v sends to %v in round %v\n", i, ins.To.Physical, input.round)

						// notice when not ACKed
						go func(ins shuf.RouteInstr, round int) {
							ack := false
							m := crossMsg{ins.Pairs, ins.To.Virtual, input.round + 1, &ack}
							for !ack {
								crossChans[ins.To.Physical] <- m
								time.Sleep(inf.ResendTime)
								if !ack {
									// fmt.Printf("Node %v round %v not yet ACKed; retrying\n", i, input.round+1)
								}
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
				collection := make(map[int]*shuf.Elgamal)
				collect := true
				go func(i int, round int) {
					for collect {
						cm := <-crossChans[i]
						// fmt.Printf("Got something in node %v, round %v with round %v\n", i, round, cm.round)
						if cm.round == round {
							collection[cm.virt] = s.MergeGamal(collection[cm.virt], cm.msgs)
							*(cm.ack) = true
						}
					}
				}(i, round)
				time.Sleep(inf.CollectTime)
				collect = false
				go func(round int) {
					// fmt.Printf("Round %v node %v: sending collection %v\n", round, i, collection)
					for k, v := range collection {
						shuffleChans[i] <- shufMsg{*v, k, round}
					}
				}(round)
			}
		}(i)

	}

	// All clients send their messages
	for m := range pairs {
		go func(m int) {
			ack := false
			sendTo := s.InitialNode(m, inf)
			msg := crossMsg{pairs[m], sendTo.Virtual, 0, &ack}
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
			for {
				finalGamal := <-result[i]
				for _, val := range finalGamal.Y {
					d, e := val.Data()
					if e != nil {
						fmt.Printf("Index %v: Data got corrupted\n", i)
					} else {
						fmt.Printf("Index %v: %v\n", i, string(d))
					}
				}
			}
		}()
	}

}
