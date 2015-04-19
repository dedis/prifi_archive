package main

import (
	"fmt"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/prifi/shuf"
	"sync"
	"time"
)

// A message containing the newest shuffled order
type msg struct {
	pairs shuf.Elgamal
	round int
	h     abstract.Point
	ack   *bool
}

func ChanShuffle(s shuf.Shuffle, inf *shuf.Info, msgs []abstract.Point, wg *sync.WaitGroup) {

	// Fake internet
	chans := make([]chan msg, inf.NumNodes)
	proofs := make([]chan shuf.Proof, inf.NumNodes)
	result := make([]chan shuf.Elgamal, inf.NumClients)
	cproofs := make([]chan shuf.Proof, inf.NumClients)
	for i := range result {
		result[i] = make(chan shuf.Elgamal)
		cproofs[i] = make(chan shuf.Proof)
	}
	for i := range chans {
		chans[i] = make(chan msg)
		proofs[i] = make(chan shuf.Proof)
	}

	// Start the Shufflers
	for i := range chans {

		// Verification step
		go func(i int) {
			for {
				p := <-proofs[i]
				err := shuf.VerifyProof(inf, p)
				if err != nil {
					fmt.Printf("Node %v found a proof error: %s\n", i, err.Error())
					for cl := range cproofs {
						cproofs[cl] <- p
					}
				}
			}
		}(i)

		// Collection step
		go func(i int) {
			for _, round := range s.ActiveRounds(i, inf) {
				var xs, ys []abstract.Point
				var H abstract.Point
				for len(xs) < inf.MsgsPerGroup {
					cm := <-chans[i]
					if cm.round == round {
						if xs == nil {
							xs = cm.pairs.X
							ys = cm.pairs.Y
						} else {
							xs = append(xs, cm.pairs.X...)
							ys = append(ys, cm.pairs.Y...)
						}
						H = cm.h
						*(cm.ack) = true
					}
				}

				// Shuffling step
				oldpairs := shuf.Elgamal{xs, ys}
				instr := s.ShuffleStep(oldpairs, i, round, inf, H)
				if instr.ShufProof != nil && instr.DecryptProof != nil {
					for cl := range proofs {
						proofs[cl] <- shuf.Proof{
							ShufProof:    instr.ShufProof,
							DecryptProof: instr.DecryptProof,
							PlainY:       instr.PlainY,
							ShufPairs:    instr.ShufPairs,
							OldPairs:     oldpairs,
							H:            H,
						}
					}
				}
				if instr.To == nil {
					for cl := range result {
						result[cl] <- instr.NewPairs
					}
				} else {
					chunk := len(instr.NewPairs.Y) / len(instr.To)
					if chunk*len(instr.To) != len(instr.NewPairs.Y) {
						fmt.Printf("Node %v round %v cannot divide cleanly\n", i, round+1)
						chunk = len(instr.NewPairs.Y)
					}
					pairIdx := 0
					for _, to := range instr.To {
						go func(pairIdx int, to int) {
							ack := false
							gml := shuf.Elgamal{
								instr.NewPairs.X[pairIdx : pairIdx+chunk],
								instr.NewPairs.Y[pairIdx : pairIdx+chunk],
							}
							m := msg{gml, round + 1, instr.H, &ack}
							for !ack {
								chans[to] <- m
								time.Sleep(inf.ResendTime)
								if !ack {
									fmt.Printf("Node %v round %v not yet ACKed; retrying\n", i, round+1)
								}
							}
						}(pairIdx, to)
						pairIdx += chunk
					}
				}
			}
		}(i)
	}

	// All clients send their messages
	for i := range msgs {
		go func(i int) {
			ack := false
			pairs, H, sendTo := s.Setup(msgs[i], i, inf)
			m := msg{pairs, 0, H, &ack}
			for !ack {
				chans[sendTo] <- m
				time.Sleep(inf.ResendTime)
				if !ack {
					fmt.Printf("Client %v not ACKed\n", i)
				}
			}
		}(i)
	}

	for i := range cproofs {
		done := false

		// All clients check for proofs of false shuffles
		go func(i int, done *bool) {
			for !(*done) {
				p := <-cproofs[i]
				err := shuf.VerifyProof(inf, p)
				if err != nil {
					fmt.Printf("Client %v found a proof error: %s\n", i, err.Error())
					*done = true
				}
			}
		}(i, &done)

		// Print out the order as it comes in
		go func(i int, done *bool) {
			counter := 0
			for counter < inf.NumClients && !(*done) {
				finalGamal := <-result[i]
				counter += len(finalGamal.Y)
				for _, val := range finalGamal.Y {
					d, e := val.Data()
					if e != nil {
						fmt.Printf("Client %v: Data got corrupted\n", i)
					} else {
						fmt.Printf("Client %v: %v\n", i, string(d))
					}
				}
			}
			*done = true
			wg.Done()
		}(i, &done)
	}

}
