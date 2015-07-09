package main

import (
	"fmt"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/prifi/shuf"
	"log"
	"sync"
	"time"
)

// A message with an ACK chan
type wrapper struct {
	m   *shuf.Msg
	ack chan bool
}

func sendTo(inf *shuf.Info, c chan wrapper, m *shuf.Msg) {
	w := wrapper{m, make(chan bool)}
	for i := 0; i < inf.MaxResends+1; i++ {
		c <- w
		select {
		case <-w.ack:
			return
		case <-time.After(inf.ResendTime):
			fmt.Printf("Resending round %d\n", m.Round)
		}
	}
	fmt.Printf("Couldn't send message for round %d\n", m.Round)
}

func ChanShuffle(inf *shuf.Info, msgs []abstract.Point, wg *sync.WaitGroup) {

	// Fake internet
	messages := make([]chan wrapper, inf.NumNodes)
	results := make([]chan wrapper, inf.NumClients)
	for i := range results {
		results[i] = make(chan wrapper)
	}
	for i := range messages {
		messages[i] = make(chan wrapper)
	}

	// Start the nodes
	for i := range messages {

		// For each round it's active, wait for a message
		go func(i int) {

			cache := new(shuf.Cache)
			for ridx := 0; ridx < len(inf.Active[i]); {
				round := inf.Active[i][ridx]
				w := <-messages[i]
				log.Printf("Node %d: got message with round %d on round %d, size %d\n", i, w.m.Round, round, len(w.m.Y))
				if w.m.Round != round {
					continue
				}
				w.ack <- true
				m := inf.HandleRound(i, w.m, cache)
				to := inf.Routes[i][round]

				// Forward the new message
				if m != nil {
					ridx++
					switch {
					case to == nil:
						log.Printf("Node %d: sending back %d msgs\n", i, len(m.Y))
						for _, cl := range results {
							cl <- wrapper{m, nil}
						}
					case len(to) == 1:
						log.Printf("Node %d: sending to %d, round %d\n", i, to[0], m.Round)
						go sendTo(inf, messages[to[0]], m)
					case len(to) == 2:
						log.Printf("Node %d: jumping to a new group\n", i)
						leftMsg := shuf.GetLeft(*m)
						rightMsg := shuf.GetRight(*m)
						go sendTo(inf, messages[to[0]], leftMsg)
						go sendTo(inf, messages[to[1]], rightMsg)
					}
				}
			}
		}(i)
	}

	// All clients send and receive their messages
	for i := range msgs {
		go func(i int) {
			X, Y, to := inf.Setup(msgs[i], i)
			go sendTo(inf, messages[to], &shuf.Msg{NewX: X, Y: Y})
			defer wg.Done()
			seen := 0
			for seen < inf.NumClients {
				select {
				case w := <-results[i]:
					seen += inf.HandleClient(i, w.m)
				case <-time.After(inf.Timeout):
					fmt.Printf("Client %d timed out\n", i)
					return
				}
			}
		}(i)
	}
}
