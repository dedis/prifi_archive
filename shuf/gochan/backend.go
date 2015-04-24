package main

import (
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/prifi/shuf"
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
	for {
		c <- w
		select {
		case <-w.ack:
			break
		case <-time.After(inf.ResendTime):
		}
	}
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
			for round := range inf.Active[i] {
				w := <-messages[i]
				if w.m.Round != round {
					continue
				}
				w.ack <- true
				m := inf.HandleRound(i, w.m)
				to := inf.Routes[i][round]

				// Forward the new message
				if m != nil {
					switch {
					case to == nil:
						for _, cl := range results {
							cl <- wrapper{m, nil}
						}
					case len(to) == 1:
						go sendTo(inf, messages[to[0]], m)
					case len(to) == 2:
						go sendTo(inf, messages[to[0]], shuf.GetLeft(*m))
						go sendTo(inf, messages[to[1]], shuf.GetRight(*m))
					}
				}
			}
		}(i)
	}

	// All clients send and receive their messages
	for i := range msgs {
		go func(i int) {
			X, Y, to := inf.Setup(msgs[i], i)
			go sendTo(inf, messages[to], &shuf.Msg{X: X, Y: Y})
			w := <-results[i]
			inf.HandleClient(i, w.m)
			wg.Done()
		}(i)
	}
}
