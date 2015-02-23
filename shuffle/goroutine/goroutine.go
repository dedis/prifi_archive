package goroutine

import (
	"fmt"
	"github.com/dedis/prifi/shuffle"
	"time"
)

/*
PROTOCOL DESCRIPTION:
=====================

Clients:
- send their message to a node by NextNode
- wait for an ACK
- if they don't get one, resend in x seconds
- then wait for their result
- prettyprint their result when it comes in

Shufflers:
- wait for roundTime, collecting messages matching the seqno
- pass the collection to the Shuffler
- if shuffling is done, pass the result to the Crosser
- make sure all messages get ACKs before going to the next round
*/

// TODO: make sure there's no duplicates
// TODO: probably need a lock on collection slice

type crossMsg struct {
	msg   []byte
	seqno int
	ack   *bool
}

type shufMsg struct {
	msgs  [][]byte
	seqno int
}

func ChanShuffle(s shuffle.Shuffler, r shuffle.Crosser,
	inf *shuffle.SharedInfo, msgs [][]byte) {

	// Fake internet
	shuffleChans := make([]chan shufMsg, inf.NumNodes)
	crossChans := make([]chan crossMsg, inf.NumNodes)

	// Start the Shufflers
	for i := range shuffleChans {
		shuffleChans[i] = make(chan shufMsg)
		crossChans[i] = make(chan crossMsg)

		// Mixing step
		cross := func(myMsgs [][]byte, seqno int) {
			for m := range myMsgs {
				np := r.NextNode(myMsgs[m], &i, inf)
				if np == nil {
					fmt.Printf("%v done shuffling %v\n", i, m)
				} else {
					ack := false
					msg := crossMsg{msg: myMsgs[m], seqno: seqno, ack: &ack}
					go func() {
						for {
							crossChans[*np] <- msg
							time.Sleep(inf.ResendTime)
							if ack {
								break
							}
						}
					}()
				}
			}
		}

		// Shuffling step- runs forever
		go func() {
			for {
				input := <-shuffleChans[i]
				output, next := s.ShuffleStep(input.msgs, i, inf)
				if next == nil {
					go cross(output, input.seqno)
				} else {
					shuffleChans[*next] <- shufMsg{msgs: output, seqno: input.seqno}
				}
			}
		}()

		// Collection step
		go func() {
			for round := 0; round < inf.NumRounds; round++ {
				collection := make([][]byte, 0)
				collect := true
				go func() {
					for collect {
						cm := <-crossChans[i]
						fmt.Printf("Got a message\n")
						if cm.seqno == round {
							collection = append(collection, cm.msg)
							*(cm.ack) = true
						}
					}
				}()
				time.Sleep(inf.RoundTime)
				fmt.Printf("Done collecting\n")
				collect = false
				shuffleChans[i] <- shufMsg{msgs: collection, seqno: round}
			}
		}()
	}

	// All clients send their messages
	for m := range msgs {
		go func() {
			ack := false
			for {
				msg := crossMsg{msg: msgs[m], seqno: 0, ack: &ack}
				sendTo := *(r.NextNode(msgs[m], nil, inf))
				fmt.Printf("Sending to %v\n", sendTo)
				crossChans[sendTo] <- msg
				time.Sleep(inf.ResendTime)
				if ack {
					fmt.Printf("Acknowledged\n")
					break
				} else {
					fmt.Printf("Not Acknowledged\n")
				}
			}
		}()
	}

}
