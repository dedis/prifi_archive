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

	// Start the Shufflers
	for i := range shuffleChans {
		shuffleChans[i] = make(chan [][]byte)
		initChans[i] = make(chan initMsg)

		// Shuffling step
		go func() {
			for {
				input := <-shuffleChans[i]
				output, next := s.ShuffleStep(input, i, inf)
				if next == nil {
					fmt.Printf("%v done shuffling\n", i)
					break
				} else {
					shuffleChans[*next] <- output
				}
			}
		}()

		// Collection step
		go func() {
			collection := make([][]byte, 0)
			collect := true
			go func() {
				for collect {
					cm := <-initChans[i]
					fmt.Printf("Got a message\n")
					collection = append(collection, cm.msg)
					*(cm.ack) = true
				}
			}()
			time.Sleep(inf.RoundTime)
			fmt.Printf("Done collecting\n")
			collect = false
			shuffleChans[i] <- collection
		}()

	}

	// All clients send their messages
	for m := range msgs {
		go func() {
			ack := false
			msg := initMsg{msg: msgs[m], ack: &ack}
			sendTo := s.InitialNode(msgs[m], inf)
			fmt.Printf("Sending to %v\n", sendTo)
			initChans[sendTo] <- msg
			time.Sleep(inf.ResendTime)
			if ack {
				fmt.Printf("Acknowledged\n")
			} else {
				fmt.Printf("Not Acknowledged\n")
			}
		}()
	}

}
