package time

import (
	"bytes"
	"fmt"
	"sync"

	"github.com/dedis/prifi/coco"
)

type Client struct {
	name    string
	servers map[string]*coco.GoConn // servers I "work" with
	dir     *coco.GoDirectory       // directory of connection with servers

	// client history maps request numbers to replies from server
	// maybe at later phases we will want pair(reqno, server) as key
	history map[SeqNoType]TimeStampMessage
	reqno   SeqNoType // next request number in communications with server
	// historyMux sync.Mutex

	// maps response request numbers to channels confirming
	// where response confirmations are sent
	doneChan map[SeqNoType]chan bool

	nRounds     int        // # of last round messages received in, as perceived by client
	curRoundSig []byte     // merkle tree root of last round
	roundChan   chan int   // round numberd are sent in as rounds change
	Mux         sync.Mutex // potentially coarse grained mutex
}

func (cli *Client) handleRequest(tsm *TimeStampMessage) {
	switch tsm.Type {
	default:
		fmt.Println("Message of unknown type")
	case StampReplyType:
		cli.ProcessStampReply(tsm)

	}
}

func (cli *Client) Listen() {
	for _, c := range cli.servers {
		go func(c *coco.GoConn) {
			for {
				tsm := &TimeStampMessage{}
				c.Get(tsm)
				cli.handleRequest(tsm)
			}
		}(c)
	}
}

func NewClient(name string, dir *coco.GoDirectory) (c *Client) {
	c = &Client{name: name, dir: dir}
	c.servers = make(map[string]*coco.GoConn)
	c.history = make(map[SeqNoType]TimeStampMessage)
	c.doneChan = make(map[SeqNoType]chan bool)
	c.roundChan = make(chan int)
	return
}

func (c *Client) Name() string {
	return c.name
}

func (c *Client) Put(name string, data coco.BinaryMarshaler) {
	myConn := c.servers[name]
	myConn.Put(data)
}

func (c *Client) TimeStamp(val []byte, serverName string) {
	// new request requires new done channel
	c.Mux.Lock()
	c.reqno++
	c.doneChan[c.reqno] = make(chan bool, 1)

	myReqno := c.reqno
	fmt.Println("client putting out", myReqno)
	c.Mux.Unlock()

	// send request to server
	c.Put(serverName,
		&TimeStampMessage{
			Type:  StampRequestType,
			ReqNo: myReqno,
			sreq:  &StampRequest{Val: val}})

	// get channel associated with request
	c.Mux.Lock()
	myChan := c.doneChan[myReqno]
	// delete(c.doneChan, myReqno)
	c.Mux.Unlock()

	// wait for response to request
	fmt.Println("wating for", myReqno)
	<-myChan
}

func (c *Client) ProcessStampReply(tsm *TimeStampMessage) {
	// fmt.Println("Client processing", tsm.ReqNo)
	// update client history
	c.Mux.Lock()
	c.history[tsm.ReqNo] = *tsm
	done := c.doneChan[tsm.ReqNo]

	// can keep track of rounds
	if bytes.Compare(tsm.srep.Sig, c.curRoundSig) != 0 {
		c.curRoundSig = tsm.srep.Sig
		c.nRounds++
		if c.nRounds != 1 {
			c.Mux.Unlock()
			c.roundChan <- c.nRounds
		} else {
			c.Mux.Unlock()
		}
	} else {
		c.Mux.Unlock()
	}

	fmt.Println("Message reqno", tsm.ReqNo, "processed in round", c.nRounds)
	done <- true
}

func (c *Client) showHistory() {
	for {
		select {
		case nRound := <-c.roundChan:
			fmt.Println("All round", nRound, "responses received")
			// c.historyMux.Lock()
			// for _, msg := range c.history {
			// 	fmt.Println("ReqNo =", msg.reqno, "Signature =", msg.Sig)
			// }
			// c.historyMux.Unlock()
		}

	}
}
