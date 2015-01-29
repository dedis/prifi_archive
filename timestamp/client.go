package timestamp

import (
	"bytes"
	"log"
	"sync"

	"github.com/dedis/prifi/coconet"
)

type Client struct {
	Mux sync.Mutex // coarse grained mutex

	name string
	Sns  map[string]coconet.Conn // signing nodes I work/ communicate with
	dir  *coconet.GoDirectory    // directory of connection with sns

	// client history maps request numbers to replies from TSServer
	// maybe at later phases we will want pair(reqno, TSServer) as key
	history map[SeqNo]TimeStampMessage
	reqno   SeqNo // next request number in communications with TSServer

	// maps response request numbers to channels confirming
	// where response confirmations are sent
	doneChan map[SeqNo]chan bool

	nRounds     int      // # of last round messages were received in, as perceived by client
	curRoundSig []byte   // merkle tree root of last round
	roundChan   chan int // round numberd are sent in as rounds change
}

func NewClient(name string, dir *coconet.GoDirectory) (c *Client) {
	c = &Client{name: name, dir: dir}
	c.Sns = make(map[string]coconet.Conn)
	c.history = make(map[SeqNo]TimeStampMessage)
	c.doneChan = make(map[SeqNo]chan bool)
	c.roundChan = make(chan int)
	return
}

func (c *Client) Name() string {
	return c.name
}

// Listen to all servers for responses to requests initiated by client
func (cli *Client) Listen() {
	for _, c := range cli.Sns {
		go func(c coconet.Conn) {
			for {
				tsm := &TimeStampMessage{}
				c.Get(tsm)
				cli.handleResponse(tsm)
			}
		}(c)
	}
}

// Act on type of response received from srrvr
func (cli *Client) handleResponse(tsm *TimeStampMessage) {
	switch tsm.Type {
	default:
		log.Println("Message of unknown type")
	case StampReplyType:
		// Process reply and inform done channel associated with
		// reply sequence number that the reply was received
		cli.ProcessStampReply(tsm)

	}
}

// Send data to server given by name (data should be a timestamp request)
func (c *Client) PutToServer(name string, data coconet.BinaryMarshaler) {
	myConn := c.Sns[name]
	myConn.Put(data)
}

// When client asks for val to be timestamped
// It blocks until it get a stamp reply back
func (c *Client) TimeStamp(val []byte, TSServerName string) {
	c.Mux.Lock()
	c.reqno++
	myReqno := c.reqno
	c.doneChan[c.reqno] = make(chan bool, 1) // new done channel for new req
	c.Mux.Unlock()

	// send request to TSServer
	c.PutToServer(TSServerName,
		&TimeStampMessage{
			Type:  StampRequestType,
			ReqNo: myReqno,
			Sreq:  &StampRequest{Val: val}})

	// get channel associated with request
	c.Mux.Lock()
	myChan := c.doneChan[myReqno]
	c.Mux.Unlock()

	// wait until ProcessStampReply signals that reply was received
	<-myChan

	// delete channel as it is of no longer meaningful
	c.Mux.Lock()
	delete(c.doneChan, myReqno)
	c.Mux.Unlock()
}

func (c *Client) ProcessStampReply(tsm *TimeStampMessage) {
	// update client history
	c.Mux.Lock()
	c.history[tsm.ReqNo] = *tsm
	done := c.doneChan[tsm.ReqNo]

	// can keep track of rounds by looking at changes in the signature
	// sent back in a messages
	if bytes.Compare(tsm.Srep.Sig, c.curRoundSig) != 0 {
		c.curRoundSig = tsm.Srep.Sig
		c.nRounds++

		c.Mux.Unlock()
		c.roundChan <- c.nRounds
	} else {
		c.Mux.Unlock()
	}

	done <- true
}

func (c *Client) ShowHistory() {
	for {
		select {
		case nRound := <-c.roundChan:
			if nRound != 1 {
				// If not all replies received by client it will block infinitely
				// fmt.Println("All round", nRound-1, "responses received by", c.Name())
			}
			// c.historyMux.Lock()
			// for _, msg := range c.history {
			// 	fmt.Println("ReqNo =", msg.reqno, "Signature =", msg.Sig)
			// }
			// c.historyMux.Unlock()
		}

	}
}
