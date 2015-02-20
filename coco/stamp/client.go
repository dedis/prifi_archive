package stamp

import (
	"bytes"
	"errors"
	"io"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"

	"github.com/dedis/prifi/coco/coconet"
	"github.com/dedis/prifi/coco/test/logutils"
)

type Client struct {
	Mux sync.Mutex // coarse grained mutex

	name    string
	Servers map[string]coconet.Conn // signing nodes I work/ communicate with

	// client history maps request numbers to replies from TSServer
	// maybe at later phases we will want pair(reqno, TSServer) as key
	history map[SeqNo]TimeStampMessage
	reqno   SeqNo // next request number in communications with TSServer

	// maps response request numbers to channels confirming
	// where response confirmations are sent
	doneChan map[SeqNo]chan bool

	nRounds     int    // # of last round messages were received in, as perceived by client
	curRoundSig []byte // merkle tree root of last round
	// roundChan   chan int // round numberd are sent in as rounds change
}

func NewClient(name string) (c *Client) {
	c = &Client{name: name}
	c.Servers = make(map[string]coconet.Conn)
	c.history = make(map[SeqNo]TimeStampMessage)
	c.doneChan = make(map[SeqNo]chan bool)
	// c.roundChan = make(chan int)
	return
}

func (c *Client) Name() string {
	return c.name
}

// Listen must be called before Connect
// func (c *Client) Connect() error {
// 	var err error
// 	for _, conn := range c.Servers {
// 		e := conn.Connect()
// 		if e != nil {
// 			log.Println("failed to connect to server:", e)
// 			err = e
// 			continue
// 		}
// 		go handleServer(conn)
// 	}
// 	return err
// }

func (c *Client) Close() {
	for _, c := range c.Servers {
		log.Println("CLOSING SERVER")
		c.Close()
	}
}

func (c *Client) handleServer(s coconet.Conn) error {
	for {
		tsm := &TimeStampMessage{}
		// log.Println("connection:", s)
		err := <-s.Get(tsm)
		if err != nil {
			return err
		}
		c.handleResponse(tsm)
	}
}

// XXX: Listen to server responses?
// This doesn't make that much sense.
// I should connect to the server and then handle the connection.
// func (c *Client) Listen() {
// 	for _, s := range c.Servers {
// 		go handleServer(s)
// 	}
// }

// Act on type of response received from srrvr
func (c *Client) handleResponse(tsm *TimeStampMessage) {
	switch tsm.Type {
	default:
		log.Println("Message of unknown type")
	case StampReplyType:
		// Process reply and inform done channel associated with
		// reply sequence number that the reply was received
		c.ProcessStampReply(tsm)

	}
}

func (c *Client) AddServer(name string, conn coconet.Conn) {
	//c.Servers[name] = conn
	go func(conn coconet.Conn) {
		for {
			// log.Println("Conn Before Connection:", conn)
			err := conn.Connect()
			// log.Println("Conn After Connection:", conn, err)
			if err != nil {
				// log.Println("FAILURE: failed to connect to server:", err)
				time.Sleep(500 * time.Millisecond)
				continue
			} else {
				c.Mux.Lock()
				c.Servers[name] = conn
				c.Mux.Unlock()
				log.Println("SUCCESS: connected to server:", conn)
				if c.handleServer(conn) == io.EOF {
					c.Servers[name] = nil
					return
				} else {
					// try reconnecting if it didn't close the channel
					continue
				}
			}
		}
	}(conn)
}

// Send data to server given by name (data should be a timestamp request)
func (c *Client) PutToServer(name string, data coconet.BinaryMarshaler) error {
	c.Mux.Lock()
	defer c.Mux.Unlock()
	conn := c.Servers[name]
	if conn == nil {
		log.WithFields(log.Fields{
			"file": logutils.File(),
		}).Warnln("Server is nil:", c.Servers, "with: ", name)
		return errors.New("INVALID SERVER/NOT CONNECTED")
	}
	// log.Println("PUT CONN: ", conn)
	return <-conn.Put(data)
}

// When client asks for val to be timestamped
// It blocks until it get a stamp reply back
func (c *Client) TimeStamp(val []byte, TSServerName string) error {

	c.Mux.Lock()
	c.reqno++
	myReqno := c.reqno
	c.doneChan[c.reqno] = make(chan bool, 1) // new done channel for new req
	c.Mux.Unlock()
	// send request to TSServer
	// log.Println("SENDING TIME STAMP REQUEST TO: ", TSServerName)
	err := c.PutToServer(TSServerName,
		&TimeStampMessage{
			Type:  StampRequestType,
			ReqNo: myReqno,
			Sreq:  &StampRequest{Val: val}})
	if err != nil {
		return err
	}

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
	return nil
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
		//c.roundChan <- c.nRounds
	} else {
		c.Mux.Unlock()
	}
	done <- true
}

// func (c *Client) ShowHistory() {
// 	for {
// 		select {
// 		case nRound := <-c.roundChan:
// 			if nRound != 1 {
// 				// If not all replies received by client it will block infinitely
// 				// fmt.Println("All round", nRound-1, "responses received by", c.Name())
// 			}
// 			// c.historyMux.Lock()
// 			// for _, msg := range c.history {
// 			// 	fmt.Println("ReqNo =", msg.reqno, "Signature =", msg.Sig)
// 			// }
// 			// c.historyMux.Unlock()
// 		}

// 	}
// }
