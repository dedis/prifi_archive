package netchan

import (
	"bufio"
	"encoding/gob"
	"fmt"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/prifi/shuf"
	"net"
	"time"
)

type Node struct {
	Inf *shuf.Info
	C   int
}

type Shared struct {
	Cache *Cache
	RIdx  int
}

func Check(e error) {
	if e != nil {
		panic(e.Error())
	}
}

type CFile struct {
	NumNodes     int
	NumClients   int
	NumRounds    int
	ResendTime   int
	Port         string
	Shuffle      string
	MsgsPerGroup int
	Seed         int64
	Timeout      int
}

// Handle an incoming connection (on client or server)
func (n Node) handleConnection(conn net.Conn, shared chan *Shared, nodes, clients []string) {
	dec := gob.NewDecoder(conn)
	var m Msg
	err = dec.Decode(&m)
	if err != nil {
		fmt.Printf("Encoding error: %s\n", err.Error())
		return nil
	}
	s := <-shared
	defer func() { shared <- s }()
	if s.RIdx == -1 {
		n.Inf.HandleClient(n.C, &m)
		return
	}
	round := inf.Active[n.C][s.RIdx]
	if round == m.Round {
		conn.Write([]byte{1})
		to := inf.Routes[i][round]
		m := inf.HandleRound(n.C, m, s.Cache)
		if m != nil {
			s.RIdx++
			switch {
			case to == nil:
				for _, cl := range clients {
					n.sendMsg(m, cl)
				}
			case len(to) == 1:
				go n.sendMsg(m, nodes[to[0]])
			case len(to) == 2:
				go n.sendMsg(shuf.GetLeft(*m), nodes[to[0]])
				go n.sendMsg(shuf.GetRight(*m), nodes[to[1]])
			}
		}
	}
}

func (n Node) sendMsg(m shuf.Msg, uri string) {
	var conn net.Conn
	for {
		var err error
		conn, err = net.Dial("tcp", uri)
		if err == nil {
			break
		}
		time.Sleep(1)
	}
	enc := gob.NewEncoder(conn)
	for {
		err := enc.Encode(m)
		if err != nil {
			fmt.Printf("Encoding error: %s\n", err.Error())
		}
		conn.SetReadDeadline(time.Now().Add(n.Inf.ResendTime))
		okBuf := make([]byte, 1)
		_, err = conn.Read(okBuf)
		if err == nil {
			break
		}
	}
}

func (n Node) StartClient(nodes []string, s string, port string) {

	// Send a message to the first node
	r := n.Inf.Suite.Cipher(abstract.RandomKey)
	msgPoint, _ := n.Inf.Suite.Point().Pick([]byte(s), r)
	x, y, to := n.Inf.Setup(msgPoint, n.C)
	go n.sendMsg(&shuf.Msg{X: X, Y: Y}, nodes[to])

	// Receive messages from everybody
	ln, err := net.Listen("tcp", port)
	Check(err)
	shared := make(chan Shared, 1)
	shared <- Shared{new(shuf.Cache), -1}
	for {
		conn, err := ln.Accept()
		if err == nil {
			go n.handleConnection(conn, shared, nodes, nil)
		}
	}
}

func (n Node) StartServer(clients []string, nodes []string, port string) {
	ln, err := net.Listen("tcp", port)
	Check(err)
	shared := make(chan Shared, 1)
	shared <- Shared{new(shuf.Cache), 0}
	for {
		conn, err := ln.Accept()
		if err == nil {
			go n.handleConnection(conn, shared, nodes, clients)
		}
	}
}
