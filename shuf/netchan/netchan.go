package netchan

import (
	"encoding/binary"
	"fmt"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/prifi/shuf"
	"log"
	"net"
	"time"
)

type Node struct {
	Inf *shuf.Info
	C   int
}

type Shared struct {
	Cache *shuf.Cache
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
	MsgsPerGroup int
	Seed         int64
	Timeout      int
}

// Handle an incoming connection on the server
func (n Node) handleNodeConnection(conn net.Conn, shared chan Shared, nodes, clients []string) {
	defer conn.Close()
	s := <-shared
	defer func() { shared <- s }()
	round := n.Inf.Active[n.C][s.RIdx]
	var msgRound int32
	binary.Read(conn, binary.BigEndian, &msgRound)
	fmt.Printf("Node %d: got message with round %d on round %d\n", n.C, msgRound, round)
	if msgRound != round {
		return
	}
	_, e := conn.Write([]byte{1})
	if e != nil {
		panic(e)
	}
	var m shuf.Msg
	err := n.readMsg(conn, &m)
	if err != nil {
		panic(err)
	}
	m.Round = round
	to := n.Inf.Routes[n.C][round]
	mp := n.Inf.HandleRound(n.C, &m, s.Cache)
	if mp != nil {
		s.RIdx++
		switch {
		case to == nil:
			for _, cl := range clients {
				n.sendClientMsg(mp, cl)
			}
		case len(to) == 1:
			go n.sendMsg(mp, nodes[to[0]])
		case len(to) == 2:
			fmt.Printf("Node %d: jumping to a new group\n", n.C)
			go n.sendMsg(shuf.GetLeft(*mp), nodes[to[0]])
			go n.sendMsg(shuf.GetRight(*mp), nodes[to[1]])
		}
	}
}

// Handle an incoming connection on the client
func (n Node) handleClientConnection(conn net.Conn) {
	defer conn.Close()
	var m shuf.Msg
	err := n.readMsg(conn, &m)
	if err != nil {
		panic(err)
	}
	n.Inf.HandleClient(n.C, &m)
}

func (n Node) sendClientMsg(m *shuf.Msg, uri string) {
	conn, err := net.Dial("tcp", uri)
	defer conn.Close()
	if err != nil {
		fmt.Printf("%s\n", err.Error())
	} else {
		err = writeMsg(conn, m)
	}
}

func (n Node) sendMsg(m *shuf.Msg, uri string) {
	fmt.Printf("Node %d: sending a message to %s\n", n.C, uri)
	for {
		conn, err := net.Dial("tcp", uri)
		if err != nil {
			fmt.Printf("%s\n", err.Error())
			time.Sleep(n.Inf.ResendTime)
			continue
		}

		// Check if the round number of ok
		binary.Write(conn, binary.BigEndian, int32(m.Round))
		conn.SetReadDeadline(time.Now().Add(n.Inf.ResendTime))
		okBuf := make([]byte, 1)
		_, err = conn.Read(okBuf)
		if err != nil {
			log.Print(err.Error())
			conn.Close()
			time.Sleep(n.Inf.ResendTime)
			continue
		}
		fmt.Printf("Got the ok!\n")
		err = writeMsg(conn, m)
		conn.Close()
		if err != nil {
			panic(err)
		}
		return
	}
}

func (n Node) StartClient(nodes []string, s string, port string) {

	// Send a message to the first node
	r := n.Inf.Suite.Cipher(abstract.RandomKey)
	msgPoint, _ := n.Inf.Suite.Point().Pick([]byte(s), r)
	x, y, to := n.Inf.Setup(msgPoint, n.C)
	go n.sendMsg(&shuf.Msg{X: x, Y: y}, nodes[to])

	// Receive messages from everybody
	ln, err := net.Listen("tcp", port)
	Check(err)
	for {
		conn, err := ln.Accept()
		if err == nil {
			go n.handleClientConnection(conn)
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
			go n.handleNodeConnection(conn, shared, nodes, clients)
		}
	}
}
