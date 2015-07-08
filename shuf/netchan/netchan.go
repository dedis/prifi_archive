package netchan

import (
	"encoding/binary"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/prifi/shuf"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
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
	NumNodes      int
	NumClients    int
	NumRounds     int
	ResendTime    int
	MsgsPerGroup  int
	Seed          int64
	Shuffle       string
	Split         string
	Timeout       int
	MaxResends    int
	ActiveClients int
}

// Handle an incoming connection on the server
func (n Node) handleNodeConnection(conn net.Conn, shared chan Shared, nodes, clients []string) {
	defer conn.Close()
	s := <-shared
	defer func() { shared <- s }()
	round := n.Inf.Active[n.C][s.RIdx]
	var msgRound int32
	err := binary.Read(conn, binary.BigEndian, &msgRound)
	if err != nil {
		log.Printf("Error: node %d round %d: %s", n.C, round, err.Error())
		return
	}
	log.Printf("Node %d: got message with round %d on round %d\n", n.C, msgRound, round)
	if msgRound != round {
		return
	}
	_, err = conn.Write([]byte{1})
	if err != nil {
		log.Printf("Error: node %d: cannot ack; %s\n", n.C, err.Error())
		return
	}
	var m shuf.Msg
	err = n.readMsg(conn, &m)
	if err != nil {
		log.Printf("Error: node %d: invalid message; %s\n", n.C, err.Error())
		return
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
			log.Printf("Node %d: jumping to a new group\n", n.C)
			go n.sendMsg(shuf.GetLeft(*mp), nodes[to[0]])
			go n.sendMsg(shuf.GetRight(*mp), nodes[to[1]])
		}
	}
}

// Handle an incoming connection on the client
func (n Node) handleClientConnection(conn net.Conn, seen chan int, die chan bool) {
	defer conn.Close()
	var m shuf.Msg
	err := n.readMsg(conn, &m)
	if err != nil {
		log.Printf("Client %d: decoding error; %s\n", err.Error())
	}
	s := <-seen
	s += n.Inf.HandleClient(n.C, &m)
	seen <- s
	if s >= n.Inf.NumClients {
		die <- true
	}
}

func (n Node) sendClientMsg(m *shuf.Msg, uri string) {
	conn, err := net.Dial("tcp", uri)
	if err != nil {
		log.Printf("Error: %s\n", err.Error())
	} else {
		defer conn.Close()
		err = writeMsg(conn, m)
		if err != nil {
			log.Printf("Error: %s\n", err.Error())
		}
	}
}

func (n Node) sendMsg(m *shuf.Msg, uri string) {
	log.Printf("Node %d: sending a message to %s\n", n.C, uri)
	for i := 0; i < n.Inf.MaxResends+1; i++ {
		conn, err := net.Dial("tcp", uri)
		if err != nil {
			log.Printf("Error: node %d: %s\n", n.C, err.Error())
			time.Sleep(n.Inf.ResendTime)
			continue
		}

		// Check if the round number of ok
		err = binary.Write(conn, binary.BigEndian, int32(m.Round))
		if err != nil {
			conn.Close()
			log.Printf("Write round error: node %d: %s\n", n.C, err.Error())
			time.Sleep(n.Inf.ResendTime)
			continue
		}
		err = conn.SetReadDeadline(time.Now().Add(n.Inf.ResendTime))
		if err != nil {
			conn.Close()
			log.Printf("Set deadline error: node %d: %s\n", n.C, err.Error())
			time.Sleep(n.Inf.ResendTime)
			continue
		}
		okBuf := make([]byte, 1)
		_, err = io.ReadFull(conn, okBuf)
		if err != nil { // Not ready for message
			conn.Close()
			time.Sleep(n.Inf.ResendTime)
			continue
		}
		err = writeMsg(conn, m)
		conn.Close()
		if err != nil {
			log.Printf("Write msg error: node %d; %s\n", n.C, err.Error())
			time.Sleep(n.Inf.ResendTime)
			continue
		}
		return
	}
}

func (n Node) StartClient(nodes []string, msgPoint abstract.Point, port string) {

	// Send a message to the first node
	x, y, to := n.Inf.Setup(msgPoint, n.C)
	go n.sendMsg(&shuf.Msg{NewX: x, Y: y}, nodes[to])

	// Receive messages from everybody
	die := make(chan bool)
	ln, err := net.Listen("tcp", port)
	Check(err)
	go func() {
		seen := make(chan int, 1)
		seen <- 0
		for {
			conn, err := ln.Accept()
			if err == nil {
				go n.handleClientConnection(conn, seen, die)
			}
		}
	}()

	// Wait for interrupt, completion, or timeout
	ch := make(chan os.Signal)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-ch:
		ln.Close()
		os.Exit(1)
	case <-die:
		ln.Close()
		os.Exit(0)
	case <-time.After(n.Inf.Timeout):
		ln.Close()
		log.Printf("Client %d timed out\n", n.C)
		os.Exit(1)
	}
}

func (n Node) StartServer(clients []string, nodes []string, port string) {
	ln, err := net.Listen("tcp", port)
	Check(err)
	shared := make(chan Shared, 1)
	shared <- Shared{new(shuf.Cache), 0}
	go func() {
		for {
			conn, err := ln.Accept()
			if err == nil {
				go n.handleNodeConnection(conn, shared, nodes, clients)
			}
		}
	}()

	// Wait for interrupt
	ch := make(chan os.Signal)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-ch:
		ln.Close()
		os.Exit(0)
	}
}
