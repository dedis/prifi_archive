package netchan

import (
	"encoding/binary"
	"fmt"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/prifi/shuf"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
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
	var mstats runtime.MemStats
	runtime.ReadMemStats(&mstats)
	fmt.Printf("ALLOC: %d,%d,%d,%d\n", mstats.HeapSys, mstats.HeapAlloc, mstats.HeapIdle, mstats.HeapReleased)

	defer conn.Close()
	s := <-shared
	defer func() { shared <- s }()
	round := n.Inf.Active[n.C][s.RIdx]
	var msgRound int32
	binary.Read(conn, binary.BigEndian, &msgRound)
	log.Printf("Node %d: got message with round %d on round %d\n", n.C, msgRound, round)
	if msgRound != round {
		return
	}
	_, e := conn.Write([]byte{1})
	if e != nil {
		log.Printf("Node %d: cannot ack; %s\n", n.C, e.Error())
		return
	}
	var m shuf.Msg
	err := n.readMsg(conn, &m)
	if err != nil {
		log.Printf("Node %d: invalid message; %s\n", n.C, err.Error())
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
		log.Printf("%s\n", err.Error())
	} else {
		defer conn.Close()
		err = writeMsg(conn, m)
	}
}

func (n Node) sendMsg(m *shuf.Msg, uri string) {
	log.Printf("Node %d: sending a message to %s\n", n.C, uri)
	for i := 0; i < n.Inf.MaxResends+1; i++ {
		conn, err := net.Dial("tcp", uri)
		if err != nil {
			log.Printf("Node %d: %s\n", n.C, err.Error())
			time.Sleep(n.Inf.ResendTime)
			continue
		}

		// Check if the round number of ok
		binary.Write(conn, binary.BigEndian, int32(m.Round))
		conn.SetReadDeadline(time.Now().Add(n.Inf.ResendTime))
		okBuf := make([]byte, 1)
		_, err = conn.Read(okBuf)
		if err != nil {
			conn.Close()
			time.Sleep(n.Inf.ResendTime)
			continue
		}
		err = writeMsg(conn, m)
		conn.Close()
		if err != nil {
			log.Printf("Node %d: couldn't write message; %s\n", n.C, err.Error())
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
		fmt.Printf("Client %d timed out\n", n.C)
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
