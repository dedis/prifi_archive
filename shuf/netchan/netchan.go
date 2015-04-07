package netchan

import (
	"bufio"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/prifi/shuf"
	"net"
	"time"
	"fmt"
	"encoding/binary"
)

type node struct {
	inf *shuf.Info
	s shuf.Shuffle
	c int
}

type msg struct {
	pairs shuf.Elgamal
	round int
	h     abstract.Point
}

type proofmsg struct {
	proof    []byte
	newpairs shuf.Elgamal
	oldpairs shuf.Elgamal
	h        abstract.Point
}

func check(e error) {
	if e != nil {
		panic(e.Error())
	}
}

// Read a msg from the connection and feed it to the collector
func (n node) decodeMsg(conn net.Conn, collect chan msg, round chan int) {
	reader := bufio.NewReader(conn)
	var r int
	binary.Read(reader, binary.BigEndian, &r)
	theround := <-round
	if r == theround {
		conn.Write([]byte{1})
		var numPairs int
		binary.Read(reader, binary.BigEndian, &numPairs)
		pairs := &shuf.Elgamal{[]abstract.Point{}, []abstract.Point{}}
		for i := 0; i < numPairs; i++ {
			x := n.inf.Suite.Point()
			x.UnmarshalFrom(reader)
			pairs.X = append(pairs.X, x)
		}
		for i := 0; i < numPairs; i++ {
			y := n.inf.Suite.Point()
			y.UnmarshalFrom(reader)
			pairs.Y = append(pairs.Y, y)
		}
		h := n.inf.Suite.Point()
		h.UnmarshalFrom(reader)
		collect <- msg{*pairs, theround, h}
	}
	round <- theround
}

// Read a proof from the connection and call the callback
func (n node) decodeProof(conn net.Conn, proofCallback func(proofmsg)) {
	reader := bufio.NewReader(conn)
	var numPairs int
	proof := make([]byte, n.inf.ProofSize)
	reader.Read(proof)
	binary.Read(reader, binary.BigEndian, &numPairs)
	X := make([]abstract.Point, numPairs)
	for i := 0; i < numPairs; i++ {
		X[i] = n.inf.Suite.Point()
		X[i].UnmarshalFrom(reader)
	}
	Y := make([]abstract.Point, numPairs)
	for i := 0; i < numPairs; i++ {
		Y[i] = n.inf.Suite.Point()
		Y[i].UnmarshalFrom(reader)
	}
	XX := make([]abstract.Point, numPairs)
	for i := 0; i < numPairs; i++ {
		XX[i] = n.inf.Suite.Point()
		XX[i].UnmarshalFrom(reader)
	}
	YY := make([]abstract.Point, numPairs)
	for i := 0; i < numPairs; i++ {
		YY[i] = n.inf.Suite.Point()
		YY[i].UnmarshalFrom(reader)
	}
	h := n.inf.Suite.Point()
	h.UnmarshalFrom(reader)
	newPairs := shuf.Elgamal{X, Y}
	oldPairs := shuf.Elgamal{XX, YY}
	err := n.s.VerifyShuffle(newPairs, oldPairs, h, n.inf, proof)
	if err != nil {
		proofCallback(proofmsg{proof, newPairs, oldPairs, h})
	}
}

func (n node) sendProof(p proofmsg, uri string) {
	for {
		conn, err := net.Dial("tcp", uri)
		if err != nil {
			time.Sleep(1)
			continue
		}
		writer := bufio.NewWriter(conn)
		writer.Write([]byte{1})
		writer.Write(p.proof)
		binary.Write(writer, binary.BigEndian, len(p.oldpairs.X))
		for _, x := range p.oldpairs.X {
			x.MarshalTo(writer)
		}
		for _, y := range p.oldpairs.Y {
			y.MarshalTo(writer)
		}
		for _, x := range p.newpairs.X {
			x.MarshalTo(writer)
		}
		for _, y := range p.newpairs.Y {
			y.MarshalTo(writer)
		}
		p.h.MarshalTo(writer)
		writer.Flush()
		conn.Close()
		return
	}
}

// Handle an incoming connection (on client or server)
func (n node) handleConnection(conn net.Conn, collect chan msg,
	round chan int, proofCallback func(proofmsg)) {

	var ty byte
	err := binary.Read(conn, binary.BigEndian, &ty)
	if err == nil {
		switch ty {
		case 0:
			n.decodeMsg(conn, collect, round)
		case 1:
			n.decodeProof(conn, proofCallback)
		}
	}
}

// Start the collection thread
func (n node) startCollection(setter chan msg, round chan int, callback func(msg)) {
	X := make([]abstract.Point, 0)
	Y := make([]abstract.Point, 0)
	var H abstract.Point
	for len(X) < n.inf.MsgsPerGroup {
		m := <-setter
		X = append(X, m.pairs.X...)
		Y = append(Y, m.pairs.Y...)
		H = m.h
	}
	r := <-round
	callback(msg{shuf.Elgamal{X,Y}, n.s.ActiveRounds(n.c, n.inf)[r], H})
	round <- r+1
}

func (n node) forwardProof(clients []string) func(proofmsg) {
	return func(p proofmsg) {
		for _, c := range clients {
			n.sendProof(p, c)
		}
	}
}

func (n node) forwardMessage(clients, nodes []string) func(msg) {
	return func(m msg) {
		oldpairs := m.pairs
		instr := n.s.ShuffleStep(oldpairs, n.c, m.round, n.inf, m.h)
		if instr.To == nil {
			for _, cl := range clients {
				go n.sendMsg(msg{instr.Pairs, m.round+1, instr.H}, cl)
			}
		} else {
			for _, cl := range nodes {
				go n.sendProof(proofmsg{instr.Proof, instr.Pairs, oldpairs, instr.H}, cl)
			}
			chunk := len(instr.Pairs.Y) / len(instr.To)
			if chunk*len(instr.To) != len(instr.Pairs.Y) {
				fmt.Printf("Round %d: cannot divide cleanly\n", m.round+1)
				chunk = len(instr.Pairs.Y)
			}
			for _, to := range instr.To {
				go n.sendMsg(msg{instr.Pairs, m.round+1, instr.H}, nodes[to])
			}
		}
	}
}

func printProof(p proofmsg) {
	fmt.Printf("Received proof of wrongdoing\n")
}

func printMsg(m msg) {
	for _,y := range m.pairs.Y {
		d, e := y.Data()
		if e != nil {
			fmt.Printf("Data got corrupted")
		} else {
			fmt.Printf("%v\n", d)
		}
	}
}

func (n node) sendMsg(m msg, uri string) {
	for {
		conn, err := net.Dial("tcp", uri)
		if err != nil {
			time.Sleep(1)
			continue
		}
		conn.Write([]byte{0})
		binary.Write(conn, binary.BigEndian, m.round)
		conn.SetReadDeadline(time.Now().Add(n.inf.ResendTime))
		okBuf := make([]byte, 1)
		_, err = conn.Read(okBuf)
		if err == nil {
			writer := bufio.NewWriter(conn)
			binary.Write(writer, binary.BigEndian, len(m.pairs.X))
			for _, x := range m.pairs.X {
				x.MarshalTo(writer)
			}
			for _, y := range m.pairs.Y {
				y.MarshalTo(writer)
			}
			m.h.MarshalTo(writer)
			writer.Flush()
			conn.Close()
			return
		} else {
			conn.Close()
		}
	}
}

func (n node) StartClient(nodes []string, s string, port string) {

	// Send messages to everybody
	r := n.inf.Suite.Cipher(abstract.RandomKey)
	msgPoint, _ := n.inf.Suite.Point().Pick([]byte(s), r)
	pairs, H, sendTo := n.s.Setup(msgPoint, n.c, n.inf)
	go n.sendMsg(msg{pairs,0,H}, nodes[sendTo])

	// Receive messages from everybody
	ln, err := net.Listen("tcp", port)
	check(err)
	setter := make(chan msg, 2)
	round := make(chan int, 1)
	round <- n.inf.NumRounds
	go n.startCollection(setter, round, printMsg)
	for {
		conn, err := ln.Accept()
		if err == nil {
			go n.handleConnection(conn, setter, round, printProof)
		}
	}
}

func (n node) StartServer(clients []string, nodes []string, port string) {
	ln, err := net.Listen("tcp", port)
	check(err)
	setter := make(chan msg, 2)
	round := make(chan int, 1)
	round <- 0
	proofFn := n.forwardProof(clients)
	go n.startCollection(setter, round, n.forwardMessage(clients, nodes))
	for {
		conn, err := ln.Accept()
		if err == nil {
			go n.handleConnection(conn, setter, round, proofFn)
		}
	}
}
