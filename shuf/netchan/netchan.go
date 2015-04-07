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

type Node struct {
	Inf *shuf.Info
	S shuf.Shuffle
	C int
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

func Check(e error) {
	if e != nil {
		panic(e.Error())
	}
}

type CFile struct {
	NumNodes int
	NumClients int
	NumRounds int
	ResendTime int
	Port string
	Shuffle string
}

// Read a msg from the connection and feed it to the collector
func (n Node) decodeMsg(conn net.Conn, collect chan msg, round chan int) {
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
			x := n.Inf.Suite.Point()
			x.UnmarshalFrom(reader)
			pairs.X = append(pairs.X, x)
		}
		for i := 0; i < numPairs; i++ {
			y := n.Inf.Suite.Point()
			y.UnmarshalFrom(reader)
			pairs.Y = append(pairs.Y, y)
		}
		h := n.Inf.Suite.Point()
		h.UnmarshalFrom(reader)
		collect <- msg{*pairs, theround, h}
	}
	round <- theround
}

// Read a proof from the connection and call the callback
func (n Node) decodeProof(conn net.Conn, proofCallback func(proofmsg)) {
	reader := bufio.NewReader(conn)
	var numPairs int
	proof := make([]byte, n.Inf.ProofSize)
	reader.Read(proof)
	binary.Read(reader, binary.BigEndian, &numPairs)
	X := make([]abstract.Point, numPairs)
	for i := 0; i < numPairs; i++ {
		X[i] = n.Inf.Suite.Point()
		X[i].UnmarshalFrom(reader)
	}
	Y := make([]abstract.Point, numPairs)
	for i := 0; i < numPairs; i++ {
		Y[i] = n.Inf.Suite.Point()
		Y[i].UnmarshalFrom(reader)
	}
	XX := make([]abstract.Point, numPairs)
	for i := 0; i < numPairs; i++ {
		XX[i] = n.Inf.Suite.Point()
		XX[i].UnmarshalFrom(reader)
	}
	YY := make([]abstract.Point, numPairs)
	for i := 0; i < numPairs; i++ {
		YY[i] = n.Inf.Suite.Point()
		YY[i].UnmarshalFrom(reader)
	}
	h := n.Inf.Suite.Point()
	h.UnmarshalFrom(reader)
	newPairs := shuf.Elgamal{X, Y}
	oldPairs := shuf.Elgamal{XX, YY}
	err := n.S.VerifyShuffle(newPairs, oldPairs, h, n.Inf, proof)
	if err != nil {
		proofCallback(proofmsg{proof, newPairs, oldPairs, h})
	}
}

func (n Node) sendProof(p proofmsg, uri string) {
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
func (n Node) handleConnection(conn net.Conn, collect chan msg,
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
func (n Node) startCollection(setter chan msg, round chan int, callback func(msg)) {
	X := make([]abstract.Point, 0)
	Y := make([]abstract.Point, 0)
	var H abstract.Point
	for len(X) < n.Inf.MsgsPerGroup {
		m := <-setter
		X = append(X, m.pairs.X...)
		Y = append(Y, m.pairs.Y...)
		H = m.h
	}
	r := <-round
	callback(msg{shuf.Elgamal{X,Y}, n.S.ActiveRounds(n.C, n.Inf)[r], H})
	round <- r+1
}

func (n Node) forwardProof(clients []string) func(proofmsg) {
	return func(p proofmsg) {
		for _, c := range clients {
			n.sendProof(p, c)
		}
	}
}

func (n Node) forwardMessage(clients, nodes []string) func(msg) {
	return func(m msg) {
		oldpairs := m.pairs
		instr := n.S.ShuffleStep(oldpairs, n.C, m.round, n.Inf, m.h)
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

func (n Node) sendMsg(m msg, uri string) {
	for {
		conn, err := net.Dial("tcp", uri)
		if err != nil {
			time.Sleep(1)
			continue
		}
		conn.Write([]byte{0})
		binary.Write(conn, binary.BigEndian, m.round)
		conn.SetReadDeadline(time.Now().Add(n.Inf.ResendTime))
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

func (n Node) StartClient(nodes []string, s string, port string) {

	// Send messages to everybody
	r := n.Inf.Suite.Cipher(abstract.RandomKey)
	msgPoint, _ := n.Inf.Suite.Point().Pick([]byte(s), r)
	pairs, H, sendTo := n.S.Setup(msgPoint, n.C, n.Inf)
	go n.sendMsg(msg{pairs,0,H}, nodes[sendTo])

	// Receive messages from everybody
	ln, err := net.Listen("tcp", port)
	Check(err)
	setter := make(chan msg, 2)
	round := make(chan int, 1)
	round <- n.Inf.NumRounds
	go n.startCollection(setter, round, printMsg)
	for {
		conn, err := ln.Accept()
		if err == nil {
			go n.handleConnection(conn, setter, round, printProof)
		}
	}
}

func (n Node) StartServer(clients []string, nodes []string, port string) {
	ln, err := net.Listen("tcp", port)
	Check(err)
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
