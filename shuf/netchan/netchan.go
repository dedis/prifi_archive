package netchan

import (
	"encoding/binary"
	// "fmt"
	"bufio"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/prifi/shuf"
	"io"
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

// Handle an incoming connection (on client or server)
func (n Node) handleConnection(conn net.Conn, shared chan Shared, nodes, clients []string) {
	defer conn.Close()
	var m shuf.Msg
	s := <-shared
	defer func() { shared <- s }()
	round := n.Inf.Active[n.C][s.RIdx]
	if n.receiveMsg(conn, round, &m) {
		return
	}
	if s.RIdx == -1 {
		n.Inf.HandleClient(n.C, &m)
		return
	}
	to := n.Inf.Routes[n.C][round]
	mp := n.Inf.HandleRound(n.C, &m, s.Cache)
	if mp != nil {
		s.RIdx++
		switch {
		case to == nil:
			for _, cl := range clients {
				n.sendMsg(mp, cl)
			}
		case len(to) == 1:
			go n.sendMsg(mp, nodes[to[0]])
		case len(to) == 2:
			go n.sendMsg(shuf.GetLeft(*mp), nodes[to[0]])
			go n.sendMsg(shuf.GetRight(*mp), nodes[to[1]])
		}
	}
}

func (n Node) receiveProofs(reader io.Reader) []shuf.Proof {
	var numProofs, proofLen int
	binary.Read(reader, binary.BigEndian, &numProofs)
	Proofs := make([]shuf.Proof, numProofs)
	for i := range Proofs {
		Proofs[i].X, Proofs[i].Y = n.receivePairs(reader)
		binary.Read(reader, binary.BigEndian, &proofLen)
		Proofs[i].Proof = make([]byte, proofLen)
		reader.Read(Proofs[i].Proof)
	}
	return Proofs
}

func (n Node) receivePairs(reader io.Reader) ([]abstract.Point, []abstract.Point) {
	var numPairs int
	binary.Read(reader, binary.BigEndian, &numPairs)
	X := make([]abstract.Point, numPairs)
	Y := make([]abstract.Point, numPairs)
	for i := range X {
		X[i] = n.Inf.Suite.Point()
		X[i].UnmarshalFrom(reader)
	}
	for i := range Y {
		Y[i] = n.Inf.Suite.Point()
		Y[i].UnmarshalFrom(reader)
	}
	return X, Y
}

func (n Node) receiveMsg(conn net.Conn, round int, m *shuf.Msg) bool {

	// Check that the round matches
	reader := bufio.NewReader(conn)
	var r int
	binary.Read(reader, binary.BigEndian, &r)
	if r != round {
		return true
	}
	m.Round = r
	conn.Write([]byte{1})

	// Get the pairs
	m.X, m.Y = n.receivePairs(reader)
	var numXs int
	binary.Read(reader, binary.BigEndian, &numXs)
	NewX := make([]abstract.Point, numXs)
	for i := range NewX {
		NewX[i] = n.Inf.Suite.Point()
		NewX[i].UnmarshalFrom(reader)
	}

	// Get the proofs
	m.LeftProofs = n.receiveProofs(reader)
	m.RightProofs = n.receiveProofs(reader)
	m.ShufProofs = n.receiveProofs(reader)
	return false
}

func (n Node) sendMsg(m *shuf.Msg, uri string) {
	for {
		conn, err := net.Dial("tcp", uri)
		if err != nil {
			time.Sleep(n.Inf.ResendTime)
			continue
		}

		// Check if the round number of ok
		binary.Write(conn, binary.BigEndian, m.Round)
		conn.SetReadDeadline(time.Now().Add(n.Inf.ResendTime))
		okBuf := make([]byte, 1)
		_, err = conn.Read(okBuf)
		if err != nil {
			conn.Close()
			continue
		}
		writer := bufio.NewWriter(conn)

		// Send the pairs
		binary.Write(writer, binary.BigEndian, len(m.X))
		for _, x := range m.X {
			x.MarshalTo(writer)
		}
		for _, y := range m.Y {
			y.MarshalTo(writer)
		}
		binary.Write(writer, binary.BigEndian, len(m.NewX))
		for _, x := range m.NewX {
			x.MarshalTo(writer)
		}

		// Send the proofs
		binary.Write(writer, binary.BigEndian, len(m.ShufProofs))
		for _, p := range m.ShufProofs {
			binary.Write(writer, binary.BigEndian, len(p.X))
			for _, x := range p.X {
				x.MarshalTo(writer)
			}
			for _, y := range p.Y {
				y.MarshalTo(writer)
			}
			binary.Write(writer, binary.BigEndian, len(p.Proof))
			writer.Write(p.Proof)
		}
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
