package netchan

import (
	"bufio"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/prifi/shuf"
	"net"
	"sync"
	"time"
)

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

func decodeMsg(conn, collect, s, inf, round) {
	reader := bufio.NewReader(conn)
	var r int
	binary.Read(reader, BigEndian, &r)
	if r == round {
		conn.Write([]byte{1})
		var numPairs int
		binary.Read(reader, BigEndian, &numPairs)
		pairs := &Elgamal{[]abstract.Point{}, []abstract.Point{}}
		for i := 0; i < numPairs; i++ {
			x := inf.Suite.Point().UnmarshalFrom(reader)
			*pairs = append(pairs.X, x)
		}
		for i := 0; i < numPairs; i++ {
			y := inf.Suite.Point().UnmarshalFrom(reader)
			*pairs = append(pairs.Y, y)
		}
		h := inf.Suite.Point().UnmarshalFrom(reader)
		collect <- msg{pairs, round, h}
	}
}

func decodeProof(conn, inf, proofCallback) {
	reader := bufio.NewReader(conn)
	var numPairs int
	proof := make([]byte, inf.ProofSize)
	reader.Read(proof)
	binary.Read(reader, BigEndian, &numPairs)
	X := make([]abstract.Point, numPairs)
	for i := 0; i < numPairs; i++ {
		X[i] = inf.Suite.Point().UnmarshalFrom(reader)
	}
	Y := make([]abstract.Point, numPairs)
	for i := 0; i < numPairs; i++ {
		Y[i] = inf.Suite.Point().UnmarshalFrom(reader)
	}
	XX := make([]abstract.Point, numPairs)
	for i := 0; i < numPairs; i++ {
		XX[i] = inf.Suite.Point().UnmarshalFrom(reader)
	}
	YY := make([]abstract.Point, numPairs)
	for i := 0; i < numPairs; i++ {
		YY[i] = inf.Suite.Point().UnmarshalFrom(reader)
	}
	h := inf.Suite.Point().UnmarshalFrom(reader)
	newairs = Elgamal{X, Y}
	oldpairs = Elgamal{XX, YY}
	err := s.VerifyShuffle(newPairs, oldPairs, h, inf, proof)
	if err != nil {
		proofCallback(proofmsg{proof, newpairs, oldpairs, h})
	}
}

func handleConnection(conn Conn, collect chan Elgamal, s shuf.Shuffle,
	inf *Info, round chan int, proofCallback func(proofmsg)) {

	var ty byte
	err := binary.Read(conn, binary.BigEndian, &ty)
	if err == nil {
		switch ty {
		case 0:
			decodeMsg(conn, collect, s, inf, round)
		case 1:
			decodeProof(conn, inf, proofCallback)
		}
	}
}

func sendElgamal(round int, pairs *shuf.Elgamal, h abstract.Point, uri string) {
	for {
		conn, err := net.Dial("tcp", uri)
		if err != nil {
			time.Sleep(1)
			continue
		}
		_, _ = conn.Write([]byte{0})
		conn.SetReadDeadline(time.Now().Add(inf.ResendTime))
		okBuf := make([]byte, 1)
		_, err = conn.Read(okBuf)
		if err == nil {
			writer := bufio.NewWriter(conn)
			binary.Write(writer, binary.BigEndian, len(pairs.X))
			for _, x := range pairs.X {
				x.MarshalTo(writer)
			}
			for _, y := range pairs.Y {
				y.MarshalTo(writer)
			}
			h.MarshalTo(writer)
			writer.Flush()
			conn.Close()
			return
		} else {
			conn.Close()
		}
	}
}

func StartClient(s shuf.Shuffle, c int, nodes []string,
	inf *shuf.Info, msg string, port string) {

	// Setup the message
	rand := inf.Suite.Cipher(abstract.RandomKey)
	p, _ := inf.Suite.Point().Pick([]byte(msg), rand)
	X, Y, H := shuf.OnionEncrypt([]abstract.Point{p}, inf, []int{0})
	pairs := Elgamal{X, Y}

	// Send messages to everybody
	for _, node := range nodes {
		go sendElgamal(0, &pairs, H, node)
	}

	// Receive messages from everybody
	ln, err := net.Listen("tcp", port)
	check(err)
	setter := make(chan Elgamal, 2)
	round := make(chan int, 1)
	round <- inf.NumRounds
	go startCollection(setter, printMsg)
	for {
		conn, err := ln.Accept()
		if err == nil {
			go handleConnection(conn, setter, s, inf, round, printProof)
		}
	}
}

func StartServer(s shuf.Shuffle, c int, clients []string,
	nodes []string, inf *shuf.Info, port string) {

	ln, err := net.Listen("tcp", port)
	check(err)
	setter := make(chan Elgamal, 2)
	round := make(chan int, 1)
	round <- s.ActiveRounds(c, inf)[0]
	proofFn := doProof(clients)
	go startCollection(setter, doMsg(clients, nodes))
	for {
		conn, err := ln.Accept()
		if err == nil {
			go handleConnection(conn, setter, s, inf, round, proofFn)
		}
	}
}
