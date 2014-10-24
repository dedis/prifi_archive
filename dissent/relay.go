package main

import (
	"io"
	"fmt"
	"net"
	"log"
	"time"
	"encoding/binary"
	"github.com/dedis/crypto/abstract"
	"dissent/dcnet"
)

type Trustee struct {
	pubkey abstract.Point
}

type AnonSet struct {
	suite abstract.Suite
	trustees []Trustee
}

func startRelay() {
	tg := dcnet.TestSetup(suite, factory, nclients, ntrustees)
	me := tg.Relay

	// Start our own local HTTP proxy for simplicity.
/*
	go func() {
		proxy := goproxy.NewProxyHttpServer()
		proxy.Verbose = true
		println("Starting HTTP proxy")
		log.Fatal(http.ListenAndServe(":8888", proxy))
	}()
*/

	lsock,err := net.Listen("tcp", bindport)
	if err != nil {
		panic("Can't open listen socket:"+err.Error())
	}

	// Wait for all the clients and trustees to connect
	ccli := 0
	ctru := 0
	csock := make([]net.Conn, nclients)
	tsock := make([]net.Conn, ntrustees)
	for ; ccli < nclients || ctru < ntrustees ; {
		fmt.Printf("Waiting for %d clients, %d trustees\n",
				nclients-ccli, ntrustees-ctru)

		conn,err := lsock.Accept()
		if err != nil {
			panic("Listen error:"+err.Error())
		}

		b := make([]byte,1)
		n,err := conn.Read(b)
		if n < 1 || err != nil {
			panic("Read error:"+err.Error())
		}

		node := int(b[0] & 0x7f)
		if b[0] & 0x80 == 0 && node < nclients {
			if csock[node] != nil {
				panic("Oops, client connected twice")
			}
			csock[node] = conn
			ccli++
		} else if b[0] & 0x80 != 0 && node < ntrustees {
			if tsock[node] != nil {
				panic("Oops, trustee connected twice")
			}
			tsock[node] = conn
			ctru++
		} else {
			panic("illegal node number")
		}
	}
	println("All clients and trustees connected")

	// Create ciphertext slice buffers for all clients and trustees
	clisize := me.Coder.ClientCellSize(payloadlen)
	cslice := make([][]byte, nclients)
	for i := 0; i < nclients; i++ {
		cslice[i] = make([]byte, clisize)
	}
	trusize := me.Coder.TrusteeCellSize(payloadlen)
	tslice := make([][]byte, ntrustees)
	for i := 0; i < ntrustees; i++ {
		tslice[i] = make([]byte, trusize)
	}

	// Periodic stats reporting
	begin := time.Now()
	report := begin
	period,_ := time.ParseDuration("3s")
	totupcells := int64(0)
	totupbytes := int64(0)
	totdowncells := int64(0)
	totdownbytes := int64(0)

	conns := make(map[int] chan<- []byte)
	downstream := make(chan connbuf)
	nulldown := connbuf{}	// default empty downstream cell
	window := 2		// Maximum cells in-flight
	inflight := 0		// Current cells in-flight
	for {
		//print(".")

		// Show periodic reports
		now := time.Now()
		if now.After(report) {
			duration := now.Sub(begin).Seconds()
			fmt.Printf("@ %f sec: %d cells, %f cells/sec, %d upbytes, %f upbytes/sec, %d downbytes, %f downbytes/sec\n",
				duration,
				totupcells, float64(totupcells) / duration,
				totupbytes, float64(totupbytes) / duration,
				totdownbytes, float64(totdownbytes) / duration)

			// Next report time
			report = now.Add(period)
		}

		// See if there's any downstream data to forward.
		var downbuf connbuf
		select {
		case downbuf = <-downstream: // some data to forward downstream
			//fmt.Printf("v %d\n", len(dbuf)-6)
		default:		// nothing at the moment to forward
			downbuf = nulldown
		}
		dlen := len(downbuf.buf)
		dbuf := make([]byte, 6+dlen)
		binary.BigEndian.PutUint32(dbuf[0:4], uint32(downbuf.cno))
		binary.BigEndian.PutUint16(dbuf[4:6], uint16(dlen))
		copy(dbuf[6:], downbuf.buf)

		// Broadcast the downstream data to all clients.
		for i := 0; i < nclients; i++ {
			//fmt.Printf("client %d -> %d downstream bytes\n",
			//		i, len(dbuf)-6)
			n,err := csock[i].Write(dbuf)
			if n != 6+dlen {
				panic("Write to client: "+err.Error())
			}
		}
		totdowncells++
		totdownbytes += int64(dlen)
		//fmt.Printf("sent %d downstream cells, %d bytes \n",
		//		totdowncells, totdownbytes)

		inflight++
		if inflight < window {
			continue	// Get more cells in flight
		}

		me.Coder.DecodeStart(payloadlen, me.Histoream)

		// Collect a cell ciphertext from each trustee
		for i := 0; i < ntrustees; i++ {
			n,err := io.ReadFull(tsock[i], tslice[i])
			if n < trusize {
				panic("Read from client: "+err.Error())
			}
			//println("trustee slice")
			//println(hex.Dump(tslice[i]))
			me.Coder.DecodeTrustee(tslice[i])
		}

		// Collect an upstream ciphertext from each client
		for i := 0; i < nclients; i++ {
			n,err := io.ReadFull(csock[i], cslice[i])
			if n < clisize {
				panic("Read from client: "+err.Error())
			}
			//println("client slice")
			//println(hex.Dump(cslice[i]))
			me.Coder.DecodeClient(cslice[i])
		}

		outb := me.Coder.DecodeCell()
		inflight--

		totupcells++
		totupbytes += int64(payloadlen)
		//fmt.Printf("received %d upstream cells, %d bytes\n",
		//		totupcells, totupbytes)

		// Process the decoded cell
		if outb == nil {
			continue	// empty or corrupt upstream cell
		}
		if len(outb) != payloadlen {
			panic("DecodeCell produced wrong-size payload")
		}

		// Decode the upstream cell header (may be empty, all zeros)
		cno := int(binary.BigEndian.Uint32(outb[0:4]))
		uplen := int(binary.BigEndian.Uint16(outb[4:6]))
		//fmt.Printf("^ %d (conn %d)\n", uplen, cno)
		if cno == 0 {
			continue	// no upstream data
		}
		conn := conns[cno]
		if conn == nil {	// client initiating new connection
			conn = relayNewConn(cno, downstream)
			conns[cno] = conn
		}
		if 6+uplen > payloadlen {
			log.Printf("upstream cell invalid length %d", 6+uplen)
			continue
		}
		conn <- outb[6:6+uplen]
	}
}

