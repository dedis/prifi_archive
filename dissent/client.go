package main

import (
	"io"
	"net"
	"log"
	"encoding/binary"
)

func openRelay(ctno int) net.Conn {
	conn,err := net.Dial("tcp", relayhost)
	if err != nil {
		panic("Can't connect to relay:"+err.Error())
	}

	// Tell the relay our client or trustee number
	b := make([]byte,1)
	b[0] = byte(ctno)
	n,err := conn.Write(b)
	if n < 1 || err != nil {
		panic("Error writing to socket:"+err.Error())
	}

	return conn
}

func clientListen(listenport string, newconn chan<- net.Conn) {
	log.Printf("Listening on port %s\n", listenport)
	lsock,err := net.Listen("tcp", listenport)
	if err != nil {
		log.Printf("Can't open listen socket at port %s: %s",
				listenport, err.Error())
		return
	}
	for {
		conn,err := lsock.Accept()
		log.Printf("Accept on port %s\n", listenport)
		if err != nil {
			//log.Printf("Accept error: %s", err.Error())
			lsock.Close()
			return
		}
		newconn <- conn
	}
}

func clientConnRead(cno int, conn net.Conn, upload chan<- []byte,
		close chan<- int) {

	for {
		// Read up to a cell worth of data to send upstream
		buf := make([]byte, payloadlen)
		n,err := conn.Read(buf[proxyhdrlen:])

		// Encode the connection number and actual data length
		binary.BigEndian.PutUint32(buf[0:4], uint32(cno))
		binary.BigEndian.PutUint16(buf[4:6], uint16(n))

		// Send it upstream!
		upload <- buf
		//fmt.Printf("read %d bytes from client %d\n", n, cno)

		// Connection error or EOF?
		if n == 0 {
			if err == io.EOF {
				println("clientUpload: EOF, closing")
			} else {
				println("clientUpload: "+err.Error())
			}
			conn.Close()
			close <- cno	// signal that channel is closed
			return
		}
	}
}

func clientReadRelay(rconn net.Conn, fromrelay chan<- connbuf) {
	hdr := [6]byte{}
	totcells := uint64(0)
	totbytes := uint64(0)
	for {
		// Read the next downstream/broadcast cell from the relay
		n,err := io.ReadFull(rconn, hdr[:])
		if n != len(hdr) {
			panic("clientReadRelay: "+err.Error())
		}
		cno := int(binary.BigEndian.Uint32(hdr[0:4]))
		dlen := int(binary.BigEndian.Uint16(hdr[4:6]))
		//if cno != 0 || dlen != 0 {
		//	fmt.Printf("clientReadRelay: cno %d dlen %d\n",
		//			cno, dlen)
		//}

		// Read the downstream data itself
		buf := make([]byte, dlen)
		n,err = io.ReadFull(rconn, buf)
		if n != dlen {
			panic("clientReadRelay: "+err.Error())
		}

		// Pass the downstream cell to the main loop
		fromrelay <- connbuf{cno,buf}

		totcells++
		totbytes += uint64(dlen)
		//fmt.Printf("read %d downstream cells, %d bytes\n",
		//		totcells, totbytes)
	}
}

