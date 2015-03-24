package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"log"
	"encoding/binary"
)

// Main loop of our socks relay-side SOCKS proxy.
func relaySocksProxy(cno int, upstream <-chan []byte,
				downstream chan<- connbuf) {

	// Send downstream close indication when we bail for whatever reason
	defer func() {
		downstream <- connbuf{cno, []byte{}}
	}()

	// Put a convenient I/O wrapper around the raw upstream channel
	cr := newChanReader(upstream)

	// Read the SOCKS client's version/methods header
	vernmeth := [2]byte{}
	_,err := io.ReadFull(cr, vernmeth[:])
	if err != nil {
		log.Printf("SOCKS: no version/method header: "+err.Error())
		return
	}
	//log.Printf("SOCKS proxy: version %d nmethods %d \n",
	//	vernmeth[0], vernmeth[1])
	ver := int(vernmeth[0])
	if ver != 5 {
		log.Printf("SOCKS: unsupported version number %d", ver)
		return
	}
	nmeth := int(vernmeth[1])
	methods := make([]byte, nmeth)
	_,err = io.ReadFull(cr, methods)
	if err != nil {
		log.Printf("SOCKS: short version/method header: "+err.Error())
		return
	}

	// Find a supported method (currently only NoAuth)
	for i := 0; ; i++ {
		if i >= len(methods) {
			log.Printf("SOCKS: no supported method")
			resp := [2]byte{byte(ver), byte(methNone)}
			downstream <- connbuf{cno, resp[:]}
			return
		}
		if methods[i] == methNoAuth {
			break
		}
	}

	// Reply with the chosen method
	methresp := [2]byte{byte(ver), byte(methNoAuth)}
	downstream <- connbuf{cno, methresp[:]}

	// Receive client request
	req := make([]byte, 4)
	_,err = io.ReadFull(cr, req)
	if err != nil {
		log.Printf("SOCKS: missing client request: "+err.Error())
		return
	}
	if req[0] != byte(ver) {
		log.Printf("SOCKS: client changed versions")
		return
	}
	host, err := readSocksAddr(cr, int(req[3]))
	if err != nil {
		log.Printf("SOCKS: invalid destination address: "+err.Error())
		return
	}
	portb := [2]byte{}
	_,err = io.ReadFull(cr, portb[:])
	if err != nil {
		log.Printf("SOCKS: invalid destination port: "+err.Error())
		return
	}
	port := binary.BigEndian.Uint16(portb[:])
	hostport := fmt.Sprintf("%s:%d", host, port)

	// Process the command
	cmd := int(req[1])
	//log.Printf("SOCKS proxy: request %d for %s\n", cmd, hostport)
	switch cmd {
	case cmdConnect:
		conn,err := net.Dial("tcp", hostport)
		if err != nil {
			log.Printf("SOCKS: error connecting to destionation: "+
					err.Error())
			downstream <- socks5Reply(cno, err, nil)
			return
		}

		// Send success reply downstream
		downstream <- socks5Reply(cno, nil, conn.LocalAddr())

		// Commence forwarding raw data on the connection
		go socksRelayDown(cno, conn, downstream)
		socksRelayUp(cno, conn, upstream)

	default:
		log.Printf("SOCKS: unsupported command %d", cmd)
	}
}

func readSocksAddr(cr io.Reader, addrtype int) (string, error) {
	switch addrtype {
	case addrIPv4:
		return readIP(cr, net.IPv4len)

	case addrIPv6:
		return readIP(cr, net.IPv6len)

	case addrDomain:

		// First read the 1-byte domain name length
		dlen := [1]byte{}
		_,err := io.ReadFull(cr, dlen[:])
		if err != nil {
			return "", err
		}

		// Now the domain name itself
		domain := make([]byte, int(dlen[0]))
		_,err = io.ReadFull(cr, domain)
		if err != nil {
			return "", err
		}
		log.Printf("SOCKS: domain '%s'\n", string(domain))

		return string(domain), nil

	default:
		msg := fmt.Sprintf("unknown SOCKS address type %d", addrtype)
		return "", errors.New(msg)
	}
}

func socks5Reply(cno int, err error, addr net.Addr) connbuf {

	buf := make([]byte, 4)
	buf[0] = byte(5)	// version

	// buf[1]: Reply field
	switch err {
	case nil:	// succeeded
		buf[1] = repSucceeded
	// XXX recognize some specific errors
	default:
		buf[1] = repGeneralFailure
	}

	// Address type
	if addr != nil {
		tcpaddr := addr.(*net.TCPAddr)
		host4 := tcpaddr.IP.To4()
		host6 := tcpaddr.IP.To16()
		port := [2]byte{}
		binary.BigEndian.PutUint16(port[:], uint16(tcpaddr.Port))
		if host4 != nil {		// it's an IPv4 address
			buf[3] = addrIPv4
			buf = append(buf, host4...)
			buf = append(buf, port[:]...)
		} else if host6 != nil {	// it's an IPv6 address
			buf[3] = addrIPv6
			buf = append(buf, host6...)
			buf = append(buf, port[:]...)
		} else {			// huh???
			log.Printf("SOCKS: neither IPv4 nor IPv6 addr?")
			addr = nil
			err = errAddressTypeNotSupported
		}
	}
	if addr == nil {	// attach a null IPv4 address
		buf[3] = addrIPv4
		buf = append(buf, make([]byte, 4+2)...)
	}

	// Reply code
	var rep int
	switch err {
	case nil:
		rep = repSucceeded
	case errAddressTypeNotSupported:
		rep = repAddressTypeNotSupported
	default:
		rep = repGeneralFailure
	}
	buf[1] = byte(rep)

	//log.Printf("SOCKS5 reply:\n" + hex.Dump(buf))
	return connbuf{cno, buf}
}


func relayNewConn(cno int, downstream chan<- connbuf) chan<- []byte {

/* connect to local HTTP proxy
	conn,err := net.Dial("tcp", "localhost:8888")
	if err != nil {
		panic("error dialing proxy: "+err.Error())
	}
	go relayReadConn(cno, conn, downstream)
*/

	upstream := make(chan []byte)
	go relaySocksProxy(cno, upstream, downstream)
	return upstream
}

