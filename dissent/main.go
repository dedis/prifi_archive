package main

import (
	"io"
	"os"
	"net"
	"fmt"
	"log"
	"flag"
	"errors"
	//"net/http"
	"os/signal"
	//"encoding/hex"
	"encoding/binary"
	"github.com/dedis/crypto/nist"
	"github.com/dedis/crypto/test"
	"github.com/dedis/crypto/openssl"
	"dissent/dcnet"
	//"github.com/elazarl/goproxy"
)


var suite = nist.NewAES128SHA256P256()	// XXX should only have defaultSuite
//var suite = openssl.NewAES128SHA256P256()
//var suite = ed25519.NewAES128SHA256Ed25519()
var factory = dcnet.OwnedCoderFactory

var defaultSuite = suite

const nclients = 5
const ntrustees = 3

const relayhost = "localhost:9876"	// XXX
const bindport = ":9876"

//const payloadlen = 1200			// upstream cell size
const payloadlen = 256			// upstream cell size

const downcellmax = 16*1024		// downstream cell max size

// Number of bytes of cell payload to reserve for connection header, length
const proxyhdrlen = 6

type connbuf struct {
	cno int			// connection number
	buf []byte		// data buffer
}



func testSuites() {
	test.TestSuite(nist.NewAES128SHA256QR512())
	test.TestSuite(nist.NewAES128SHA256P256())
	test.TestSuite(openssl.NewAES128SHA256P256())
}

func testDCNet() {
	//dcnet.TestCellCoder(suite, factory)
	dcnet.TestCellCoder(suite, factory)
}


func min(x,y int) int {
	if x < y {
		return x
	}
	return y
}

type chanreader struct {
	b []byte
	c <-chan []byte
	eof bool
}

func (cr *chanreader) Read(p []byte) (n int, err error) {
	if cr.eof {
		return 0, io.EOF
	}
	blen := len(cr.b)
	if blen == 0 {
		cr.b = <-cr.c		// read next block from channel
		blen = len(cr.b)
		if blen == 0 {		// channel sender signaled EOF
			cr.eof = true
			return 0, io.EOF
		}
	}

	act := min(blen, len(p))
	copy(p, cr.b[:act])
	cr.b = cr.b[act:]
	return act, nil
}

func newChanReader(c <-chan []byte) *chanreader {
	return &chanreader{[]byte{}, c, false}
}

// Authentication methods
const (
	methNoAuth = iota
	methGSS
	methUserPass
	methNone = 0xff
)

// Address types
const (
	addrIPv4 = 0x01
	addrDomain = 0x03
	addrIPv6 = 0x04
)

// Commands
const (
	cmdConnect = 0x01
	cmdBind = 0x02
	cmdAssociate = 0x03
)

// Reply codes
const (
	repSucceeded = iota
	repGeneralFailure
	repConnectionNotAllowed
	repNetworkUnreachable
	repHostUnreachable
	repConnectionRefused
	repTTLExpired
	repCommandNotSupported
	repAddressTypeNotSupported
)

var errAddressTypeNotSupported = errors.New("SOCKS5 address type not supported")

// Read an IPv4 or IPv6 address from an io.Reader and return it as a string
func readIP(r io.Reader, len int) (string, error) {
	addr := make([]byte, len)
	_,err := io.ReadFull(r, addr)
	if err != nil {
		return "", err
	}
	return net.IP(addr).String(), nil
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

func socksRelayDown(cno int, conn net.Conn, downstream chan<- connbuf) {
	//log.Printf("socksRelayDown: cno %d\n", cno)
	for {
		buf := make([]byte, downcellmax)
		n,err := conn.Read(buf)
		buf = buf[:n]
		//fmt.Printf("socksRelayDown: %d bytes on cno %d\n", n, cno)
		//fmt.Print(hex.Dump(buf[:n]))

		// Forward the data (or close indication if n==0) downstream
		downstream <- connbuf{cno, buf}

		// Connection error or EOF?
		if n == 0 {
			log.Println("socksRelayDown: "+err.Error())
			conn.Close()
			return
		}
	}
}

func socksRelayUp(cno int, conn net.Conn, upstream <-chan []byte) {
	//log.Printf("socksRelayUp: cno %d\n", cno)
	for {
		// Get the next upstream data buffer
		buf := <-upstream
		dlen := len(buf)
		//fmt.Printf("socksRelayUp: %d bytes on cno %d\n", len(buf), cno)
		//fmt.Print(hex.Dump(buf))

		if dlen == 0 {		// connection close indicator
			log.Printf("socksRelayUp: closing stream %d\n", cno)
			conn.Close()
			return
		}
		//println(hex.Dump(buf))
		n,err := conn.Write(buf)
		if n != dlen {
			log.Printf("socksRelayUp: "+err.Error())
			conn.Close()
			return
		}
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

func startClient(clino int) {
	fmt.Printf("startClient %d\n", clino)

	tg := dcnet.TestSetup(suite, factory, nclients, ntrustees)
	me := tg.Clients[clino]
	clisize := me.Coder.ClientCellSize(payloadlen)

	rconn := openRelay(clino)
	fromrelay := make(chan connbuf)
	go clientReadRelay(rconn, fromrelay)
	println("client",clino,"connected")

	// We're the "slot owner" - start an HTTP proxy
	newconn := make(chan net.Conn)
	upload := make(chan []byte)
	close := make(chan int)
	conns := make([]net.Conn, 1)	// reserve conns[0]
	if clino == 0 {
		go clientListen(":1080",newconn)
		//go clientListen(":8080",newconn)
	}

	// Client/proxy main loop
	upq := make([][]byte,0)
	totupcells := uint64(0)
	totupbytes := uint64(0)
	for {
		select {
		case conn := <-newconn:		// New TCP connection
			cno := len(conns)
			conns = append(conns, conn)
			//fmt.Printf("new conn %d %p %p\n", cno, conn, conns[cno])
			go clientConnRead(cno, conn, upload, close)

		case buf := <-upload:		// Upstream data from client
			upq = append(upq, buf)

		case cno := <-close:		// Connection closed
			conns[cno] = nil

		case cbuf := <-fromrelay:	// Downstream cell from relay
			//print(".")

			cno := cbuf.cno
			//if cno != 0 || len(cbuf.buf) != 0 {
			//	fmt.Printf("v %d (conn %d)\n",
			//			len(cbuf.buf), cno)
			//}
			if cno > 0 && cno < len(conns) && conns[cno] != nil {
				buf := cbuf.buf
				blen := len(buf)
				//println(hex.Dump(buf))
				if blen > 0 {
					// Data from relay for this connection
					n,err := conns[cno].Write(buf)
					if n < blen {
						panic("Write to client: " +
							err.Error())
					}
				} else {
					// Relay indicating EOF on this conn
					fmt.Printf("upstream closed conn %d",
							cno);
					conns[cno].Close()
				}
			}

			// XXX account for downstream cell in history

			// Produce and ship the next upstream cell
			var p []byte
			if len(upq) > 0 {
				p = upq[0]
				upq = upq[1:]
				//fmt.Printf("^ %d\n", len(p))
			}
			slice := me.Coder.ClientEncode(p, payloadlen,
							me.Histoream)
			//println("client slice")
			//println(hex.Dump(slice))
			if len(slice) != clisize {
				panic("client slice wrong size")
			}
			n,err := rconn.Write(slice)
			if n != len(slice) {
				panic("Write to relay conn: "+err.Error())
			}

			totupcells++
			totupbytes += uint64(payloadlen)
			//fmt.Printf("sent %d upstream cells, %d bytes\n",
			//		totupcells, totupbytes)
		}
	}
}

func startTrustee(tno int) {
	tg := dcnet.TestSetup(suite, factory, nclients, ntrustees)
	me := tg.Trustees[tno]

	conn := openRelay(tno | 0x80)
	println("trustee",tno,"connected")

	// Just generate ciphertext cells and stream them to the server.
	for {
		// Produce a cell worth of trustee ciphertext
		tslice := me.Coder.TrusteeEncode(payloadlen)

		// Send it to the relay
		//println("trustee slice")
		//println(hex.Dump(tslice))
		n,err := conn.Write(tslice)
		if n < len(tslice) || err != nil {
			panic("can't write to socket: "+err.Error())
		}
	}
}

func interceptCtrlC() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func(){
		for sig := range c {
			panic("signal: "+sig.String())	// with stacktrace
		}
	}()
}

func main() {
	interceptCtrlC()

	//testSuites()
	//testDCNet()

	isrel := flag.Bool("relay", false, "Start relay node")
	iscli := flag.Int("client", -1, "Start client node")
	istru := flag.Int("trustee", -1, "Start trustee node")
	flag.Parse()

	readConfig()

	if *isrel {
		startRelay()
	} else if *iscli >= 0 {
		startClient(*iscli)
	} else if *istru >= 0 {
		startTrustee(*istru)
	} else {
		panic("must specify -relay, -client=n, or -trustee=n")
	}
}

