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
	"github.com/dedis/crypto/nist"
	"github.com/dedis/crypto/test"
	"github.com/dedis/crypto/openssl"
	"github.com/dedis/prifi/dcnet"
	//"github.com/elazarl/goproxy"
)


var suite = nist.NewAES128SHA256P256()	// XXX should only have defaultSuite
//var suite = openssl.NewAES128SHA256P256()
//var suite = ed25519.NewAES128SHA256Ed25519()
var factory = dcnet.OwnedCoderFactory
// var factory = dcnet.SimpleCoderFactory

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

func startClient(clino int, port int) {
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
		go clientListen(fmt.Sprintf(":%d", port),newconn)
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
			// TODO: need to use OwnerEncode when it's our cell.
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
	listenport := flag.Int("port", 1080, "Port to listen on")
	flag.Parse()

	readConfig()

	if *isrel {
		startRelay()
	} else if *iscli >= 0 {
		startClient(*iscli, *listenport)
	} else if *istru >= 0 {
		startTrustee(*istru)
	} else {
		panic("must specify -relay, -client=n, or -trustee=n")
	}
}

