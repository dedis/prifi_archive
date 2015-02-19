package coconet

import (
	"encoding/gob"
	"errors"
	"net"
	"sync"

	log "github.com/Sirupsen/logrus"

	"github.com/dedis/crypto/abstract"
)

// TcpConn is a prototype TCP connection with gob encoding.
type TCPConn struct {
	sync.RWMutex

	name string
	conn net.Conn
	enc  *gob.Encoder
	dec  *gob.Decoder

	mupk   sync.Mutex
	pubkey abstract.Point
}

func NewTCPConnFromNet(conn net.Conn) *TCPConn {
	return &TCPConn{
		name: conn.RemoteAddr().String(),
		conn: conn,
		enc:  gob.NewEncoder(conn),
		dec:  gob.NewDecoder(conn)}

}

func NewTCPConn(hostname string) *TCPConn {
	tp := &TCPConn{}
	tp.name = hostname
	return tp
}

func (tc *TCPConn) Connect() error {
	// log.Println("tcpconn establishing new connection:", tc.name)
	// establish the connection
	conn, err := net.Dial("tcp", tc.name)
	if err != nil {
		return err
	}
	tc.conn = conn
	// gob encoders call MarshalBinary and UnmarshalBinary
	// TODO replace gob with minimal Put, Get interface
	// gob nicely handles reading from the connection
	// otherwise we would have to deal with making the tcp
	// read and write blocking rather than non-blocking.
	tc.enc = gob.NewEncoder(conn)
	tc.dec = gob.NewDecoder(conn)
	return nil
}

func (tc *TCPConn) SetName(n string) {
	tc.name = n
}

func (tc *TCPConn) Name() string {
	return tc.name
}

func (c *TCPConn) SetPubKey(pk abstract.Point) {
	c.mupk.Lock()
	c.pubkey = pk
	c.mupk.Unlock()
}

func (c *TCPConn) PubKey() abstract.Point {
	c.mupk.Lock()
	pl := c.pubkey
	c.mupk.Unlock()
	return pl
}

var ConnectionNotEstablished error = errors.New("connection not established")

// blocks until the put is availible
func (tc *TCPConn) Put(bm BinaryMarshaler) chan error {
	errchan := make(chan error, 1)
	// tc.RLock()
	for tc.enc == nil {
		// tc.RUnlock()
		// time.Sleep(time.Second)
		// tc.RLock()
		log.Println("Conn not established")
		errchan <- ConnectionNotEstablished
		return errchan
	}
	// tc.RUnlock()
	err := tc.enc.Encode(bm)
	if err != nil {
		log.Errorln("failed to put/encode:", err)
	}
	errchan <- err
	return errchan
}

// blocks until we get something
func (tc *TCPConn) Get(bum BinaryUnmarshaler) chan error {
	errchan := make(chan error, 1)
	for tc.dec == nil {
		// panic("no decoder yet")
		errchan <- ConnectionNotEstablished
		return errchan
	}

	go func(bum BinaryUnmarshaler) {
		err := tc.dec.Decode(bum)
		if err != nil {
			log.Errorln("failed to decode:", err)
		}
		errchan <- err
	}(bum)

	return errchan
}

func (tc *TCPConn) Close() {
	log.Errorln("Closing Connection")
	if tc.conn != nil {
		tc.conn.Close()
	}
	tc.conn = nil
	tc.enc = nil
	tc.dec = nil
}
