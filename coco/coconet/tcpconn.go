package coconet

import (
	"encoding/gob"
	"log"
	"net"
	"sync"
	"time"
)

// TcpConn is a prototype TCP connection with gob encoding.
type TCPConn struct {
	sync.RWMutex

	name string
	conn net.Conn
	enc  *gob.Encoder
	dec  *gob.Decoder
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

func (tc TCPConn) Connect() error {
	log.Println("tcpconn establishing new connection")
	// establish the connection
	conn, err := net.Dial("tcp", tc.name)
	if err != nil {
		log.Println("connection failed")
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

func (tc TCPConn) Name() string {
	return tc.name
}

// blocks until the put is availible
func (tc *TCPConn) Put(bm BinaryMarshaler) error {
	tc.RLock()
	for tc.enc == nil {
		tc.RUnlock()
		time.Sleep(time.Second)
		tc.RLock()
		//return errors.New(" connection not established")
	}
	tc.RUnlock()
	return tc.enc.Encode(bm)
}

// blocks until we get something
func (tc *TCPConn) Get(bum BinaryUnmarshaler) error {
	for tc.dec == nil {
		time.Sleep(time.Second)
		//return errors.New(" connection not established")
	}
	return tc.dec.Decode(bum)
}

func (tc *TCPConn) Close() {
	if tc.conn != nil {
		tc.conn.Close()
	}
}
