package coconet

import (
	"encoding/gob"
	"errors"
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

func (tc TCPConn) Name() string {
	return tc.name
}

// blocks until the put is availible
func (tc *TCPConn) Put(bm BinaryMarshaler) chan error {
	errchan := make(chan error, 2)
	tc.RLock()
	for tc.enc == nil {
		tc.RUnlock()
		time.Sleep(time.Second)
		tc.RLock()
		errchan <- errors.New(" connection not established")
		return errchan
	}
	tc.RUnlock()
	err := tc.enc.Encode(bm)
	errchan <- err
	return errchan
}

// blocks until we get something
func (tc *TCPConn) Get(bum BinaryUnmarshaler) chan error {
	errchan := make(chan error, 2)
	for tc.dec == nil {
		time.Sleep(time.Second)
		// panic("no decoder yet")
		// log.Fatal("no decoder yet")
		errchan <- errors.New("connection not established")
		return errchan
	}

	// errchan := make(chan string, 1)
	go func(bum BinaryUnmarshaler) {
		err := tc.dec.Decode(bum)
		errchan <- err
	}(bum)
	return errchan
}

func (tc *TCPConn) Close() {
	if tc.conn != nil {
		tc.conn.Close()
	}
}
