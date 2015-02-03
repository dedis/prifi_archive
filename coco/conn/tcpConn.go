package conn

import (
	"encoding/gob"
	"errors"
	"log"
	"net"
)

// TcpConn is a prototype TCP connection with gob encoding.
type TCPConn struct {
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
	tc.enc = gob.NewEncoder(conn)
	tc.dec = gob.NewDecoder(conn)
	return nil
}

func (tc TCPConn) Name() string {
	return tc.name
}

func (tc *TCPConn) Put(bm BinaryMarshaler) error {
	if tc.enc == nil {
		return errors.New(" connection not established")
	}
	return tc.enc.Encode(bm)
}

func (tc *TCPConn) Get(bum BinaryUnmarshaler) error {
	if tc.dec == nil {
		return errors.New(" connection not established")
	}
	return tc.dec.Decode(bum)
}
