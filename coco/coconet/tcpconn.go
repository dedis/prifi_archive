package coconet

import (
	"encoding/gob"
	"errors"
	"io"
	"net"
	"sync"

	log "github.com/Sirupsen/logrus"

	"github.com/dedis/crypto/abstract"
)

// TCPConn is an implementation of the Conn interface for TCP network connections.
type TCPConn struct {
	// encLock guards the encoder and decoder and underlying conn.
	encLock sync.Mutex
	name    string
	conn    net.Conn
	enc     *gob.Encoder
	dec     *gob.Decoder

	// pkLock guards the public key
	pkLock sync.Mutex
	pubkey abstract.Point
}

// NewTCPConnFromNet wraps a net.Conn creating a new TCPConn using conn as the
// underlying connection.
// After creating a TCPConn in this fashion, it might be necessary to call SetName,
// in order to give it an understandable name.
func NewTCPConnFromNet(conn net.Conn) *TCPConn {
	return &TCPConn{
		name: conn.RemoteAddr().String(),
		conn: conn,
		enc:  gob.NewEncoder(conn),
		dec:  gob.NewDecoder(conn)}

}

// NewTCPConn takes a hostname and creates TCPConn.
// Before calling Get or Put Connect must first be called to establish the connection.
func NewTCPConn(hostname string) *TCPConn {
	tp := &TCPConn{}
	tp.name = hostname
	return tp
}

// Connect connects to the endpoint specified.
func (tc *TCPConn) Connect() error {
	conn, err := net.Dial("tcp", tc.name)
	if err != nil {
		return err
	}
	tc.encLock.Lock()
	tc.conn = conn
	tc.enc = gob.NewEncoder(conn)
	tc.dec = gob.NewDecoder(conn)
	tc.encLock.Unlock()
	return nil
}

// SetName sets the name of the connection.
func (tc *TCPConn) SetName(name string) {
	tc.name = name
}

// Name returns the name of the connection.
func (tc *TCPConn) Name() string {
	return tc.name
}

// SetPubKey sets the public key.
func (tc *TCPConn) SetPubKey(pk abstract.Point) {
	tc.pkLock.Lock()
	tc.pubkey = pk
	tc.pkLock.Unlock()
}

// PubKey returns the public key of this peer.
func (tc *TCPConn) PubKey() abstract.Point {
	tc.pkLock.Lock()
	pl := tc.pubkey
	tc.pkLock.Unlock()
	return pl
}

// ErrNotEstablished indicates that the connection has not been successfully established
// through a call to Connect yet. It does not indicate whether the failure was permanent or
// temporary.
var ErrNotEstablished = errors.New("connection not established")

type temporary interface {
	Temporary() bool
}

// IsTemporary returns true if it is a temporary error.
func IsTemporary(err error) bool {
	t, ok := err.(temporary)
	return ok && t.Temporary()
}

// Put puts data to the connection.
// Returns io.EOF on an irrecoverable error.
// Returns actual error if it is Temporary.
func (tc *TCPConn) Put(bm BinaryMarshaler) error {
	tc.encLock.Lock()
	if tc.enc == nil {
		tc.encLock.Unlock()
		log.Println("Conn not established")
		return ErrNotEstablished
	}
	enc := tc.enc
	tc.encLock.Unlock()

	err := enc.Encode(bm)
	if err != nil {
		if IsTemporary(err) {
			log.Errorln("TEMPORARY ERROR")
			return err
		}
		return io.EOF
	}
	return err
}

// Get gets data from the connection.
// Returns io.EOF on an irrecoveralbe error.
// Returns given error if it is Temporary.
func (tc *TCPConn) Get(bum BinaryUnmarshaler) error {
	tc.encLock.Lock()

	for tc.dec == nil {
		tc.encLock.Unlock()
		return ErrNotEstablished
	}
	dec := tc.dec
	tc.encLock.Unlock()
	err := dec.Decode(bum)
	if err != nil {
		if IsTemporary(err) {
			log.Errorln("TEMPORARY ERROR")
			return err
		}
		return io.EOF
	}
	return err
}

// Close closes the connection.
func (tc *TCPConn) Close() {
	tc.encLock.Lock()
	defer tc.encLock.Unlock()
	if tc.conn != nil {
		// ignore error becuase only other possibility was an invalid
		// connection. but we don't care if we close a connection twice.
		tc.conn.Close()
	}
	tc.conn = nil
	tc.enc = nil
	tc.dec = nil
}
