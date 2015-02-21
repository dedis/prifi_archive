package coconet

import (
	"github.com/dedis/crypto/abstract"
)

// Conn is an abstract bidirectonal connection. It abstracts away the network
// layer as well as the data-format for communication.
type Conn interface {
	Name() string // the "to" of the connection
	PubKey() abstract.Point
	SetPubKey(abstract.Point)

	Connect() error // connect with the "to"
	Close()         // clean up the connection

	Put(BinaryMarshaler) error   // sends data through the connection
	Get(BinaryUnmarshaler) error // gets data from connection (blocking)
}

/* Alternative Bytes Based Conn
type Conn interface {
	Name() string
	Put([]data) error     // sends data through the connection
	Get([]data) error     // gets data from connection
	Get() ([]data, error) // -> extra allocation for every recieve
}*/

// Taken from: http://golang.org/pkg/encoding/#BinaryMarshaler
// All messages passing through our conn must implement their own  BinaryMarshaler
type BinaryMarshaler interface {
	MarshalBinary() (data []byte, err error)
}

// Taken from: http://golang.org/pkg/encoding/#BinaryMarshaler
// All messages passing through our conn must implement their own BinaryUnmarshaler
type BinaryUnmarshaler interface {
	UnmarshalBinary(data []byte) error
}
