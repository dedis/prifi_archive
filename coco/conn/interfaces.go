package conn

import (
	"github.com/dedis/crypto/abstract"
)

/* This package defines several important interfaces for creating connections
 * for use with the coco protocol and the life insurance policy. There are two
 * main interfaces defined here: the Conn interface and the ConnManager. The
 * Conn interface abstracts away the low level networking details whereas the
 * ConnManager makes it easier to manage multiple connections.
 */
 
// Conn is an abstract bidirectonal connection. It abstracts away the network
// layer as well as the data-format for communication.
type Conn interface {
	Name() string
	Connect() error
	Put(BinaryMarshaler) error   // sends data through the connection
	Get(BinaryUnmarshaler) error // gets data from connection
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

/* The ConnManager is responsible for managing multiple connection. It allows
 * servers to send/receive messages to other servers by specifying the public
 * key of the desired server.
 */
type ConnManager interface {
	// Sends a message to a specific peer.
	Put(myKey, theirKey abstract.Point, bum BinaryMarshaler) error

	// Receive a message from the desired peer.
	Get(myKey, theirKey abstract.Point, bum BinaryMarshaler) error
}

