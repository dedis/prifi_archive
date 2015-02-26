package connMan

import (
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/prifi/coconet"
)

/* The ConnManager is responsible for managing multiple connections. It allows
 * servers to send/receive messages to other servers by specifying the public
 * key of the desired server.
 */
type ConnManager interface {
	// Sends a message to a specific peer.
	Put(abstract.Point, coconet.BinaryMarshaler) error

	// Receive a message from the desired peer.
	Get(abstract.Point, coconet.BinaryUnmarshaler) error
}
