package connMan

import (
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/prifi/coconet"
)

/* This class serves as the connection manager for the GoConn connection
 * type. It functions as a wrapper around goConn keeping track of which public
 * keys map to which connections. It also keeps track of the GoDirectory for
 * testing purposes.
 */
type ChanConnManager struct {
	// Tracks the connections to various peers
	peerMap map[string]*coconet.GoConn
	// This directory facilitates using go channels for testing purposes.
	dir *coconet.GoDirectory
	// The public key of the server that owns this manager.
	pubKey abstract.Point
}

// TODO: Prototypes to consider for the future
//
//type ConnManager struct {
//	peerMap map[string]coconet.Conn
//}

//func (cm *ConnManager) AddConn(top abstract.Point, conn coconet.Conn) {
//	to := top.String()
//	peerMap[to] = conn
//}

/* Initializes a new ChanConnManager
 *
 * Arguments:
 * 	goDir = the GoDirectory to use for creating new connections. Enter nil
 * 		to create a new one.
 * 	key = the public key of the owner of this manager
 *
 * Returns:
 * 	An initialized ChanConnManager
 */
func (gcm *ChanConnManager) Init(key abstract.Point, goDir *coconet.GoDirectory) *ChanConnManager {
	gcm.pubKey = key
	gcm.peerMap = make(map[string]*coconet.GoConn)
	if goDir == nil {
		gcm.dir = coconet.NewGoDirectory()
	} else {
		gcm.dir = goDir
	}
	return gcm
}

/* Adds a new connection to the connection manager
 *
 * Arguments:
 * 	theirkey = the key of the peer that this server wishes to connect to
 *
 * Returns:
 * 	An error denoting whether creating the new connection was successful.
 */
func (gcm *ChanConnManager) AddConn(theirKey abstract.Point) error {
	newConn, err := coconet.NewGoConn(gcm.dir, gcm.pubKey.String(),
		theirKey.String())
	if err != nil {
		return err
	}
	gcm.peerMap[theirKey.String()] = newConn
	return nil
}

// Returns the GoDirectory of the manager.
func (gcm *ChanConnManager) GetDir() *coconet.GoDirectory {
	return gcm.dir
}

/* Put a message to a given peer.
 *
 * Arguments:
 * 	p = the public key of the destination
 * 	data = the message to send
 *
 * Returns:
 * 	An error denoting whether the put was successfull
 */
func (gcm *ChanConnManager) Put(p abstract.Point, data coconet.BinaryMarshaler) error {
	return gcm.peerMap[p.String()].Put(data)
}

/* Get a message from a given peer.
 *
 * Arguments:
 *	 p = the public key of the origin
 *	 bum = a buffer for receiving the message
 *
 * Returns:
 *	An error denoting whether the get to the buffer was successfull
 */
func (gcm ChanConnManager) Get(p abstract.Point, bum coconet.BinaryUnmarshaler) error {
	return gcm.peerMap[p.String()].Get(bum)
}
