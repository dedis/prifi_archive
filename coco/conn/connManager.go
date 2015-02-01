package conn

import (
	"github.com/dedis/crypto/abstract"
)

/* This class serves as the connection manager for the GoConn connection
 * type. It functions as a wrapper around goConn keeping track of which public
 * keys map to which connections. It  also keeps track of the GoDirectory for
 * testing purposes.
 */

type GoConnManager struct {
	// Tracks the connections to various peers
	peerMap map[abstract.Point]*GoConn

	// This directory facilitates using go channels for testing purposes.
	dir *GoDirectory
	
	// The public key of the server that owns this manager.
	pubKey abstract.Point
}


/* Initializes a new GoConnManager
 *
 * Arguments:
 *	goDir = the GoDirectory to use for creating new connections. Enter nil
 *              to create a new one.
 *	key   = the public key of the owner of this manager
 * Returns:
 *   An initialized GoConnManager
 */
func (gcm *GoConnManager) Init(key abstract.Point, goDir *GoDirectory) *GoConnManager {
	gcm.pubKey = key
	gcm.peerMap = make(map[abstract.Point]*GoConn)
	if goDir == nil {
		gcm.dir = NewGoDirectory()
	} else {
		gcm.dir = goDir
	}
	return gcm
}

 /* Adds a new connection to the connection manager
 *
 * Arguments:
 *      theirkey = the key of the peer that this server wishes to connect to
 *
 * Returns:
 *   An error denoting whether creating the new connection was successful.
 */
func (gcm *GoConnManager) AddConn(theirKey abstract.Point) error {
	newConn, err := NewGoConn(gcm.dir, gcm.pubKey.String(), theirKey.String())
	if err != nil {
		return err
	}
	gcm.peerMap[theirKey] = newConn
	return nil
}

// Returns the GoDirectory of the manager.
func (gcm *GoConnManager) GetDir() *GoDirectory {
	return gcm.dir
}


/* Get a message from a given peer.
 *
 * Arguments:
 *	p    = the public key of the origin
 *      bum  = a buffer for receiving the message
 *
 * Returns:
 *   An error denoting whether the get to the buffer was successfull
 */
func (gcm *GoConnManager) Get(p abstract.Point, bum BinaryUnmarshaler) error {
	return gcm.peerMap[p].Get(bum)
}


/* Put a message to a given peer.
 *
 * Arguments:
 *     p    = the public key of the destination
 *     data = the message to send
 *
 * Returns:
 *   An error denoting whether the put was successfull
 */
func (gcm *GoConnManager) Put(p abstract.Point, data BinaryMarshaler) error {
	return gcm.peerMap[p].Put(data)
}

