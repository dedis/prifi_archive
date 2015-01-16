package coco

import (
	"strconv"
	"testing"
	// "fmt"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/openssl"
)

//       0
//      /
//     1
//    / \
//   2   3
func TestStatic(t *testing.T) {
	// Crypto setup
	suite := openssl.NewAES128SHA256P256()
	rand := suite.Cipher([]byte("example"))

	// number of nodes for the test
	nNodes := 4
	// create new directory for communication between peers
	directory := newDirectory()
	// Create Hosts and Peers
	h := make([]*HostNode, nNodes)
	for i := 0; i < nNodes; i++ {
		hostName := "host" + strconv.Itoa(i)
		h[i] = NewHostNode(hostName)
	}

	// Add edges to children
	var gc, gc2 *goConn
	gc, _ = NewGoConn(directory, h[0].name, h[1].name)
	h[0].AddChildren(gc)
	gc, _ = NewGoConn(directory, h[1].name, h[2].name)
	gc2, _ = NewGoConn(directory, h[1].name, h[3].name)
	h[1].AddChildren(gc, gc2)
	// Add edges to parents
	gc, _ = NewGoConn(directory, h[1].name, h[0].name)
	h[1].AddParent(gc)
	gc, _ = NewGoConn(directory, h[2].name, h[1].name)
	h[2].AddParent(gc)
	gc, _ = NewGoConn(directory, h[3].name, h[1].name)
	h[3].AddParent(gc)

	// Create Signing Nodes out of the hosts
	nodes := make([]SigningNode, nNodes)
	for i := 0; i < nNodes; i++ {
		nodes[i] = *NewSigningNode(h[i], suite, rand)
	}
	for i := 0; i < nNodes; i++ {
		nodes[i].Listen() // start listening for messages from within the tree
	}

	// initialize root node with knowledge of the
	// combined public keys of all its descendents
	var X_hat abstract.Point = nodes[1].pubKey
	for i := 2; i < nNodes; i++ {
		X_hat.Add(X_hat, nodes[i].pubKey)
	}
	nodes[0].X_hat = X_hat

	// Have root node initiate the signing protocol
	// via a simple annoucement
	nodes[0].logTest = []byte("Hello World")
	nodes[0].Announce(AnnouncementMessage{nodes[0].logTest})

}
