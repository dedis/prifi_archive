package coco

import (
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/openssl"
	"strconv"
)

//       0
//      /
//     1
//    / \
//   2   3
func Example_Static(){
	// Crypto setup
	suite := openssl.NewAES128SHA256P256()
	rand := abstract.HashStream(suite, []byte("example"), nil)

	// number of nodes for the test
	nNodes := 4
	// create new directory for communication between peers
	directory := newDirectory()
	// Create Hosts and Peers
	h := make([]HostNode, nNodes)
	p := make([]goPeer, nNodes)
	for i:=0; i<nNodes; i++ {
		hostName := "host" + strconv.Itoa(i)
		h[i] = *NewHostNode(hostName)
		auxp, _ := NewGoPeer(directory, hostName)
		p[i] = *auxp
	}

	// Add edges to children
	h[0].AddChildren(p[1])
	h[1].AddChildren(p[2], p[3])
	// Add edges to parents
	h[1].AddParent(p[0])
	h[2].AddParent(p[1])
	h[3].AddParent(p[1])

	// Create Signing Nodes out of the hosts
	nodes := make([]SigningNode, nNodes)
	for i:=0; i<nNodes; i++ {
		nodes[i] = *NewSigningNode(h[i], suite, rand)
		nodes[i].Listen() // start listening for messages from withing the tree
	}

	// initialize root node with knowledge of the 
	// combined public keys of all its descendents
	var X_hat abstract.Point = nodes[1].pubKey
	for i:=2; i<nNodes; i++ {
		X_hat.Add(X_hat, nodes[i].pubKey)
	}	
	nodes[0].X_hat = X_hat


	// Have root node initiate the signing protocol 
	// via a simple annoucement
	nodes[0].logTest = []byte("Hello World")
	nodes[0].Announce(AnnouncementMessage{nodes[0].logTest})

	// Output:
	// ElGamal Collective Signature succeeded
}