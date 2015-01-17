package coco

import (
	"fmt"
	"strconv"
	"testing"
	// "fmt"
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

	// initialize all nodes with knowledge of
	// combined public keys of all its descendents
	nodes[2].X_hat = nodes[2].pubKey
	nodes[3].X_hat = nodes[3].pubKey
	nodes[1].X_hat.Add(nodes[1].pubKey, nodes[2].X_hat)
	nodes[1].X_hat.Add(nodes[1].X_hat, nodes[3].X_hat)
	nodes[0].X_hat.Add(nodes[0].pubKey, nodes[1].X_hat)

	// Have root node initiate the signing protocol
	// via a simple annoucement
	nodes[0].logTest = []byte("Hello World")
	nodes[0].Announce(AnnouncementMessage{nodes[0].logTest})
}

// Configuration file data/exconf.json
//       0
//      / \
//     1   4
//    / \   \
//   2   3   5
func TestTreeFromStaticConfig(t *testing.T) {
	hostConfig, _ := LoadConfig("data/exconf.json")

	// Have root node initiate the signing protocol
	// via a simple annoucement
	hostConfig.SNodes[0].logTest = []byte("Hello World")
	hostConfig.SNodes[0].Announce(AnnouncementMessage{hostConfig.SNodes[0].logTest})
}

func TestReadWrite(t *testing.T) {
	return
	// Crypto setup
	suite := openssl.NewAES128SHA256P256()
	rand := suite.Cipher([]byte("example"))
	// intialize example to be read/ wrote, and a signing node
	// testBytes := []byte("Hello World")
	s := suite.Secret().Pick(rand)
	m := TestMessage{S: s}
	h := NewHostNode("exampleHost")
	sn := NewSigningNode(h, suite, rand)

	// test write
	dataBytes := sn.Write(m)
	dataInterface, err := sn.Read(dataBytes)
	if err != nil {
		t.Error("Decoding didn't work")
	}
	fmt.Println(dataInterface)

	switch mDecoded := dataInterface.(type) {
	case TestMessage:
		fmt.Println("Decoded annoucement message")
		fmt.Println(mDecoded)
	default:
		t.Error("Decoding didn't work")
	}

}
