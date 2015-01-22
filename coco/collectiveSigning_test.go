package coco

import (
	"strconv"
	"testing"
	// "fmt"
	"github.com/dedis/crypto/nist"
)

//       0
//      /
//     1
//    / \
//   2   3
func TestStatic(t *testing.T) {
	// Crypto setup
	suite := nist.NewAES128SHA256P256()
	rand := suite.Cipher([]byte("example"))

	// number of nodes for the test
	nNodes := 4
	// create new directory for communication between peers
	dir := NewGoDirectory()
	// Create Hosts and Peers
	h := make([]*GoHost, nNodes)
	for i := 0; i < nNodes; i++ {
		hostName := "host" + strconv.Itoa(i)
		h[i] = NewGoHost(hostName, dir)
	}

	// Add edges to children
	//gc, _ = NewGoConn(directory, h[0].name, h[1].name)
	h[0].AddChildren(h[1].name)
	//gc, _ = NewGoConn(directory, h[1].name, h[2].name)
	//gc2, _ = NewGoConn(directory, h[1].name, h[3].name)
	h[1].AddChildren(h[2].name, h[3].name)
	// Add edges to parents
	//gc, _ = NewGoConn(directory, h[1].name, h[0].name)
	h[1].AddParent(h[0].name)
	//gc, _ = NewGoConn(directory, h[2].name, h[1].name)
	h[2].AddParent(h[1].name)
	//gc, _ = NewGoConn(directory, h[3].name, h[1].name)
	h[3].AddParent(h[1].name)

	// Create Signing Nodes out of the hosts
	nodes := make([]*SigningNode, nNodes)
	for i := 0; i < nNodes; i++ {
		nodes[i] = NewSigningNode(h[i], suite, rand)
	}
	for i := 0; i < nNodes; i++ {
		go func(i int) {
			// start listening for messages from within the tree
			nodes[i].Listen()
		}(i)
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
	nodes[0].Announce(&AnnouncementMessage{nodes[0].logTest})
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
	hostConfig.SNodes[0].Announce(&AnnouncementMessage{hostConfig.SNodes[0].logTest})
}

func TestTreeBigConfig(t *testing.T) {
	hc, err := LoadConfig("data/exwax.json")
	if err != nil {
		t.Error()
	}
	hc.SNodes[0].logTest = []byte("hello world")
	hc.SNodes[0].Announce(&AnnouncementMessage{hc.SNodes[0].logTest})
}

// tree from configuration file data/exconf.json
func TestMultipleRounds(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}
	hostConfig, _ := LoadConfig("data/exconf.json")
	N := 1000

	// Have root node initiate the signing protocol
	// via a simple annoucement
	for i := 0; i < N; i++ {
		hostConfig.SNodes[0].logTest = []byte("Hello World" + strconv.Itoa(i))
		hostConfig.SNodes[0].Announce(&AnnouncementMessage{hostConfig.SNodes[0].logTest})
	}
}

// func TestTCPStaticConfig(t *testing.T) {
// 	hc, err := LoadConfig("data/extcpconf.json")
// 	if err != nil {
// 		t.Error(err)
// 	}
// 	hc.SNodes[0].logTest = []byte("hello world")
// 	hc.SNodes[0].Announce(&AnnouncementMessage{hc.SNodes[0].logTest})
// }
