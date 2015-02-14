package sign_test

import (
	"strconv"
	"testing"

	"github.com/dedis/crypto/nist"
	_ "github.com/dedis/prifi/coco"
	"github.com/dedis/prifi/coco/coconet"
	"github.com/dedis/prifi/coco/sign"
	"github.com/dedis/prifi/coco/test/oldconfig"
)

//       0
//      /
//     1
//    / \
//   2   3
func TestStaticMerkle(t *testing.T) {
	if err := runStaticTest(sign.MerkleTree); err != nil {
		t.Fatal(err)
	}
}

func TestStaticPubKey(t *testing.T) {
	if err := runStaticTest(sign.PubKey); err != nil {
		t.Fatal(err)
	}
}

// func TestStaticFaulty(t *testing.T) {
// 	faultyNodes := make([]int, 0)
// 	faultyNodes = append(faultyNodes, 1)

// 	if err := runStaticTest(sign.PubKey, faultyNodes...); err != nil {
// 		t.Fatal(err)
// 	}
// }

func runStaticTest(signType sign.Type, faultyNodes ...int) error {
	// Crypto setup
	suite := nist.NewAES128SHA256P256()
	rand := suite.Cipher([]byte("example"))

	// number of nodes for the test
	nNodes := 4
	// create new directory for communication between peers
	dir := coconet.NewGoDirectory()
	// Create Hosts and Peers
	h := make([]coconet.Host, nNodes)

	for i := 0; i < nNodes; i++ {
		hostName := "host" + strconv.Itoa(i)

		if len(faultyNodes) > 0 {
			h[i] = &coconet.FaultyHost{}
			gohost := coconet.NewGoHost(hostName, dir)
			h[i] = coconet.NewFaultyHost(gohost)
		} else {
			h[i] = coconet.NewGoHost(hostName, dir)
		}

	}

	for _, fh := range faultyNodes {
		h[fh].(*coconet.FaultyHost).SetDeadFor("commit", true)
	}

	// Create Signing Nodes out of the hosts
	nodes := make([]*sign.SigningNode, nNodes)
	for i := 0; i < nNodes; i++ {
		nodes[i] = sign.NewSigningNode(h[i], suite, rand)
		nodes[i].Type = signType

		h[i].SetPubKey(nodes[i].PubKey)
		// To test the already keyed signing node, uncomment
		// PrivKey := suite.Secret().Pick(rand)
		// nodes[i] = NewKeyedSigningNode(h[i], suite, PrivKey)
	}

	// Add edges to children, listen to children
	h[0].AddChildren(h[1].Name())
	h[0].Listen()
	h[1].AddChildren(h[2].Name(), h[3].Name())
	h[1].Listen()

	// Add edges to parents
	h[1].AddParent(h[0].Name())
	h[2].AddParent(h[1].Name())
	h[3].AddParent(h[1].Name())
	// h[2].Listen()
	// h[3].Listen()

	for i := 0; i < nNodes; i++ {
		if len(faultyNodes) > 0 {
			nodes[i].TestingFailures = true
		}

		go func(i int) {
			// start listening for messages from within the tree
			nodes[i].Listen()
		}(i)
	}

	nodes[0].Height = 2
	nodes[1].Height = 1
	nodes[2].Height = 0
	nodes[3].Height = 0

	// initialize all nodes with knowledge of
	// combined public keys of all its descendents
	nodes[2].X_hat = nodes[2].PubKey
	nodes[3].X_hat = nodes[3].PubKey
	nodes[1].X_hat.Add(nodes[1].PubKey, nodes[2].X_hat)
	nodes[1].X_hat.Add(nodes[1].X_hat, nodes[3].X_hat)
	nodes[0].X_hat.Add(nodes[0].PubKey, nodes[1].X_hat)

	// test that X_Hats of non-leaves are != their pub keys
	firstLeaf := 2
	for i := 0; i < firstLeaf; i++ {
		if nodes[i].X_hat.Equal(nodes[i].PubKey) {
			panic("pub key equal x hat")
		}

	}

	// Have root node initiate the signing protocol
	// via a simple annoucement
	nodes[0].LogTest = []byte("Hello World")
	return nodes[0].Announce(&sign.AnnouncementMessage{nodes[0].LogTest})
}

// Configuration file data/exconf.json
//       0
//      / \
//     1   4
//    / \   \
//   2   3   5
func TestTreeFromStaticConfig(t *testing.T) {
	hostConfig, err := oldconfig.LoadConfig("../test/data/exconf.json")
	if err != nil {
		t.Fatal(err)
	}
	err = hostConfig.Run(sign.MerkleTree)
	if err != nil {
		t.Fatal(err)
	}
	// Have root node initiate the signing protocol
	// via a simple annoucement
	hostConfig.SNodes[0].LogTest = []byte("Hello World")
	hostConfig.SNodes[0].Announce(&sign.AnnouncementMessage{hostConfig.SNodes[0].LogTest})
}

func TestTreeBigConfig(t *testing.T) {
	hc, err := oldconfig.LoadConfig("../test/data/exwax.json")
	if err != nil {
		t.Fatal()
	}
	err = hc.Run(sign.MerkleTree)
	if err != nil {
		t.Fatal(err)
	}
	hc.SNodes[0].LogTest = []byte("hello world")
	err = hc.SNodes[0].Announce(&sign.AnnouncementMessage{hc.SNodes[0].LogTest})
	if err != nil {
		t.Error(err)
	}
}

// tree from configuration file data/exconf.json
func TestMultipleRounds(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}
	hostConfig, err := oldconfig.LoadConfig("../test/data/exconf.json")
	if err != nil {
		t.Fatal(err)
	}
	N := 5
	err = hostConfig.Run(sign.MerkleTree)
	if err != nil {
		t.Fatal(err)
	}
	// Have root node initiate the signing protocol
	// via a simple annoucement
	for i := 0; i < N; i++ {
		hostConfig.SNodes[0].LogTest = []byte("Hello World" + strconv.Itoa(i))
		err = hostConfig.SNodes[0].Announce(&sign.AnnouncementMessage{hostConfig.SNodes[0].LogTest})
		if err != nil {
			t.Error(err)
		}
	}
}

func TestTCPStaticConfig(t *testing.T) {
	hc, err := oldconfig.LoadConfig("../test/data/extcpconf.json", oldconfig.ConfigOptions{ConnType: "tcp", GenHosts: true})
	if err != nil {
		t.Error(err)
	}
	err = hc.Run(sign.MerkleTree)
	if err != nil {
		t.Fatal(err)
	}
	hc.SNodes[0].LogTest = []byte("hello world")
	err = hc.SNodes[0].Announce(&sign.AnnouncementMessage{hc.SNodes[0].LogTest})
	if err != nil {
		t.Error(err)
	}
	for _, n := range hc.SNodes {
		n.Close()
	}
}

func TestTCPStaticConfigRounds(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}
	hc, err := oldconfig.LoadConfig("../test/data/extcpconf.json", oldconfig.ConfigOptions{ConnType: "tcp", GenHosts: true})
	if err != nil {
		t.Error(err)
	}
	err = hc.Run(sign.MerkleTree)
	if err != nil {
		t.Fatal(err)
	}
	N := 5
	for i := 0; i < N; i++ {
		hc.SNodes[0].LogTest = []byte("hello world")
		err = hc.SNodes[0].Announce(&sign.AnnouncementMessage{hc.SNodes[0].LogTest})
		if err != nil {
			t.Error(err)
		}
	}
	for _, n := range hc.SNodes {
		n.Close()
	}
}

// func TestTreeBigConfigTCP(t *testing.T) {
// 	if testing.Short() {
// 		t.Skip("skipping test in short mode.")
// 	}
// 	hc, err := LoadConfig("data/wax.json", ConfigOptions{ConnType: "tcp", GenHosts: true})
// 	if err != nil {
// 		t.Error()
// 	}
// 	err = hc.Run(sign.MerkleTree)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	hc.SNodes[0].LogTest = []byte("hello world")
// 	err = hc.SNodes[0].Announce(&AnnouncementMessage{hc.SNodes[0].LogTest})
// 	if err != nil {
// 		t.Error(err)
// 	}
// 	for _, n := range hc.SNodes {
// 		n.Close()
// 	}
// }

/*func BenchmarkTreeBigConfigTCP(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping test in short mode.")
	}
	hc, err := LoadConfig("data/wax.json", "tcp")
	if err != nil {
		b.Error()
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hc.SNodes[0].LogTest = []byte("hello world")
		hc.SNodes[0].Announce(&AnnouncementMessage{hc.SNodes[0].LogTest})
	}
}*/
