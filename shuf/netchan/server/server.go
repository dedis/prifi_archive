package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/edwards/ed25519"
	"github.com/dedis/prifi/shuf"
	"github.com/dedis/prifi/shuf/netchan"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

func main() {

	if len(os.Args) < 7 {
		fmt.Printf("Usage: server id [configFile] [nodeURIs] [clientURIs] [nodePubKeys] [privKey]\n")
		os.Exit(1)
	}

	// Parse the args
	id, cerr := strconv.Atoi(os.Args[1])
	netchan.Check(cerr)
	configFile := os.Args[2]
	nodesFile := os.Args[3]
	clientsFile := os.Args[4]
	pubKeysDir := os.Args[5]
	privKeyFile := os.Args[6]

	// Read the config
	f, err := os.Open(configFile)
	netchan.Check(err)
	dec := json.NewDecoder(f)
	var c netchan.CFile
	err = dec.Decode(&c)
	f.Close()
	netchan.Check(err)

	// Create the key functions
	suite := ed25519.NewAES128SHA256Ed25519(true)
	f, err = os.Open(privKeyFile)
	netchan.Check(err)
	h := suite.Secret()
	h.UnmarshalFrom(f)
	f.Close()
	privKeyFn := func(n int) abstract.Secret {
		return h
	}

	// Read the public keys
	pubKeys := make([]abstract.Point, c.NumNodes)
	for i := 0; i < c.NumNodes; i++ {
		f, err = os.Open(filepath.Join(pubKeysDir, strconv.Itoa(i)+".pub"))
		pubKeys[i] = suite.Point()
		pubKeys[i].UnmarshalFrom(f)
		f.Close()
	}

	// Create the info
	inf := shuf.Info{
		Suite:        suite,
		PrivKey:      privKeyFn,
		PubKey:       pubKeys,
		NumNodes:     c.NumNodes,
		NumClients:   c.NumClients,
		NumRounds:    c.NumRounds,
		ResendTime:   time.Millisecond * time.Duration(c.ResendTime),
		MsgSize:      suite.Point().MarshalSize(),
		MsgsPerGroup: c.MsgsPerGroup,
	}

	// Read the clients file
	clients := make([]string, c.NumClients)
	f, err = os.Open(clientsFile)
	netchan.Check(err)
	r := bufio.NewReader(f)
	for i := range clients {
		l, _ := r.ReadString('\n')
		clients[i] = l
	}

	// Read the nodes file
	nodes := make([]string, c.NumNodes)
	f, err = os.Open(nodesFile)
	netchan.Check(err)
	r = bufio.NewReader(f)
	for i := range nodes {
		l, _ := r.ReadString('\n')
		nodes[i] = l
	}

	// Start the server
	var s shuf.Shuffle
	switch c.Shuffle {
	case "id":
		s = shuf.IdShuffle{}
	}
	n := netchan.Node{&inf, s, id}
	n.StartServer(clients, nodes, c.Port)
}
