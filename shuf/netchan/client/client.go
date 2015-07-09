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

	if len(os.Args) < 6 {
		fmt.Printf("Usage: client id [configFile] [nodeURIs] [clientURIs] [nodePubKeys]\n")
		os.Exit(1)
	}

	// Parse the args
	id, cerr := strconv.Atoi(os.Args[1])
	netchan.Check(cerr)
	configFile := os.Args[2]
	nodesFile := os.Args[3]
	clientsFile := os.Args[4]
	pubKeysDir := os.Args[5]

	// Read the config
	f, err := os.Open(configFile)
	netchan.Check(err)
	dec := json.NewDecoder(f)
	var c netchan.CFile
	err = dec.Decode(&c)
	f.Close()
	netchan.Check(err)

	// Read the public keys
	suite := ed25519.NewAES128SHA256Ed25519(true)
	pubKeys := make([]abstract.Point, c.NumNodes)
	for i := 0; i < c.NumNodes; i++ {
		f, err = os.Open(filepath.Join(pubKeysDir, strconv.Itoa(i)+".pub"))
		pubKeys[i] = suite.Point()
		pubKeys[i].UnmarshalFrom(f)
		f.Close()
	}
	privKeyFn := func(i int) abstract.Secret { panic("Cannot lookup key") }

	// Create the info
	inf := shuf.MakeInfo(shuf.UserInfo{
		Suite:        suite,
		PrivKey:      privKeyFn,
		PubKey:       pubKeys,
		NumNodes:     c.NumNodes,
		NumClients:   c.NumClients,
		MsgsPerGroup: c.MsgsPerGroup,
		NumRounds:    c.NumRounds,
		ResendTime:   time.Millisecond * time.Duration(c.ResendTime),
		Timeout:      time.Second * time.Duration(c.Timeout),
		MaxResends:   c.MaxResends,
	}, c.Seed)

	switch c.Shuffle {
	case "Biffle":
		inf.Shuffle = shuf.Biffle{inf}
	default:
		inf.Shuffle = shuf.Neff{inf}
	}

	switch c.Split {
	case "Conflict":
		inf.Split = shuf.Conflict{inf}
	default:
		inf.Split = shuf.Butterfly{inf}
	}

	// Read the clients file
	clients := make([]string, c.NumClients)
	f, err = os.Open(clientsFile)
	netchan.Check(err)
	r := bufio.NewScanner(f)
	for i := 0; r.Scan() && i < inf.NumClients; i++ {
		clients[i] = r.Text()
	}
	f.Close()

	// Read the nodes file
	nodes := make([]string, c.NumNodes)
	f, err = os.Open(nodesFile)
	netchan.Check(err)
	r = bufio.NewScanner(f)
	for i := 0; r.Scan() && i < inf.NumNodes; i++ {
		nodes[i] = r.Text()
	}
	f.Close()

	// Start the client
	n := netchan.Node{inf, id}
	var message abstract.Point
	if id < c.ActiveClients {
		r := suite.Cipher(abstract.RandomKey)
		message, _ = suite.Point().Pick([]byte("Message "+strconv.Itoa(id)), r)
	} else {
		message = suite.Point().Null()
	}
	n.StartClient(nodes, message, clients[id])
}
