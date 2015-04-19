package main

import (
	"encoding/json"
	"fmt"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/edwards/ed25519"
	"github.com/dedis/prifi/shuf"
	"os"
	"strconv"
	"sync"
	"time"
)

func check(e error) {
	if e != nil {
		fmt.Printf("Error!")
		panic(e.Error())
	}
}

type cFile struct {
	NumNodes     int
	NumClients   int
	NumRounds    int
	ResendTime   int
	MsgsPerGroup int
	Shuffle      string
	Seed         int64
}

func main() {

	// Read the config
	configFile := os.Args[1]
	f, err := os.Open(configFile)
	check(err)
	dec := json.NewDecoder(f)
	var c cFile
	err = dec.Decode(&c)
	f.Close()
	check(err)

	// Create  the key functions
	suite := ed25519.NewAES128SHA256Ed25519(true)
	rand := suite.Cipher(abstract.RandomKey)
	pubKeys := make([]abstract.Point, c.NumNodes)
	privKeys := make([]abstract.Secret, c.NumNodes)
	for i := range pubKeys {
		privKeys[i] = suite.Secret().Pick(rand)
		// privKeys[i] = suite.Secret().Zero()
		pubKeys[i] = suite.Point().Mul(nil, privKeys[i])
	}
	privKeyFn := func(n int) abstract.Secret {
		return privKeys[n]
	}

	// Create the messages
	messages := make([]abstract.Point, c.NumClients)
	for i := range messages {
		messages[i], _ = suite.Point().Pick([]byte("Message "+strconv.Itoa(i)), rand)
	}

	// Perform the shuffle
	inf := shuf.Info{
		Suite:        suite,
		PrivKey:      privKeyFn,
		PubKey:       pubKeys,
		NumNodes:     c.NumNodes,
		NumClients:   c.NumClients,
		NumRounds:    c.NumRounds,
		ResendTime:   time.Millisecond * time.Duration(c.ResendTime),
		MsgSize:      suite.Point().MarshalSize(),
		MsgsPerGroup: c.MsgsPerGroup}

	var s shuf.Shuffle
	switch c.Shuffle {
	case "id":
		s = shuf.IdShuffle{}
	case "dumb":
		s = shuf.DumbShuffle{c.Seed}
	case "neff":
		s = shuf.NeffShuffle{}
	case "subset":
		s = shuf.NewSubsetShuffle(c.Seed, c.NumRounds, c.NumNodes)
	case "butterfly":
		s = shuf.NewButterfly(&inf, c.Seed)
	}

	var wg sync.WaitGroup
	wg.Add(inf.NumClients)
	ChanShuffle(s, &inf, messages, &wg)
	wg.Wait()
}
