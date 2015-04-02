package main

import (
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/edwards/ed25519"
	"github.com/dedis/prifi/shuf"
	"github.com/dedis/prifi/shuf/gochan"
	"sync"
	"time"
)

func main() {

	suite := ed25519.NewAES128SHA256Ed25519(true)
	rand := suite.Cipher(abstract.RandomKey)

	// Create a server private/public keypair
	h := suite.Secret().Pick(rand)
	H := suite.Point().Mul(nil, h)
	privKeyFn := func(n int) abstract.Secret {
		return h
	}

	// Create the client messages
	var messages [4]abstract.Point
	messages[0], _ = suite.Point().Pick([]byte("hello"), rand)
	messages[1], _ = suite.Point().Pick([]byte("world"), rand)
	messages[2], _ = suite.Point().Pick([]byte("11111"), rand)
	messages[3], _ = suite.Point().Pick([]byte("22222"), rand)

	// Perform the shuffle
	defaultOpts := shuf.Info{
		Suite:        suite,
		PrivKey:      privKeyFn,
		PubKey:       []abstract.Point{H},
		NumNodes:     1,
		NumClients:   4,
		NumRounds:    1,
		ResendTime:   time.Second / 3,
		MsgSize:      suite.Point().MarshalSize(),
		MsgsPerGroup: 4}

	// s := shuf.IdShuffle{}
	// s := shuf.DumbShuffle{2}
	// s := shuf.NewSubsetShuffle(2, 1, 1)
	s := shuf.NewButterfly(&defaultOpts, 2)
	// s := (*shuf.ConflictSwap)(shuf.NewButterfly(&defaultOpts, 23457))
	// s := shuf.NeffShuffle{}

	var wg sync.WaitGroup
	wg.Add(defaultOpts.NumClients)
	gochan.ChanShuffle(s, &defaultOpts, messages[:4], &wg)
	wg.Wait()
}
