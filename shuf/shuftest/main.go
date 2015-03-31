package main

import (
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/edwards/ed25519"
	"github.com/dedis/prifi/shuf"
	"github.com/dedis/prifi/shuf/gochan"
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
	// fmt.Printf("Starting with %v\n", messages)

	// ElGamal-encrypt all these messages with the server key
	var X, Y [4]abstract.Point
	r := suite.Secret() // temporary
	for i := 0; i < 4; i++ {
		r.Pick(rand)
		X[i] = suite.Point().Mul(nil, r)
		Y[i] = suite.Point().Mul(H, r) // ElGamal blinding factor
		Y[i].Add(Y[i], messages[i])    // Encrypted client public key
	}

	// For butterfly and conflict (so far)
	// var X, Y [4]abstract.Point
	// for i := 0; i < 4; i++ {
	// 	X[i] = suite.Point().Base()
	// 	Y[i] = messages[i]
	// }

	// Package these up into separate Elgamal boxes
	pairs := make([]shuf.Elgamal, 4)
	for i := range pairs {
		pairs[i] = shuf.Elgamal{
			X:      []abstract.Point{X[i]},
			Y:      []abstract.Point{Y[i]},
			Shared: H,
		}
	}

	// Perform the shuffle
	defaultOpts := shuf.Info{
		Suite:       suite,
		PrivKey:     privKeyFn,
		NumNodes:    1,
		NumClients:  4,
		NumRounds:   1,
		TotalTime:   time.Second * 5,
		ResendTime:  time.Second / 3,
		CollectTime: time.Second}

	// s := shuf.IdShuffle{}
	// s := shuf.DumbShuffle{2}
	s := shuf.NewSubsetShuffle(2, 1)
	// s := shuf.NewButterfly(&defaultOpts, 2)
	// s := (*shuf.ConflictSwap)(shuf.NewButterfly(&defaultOpts, 23457))
	// s := shuf.NeffShuffle{}

	gochan.ChanShuffle(s, &defaultOpts, pairs)
	time.Sleep(defaultOpts.TotalTime)
}
