package main

import (
// "fmt"
// "github.com/dedis/crypto/abstract"
// "github.com/dedis/crypto/edwards/ed25519"
// "github.com/dedis/prifi/shuf"
// "github.com/dedis/prifi/shuf/gochan"
// "time"
)

// Obviously this code is under development
// Look away for now

func main() {

	// defaultOpts := shuf.Info{
	// 	NumNodes:    1,
	// 	NumClients:  4,
	// 	MsgSize:     5,
	// 	NumRounds:   1,
	// 	TotalTime:   time.Second * 5,
	// 	ResendTime:  time.Second / 3,
	// 	CollectTime: time.Second}
	//
	// suite := ed25519.NewAES128SHA256Ed25519(true)
	// rand := suite.Cipher(abstract.RandomKey)

	// Create a server private/public keypair
	// h := suite.Secret().Pick(rand)
	// H := suite.Point().Mul(nil, h)
	// pubKeyFn := func(n int) abstract.Point {
	// 	return H
	// }
	// privKeyFn := func(n int) abstract.Secret {
	// 	return h
	// }

	// Create the client messages
	// var messages [2]abstract.Point
	// messages[0], _ = suite.Point().Pick([]byte("hello"), rand)
	// messages[1], _ = suite.Point().Pick([]byte("world"), rand)

	// ElGamal-encrypt all these messages with the "server" key
	// var X, Y [2]abstract.Point
	// r := suite.Secret() // temporary
	// for i := 0; i < 2; i++ {
	// 	r.Pick(rand)
	// 	X[i] = suite.Point().Mul(nil, r)
	// 	Y[i] = suite.Point().Mul(H, r) // ElGamal blinding factor
	// 	Y[i].Add(Y[i], messages[i])           // Encrypted client public key
	// }

	// Encode the client messages

	// s := shuf.NeffShuffle{
	// 	Suite:   suite,
	// 	PubKey:  pubKeyFn,
	// 	PrivKey: privKeyFn,
	// }
	//
	// gochan.ChanShuffle(s, &defaultOpts, messages)
	// time.Sleep(defaultOpts.TotalTime)
}
