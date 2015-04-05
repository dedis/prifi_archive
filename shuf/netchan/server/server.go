package main

import (
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/edwards/ed25519"
	"github.com/dedis/prifi/shuf"
	"github.com/dedis/prifi/shuf/netchan"
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

	inf := shuf.Info{
		Suite:      suite,
		PrivKey:    privKeyFn,
		PubKey:     []abstract.Point{H},
		NumNodes:   1,
		NumClients: 4,
		NumRounds:  2,
		ResendTime: time.Second / 3,
		MsgSize:    suite.Point().MarshalSize(),
	}
	netchan.StartServer(shuf.IdShuffle{}, 0, []string{"localhost:8080"}, &inf, ":9000")
}
