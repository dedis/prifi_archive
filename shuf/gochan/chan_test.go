package main

import (
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/edwards/ed25519"
	"github.com/dedis/prifi/shuf"
	"strconv"
	"sync"
	"testing"
	"time"
)

func setup() (*shuf.Info, []abstract.Point) {
	suite := ed25519.NewAES128SHA256Ed25519(true)
	rand := suite.Cipher(abstract.RandomKey)
	pubKeys := make([]abstract.Point, 4)
	privKeys := make([]abstract.Secret, 4)
	for i := range pubKeys {
		privKeys[i] = suite.Secret().Pick(rand)
		pubKeys[i] = suite.Point().Mul(nil, privKeys[i])
	}
	privKeyFn := func(n int) abstract.Secret {
		return privKeys[n]
	}
	inf := shuf.MakeInfo(shuf.UserInfo{
		Suite:        suite,
		PrivKey:      privKeyFn,
		PubKey:       pubKeys,
		NumNodes:     4,
		NumClients:   8,
		NumRounds:    8,
		ResendTime:   time.Millisecond * time.Duration(333),
		MsgsPerGroup: 4,
		MaxResends:   3,
		Timeout:      time.Second * time.Duration(3),
	}, 2)
	messages := make([]abstract.Point, 8)
	for i := range messages {
		messages[i], _ = suite.Point().Pick([]byte("Message "+strconv.Itoa(i)), rand)
	}
	return inf, messages
}

func TestNeff(t *testing.T) {
	inf, messages := setup()
	inf.Shuffle = shuf.Neff{inf}
	inf.Split = shuf.Butterfly{inf}
	var wg sync.WaitGroup
	wg.Add(inf.NumClients)
	ChanShuffle(inf, messages, &wg)
	wg.Wait()
}

func TestBiffle(t *testing.T) {
	inf, messages := setup()
	inf.Shuffle = shuf.Biffle{inf}
	inf.Split = shuf.Butterfly{inf}
	var wg sync.WaitGroup
	wg.Add(inf.NumClients)
	ChanShuffle(inf, messages, &wg)
	wg.Wait()
}
