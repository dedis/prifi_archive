package graphs

import (
	"encoding/hex"

	"github.com/dedis/crypto/abstract"
)

// tree easy to deal with
// default json encoding can be read as the
// Tree section of a config file
type Tree struct {
	Name string `json:"name"`
	// hex encoded public and private keys
	PriKey   string  `json:"prikey,omitempty"`
	PubKey   string  `json:"pubkey,omitempty"`
	Children []*Tree `json:"children,omitempty"`
}

func (t *Tree) TraverseTree(f func(*Tree)) {
	f(t)
	for _, c := range t.Children {
		c.TraverseTree(f)
	}
}

// generate keys for the tree
func (t *Tree) GenKeys(suite abstract.Suite, rand abstract.Cipher) {
	t.TraverseTree(func(t *Tree) {
		privKey := suite.Secret().Pick(rand)
		pubKey := suite.Point().Mul(nil, privKey)

		t.PriKey = string(hex.EncodeToString(privKey.Encode()))
		t.PubKey = string(hex.EncodeToString(pubKey.Encode()))
	})
}
