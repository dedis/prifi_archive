package time

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestPath(t *testing.T) {

	newHash := sha256.New
	hash := newHash()
	n := 100

	leaves := make([]HashId, n)
	for i := range leaves {
		leaves[i] = make([]byte, hash.Size())
		for j := range leaves[i] {
			leaves[i][j] = byte(i)
		}
		//println("leaf",i,":",hex.EncodeToString(leaves[i]))
	}

	root, proofs := ProofTree(newHash, leaves)
	println("root:", hex.EncodeToString(root))
	for i := range proofs {
		println("leaf", i, hex.EncodeToString(leaves[i]))
		proofs[i].Check(newHash, root, leaves[i])
		for j := range proofs[i] {
			println("  ", j, hex.EncodeToString(proofs[i][j]))
		}
	}
}
