package tree

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"hash"

	"github.com/dedis/crypto/abstract"
)

// MerklePath represents a downward path from a (root) node in a Merkle tree
// to a given (interior or leaf) descendant node,
// including all the data necessary to validate and extract the descendant.
// It is assumed the caller has a valid hash-pointer to the root/starting node,
// and that all nodes in the path can be retrieved via self-certifying hash-ID.
type MerklePath struct {
	Ptr []int // Offsets of hash-pointers at each intermediate level
	Ofs int   // Offset of relevant object in last-level blob
	Len int   // Length of relevant object in last-level blob
}

// Retrieve an object in a Merkle tree,
// validating the entire path in the process.
// Returns a slice of a buffer obtained from HashGet.Get(),
// which might be shared and should be considered read-only.
func MerkleGet(suite abstract.Suite, root []byte, path MerklePath,
	ctx HashGet) ([]byte, error) {

	// Follow pointers through intermediate levels
	blob := root
	for i := range path.Ptr {
		beg := path.Ptr[i]
		end := beg + suite.HashLen()
		if end > len(blob) {
			return nil, errors.New("bad Merkle tree pointer offset")
		}
		id := HashId(blob[beg:end])
		b, e := ctx.Get(id) // Lookup the next-level blob
		if e != nil {
			return nil, e
		}
		blob = b
	}

	// Validate and extract the actual object
	beg := path.Ofs
	end := beg + path.Len
	if end > len(blob) {
		return nil, errors.New("bad Merkle tree object offset/length")
	}
	return blob[beg:end], nil
}

// Proof-of-beforeness:
// a list of offsets of peer-hash-pointers at each level below the root.
type MerkleProof []HashId

// Given a MerkleProof and the hash of the leaf, compute the hash of the root.
// If the MerkleProof is of length 0, simply returns leaf.
func (p MerkleProof) Calc(newHash func() hash.Hash, leaf []byte) []byte {
	var buf []byte
	var h hash.Hash
	for i := len(p) - 1; i >= 0; i-- {
		peer := p[i]
		if bytes.Compare(leaf, peer) > 0 { // sort so leaf < peer
			leaf, peer = peer, leaf
		}

		// Hash the sorted leaf/peer pair to yield the next-higher node
		if h == nil {
			h = newHash()
		} else {
			h.Reset()
		}
		h.Write(leaf)
		h.Write(peer)
		buf = h.Sum(buf[:0])
		leaf = buf
	}
	return leaf
}

// Check a purported MerkleProof against given root and leaf hashes.
func (p MerkleProof) Check(newHash func() hash.Hash, root, leaf []byte) bool {
	chk := p.Calc(newHash, leaf)
	return subtle.ConstantTimeCompare(chk, root) != 0
}

//type MerkleLog struct {
//}
