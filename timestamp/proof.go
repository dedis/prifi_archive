package time

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"hash"

	"github.com/dedis/crypto/abstract"
)

type hashContext struct {
	newHash func() hash.Hash
	hash    hash.Hash
}

func (c *hashContext) hashNode(buf []byte, left, right []byte) []byte {
	if bytes.Compare(left, right) > 0 { // sort so left < right
		left, right = right, left
	}
	if c.hash == nil {
		c.hash = c.newHash()
	} else {
		c.hash.Reset()
	}
	h := c.hash
	h.Write(left)
	h.Write(right)
	return h.Sum(buf)
}

// Proof-of-beforeness:
// a list of offsets of peer-hash-pointers at each level below the root.
type Proof []HashId

// Given a Proof and the hash of the leaf, compute the hash of the root.
// If the Proof is of length 0, simply returns leaf.
func (p Proof) Calc(newHash func() hash.Hash, leaf []byte) []byte {
	c := hashContext{newHash: newHash}
	var buf []byte
	for i := len(p) - 1; i >= 0; i-- {
		leaf = c.hashNode(buf[:0], leaf, p[i])
		buf = leaf
	}
	return leaf
}

// Check a purported Proof against given root and leaf hashes.
func (p Proof) Check(newHash func() hash.Hash, root, leaf []byte) bool {
	chk := p.Calc(newHash, leaf)
	// compare returns 1 if equal, so return is true when check is good
	return subtle.ConstantTimeCompare(chk, root) != 0
}

// Generate a Merkle proof tree for the given list of leaves,
// yielding one output proof per leaf.
func ProofTree(newHash func() hash.Hash, leaves []HashId) (HashId, []Proof) {

	// Determine the required tree depth
	nleaves := len(leaves)
	depth := 0
	for n := 1; n < nleaves; n <<= 1 {
		depth++
	}

	// Build the Merkle tree
	c := hashContext{newHash: newHash}
	tree := make([][]HashId, depth+1)
	tree[depth] = leaves
	nprev := nleaves
	tprev := tree[depth]
	for d := depth - 1; d >= 0; d-- {
		nnext := (nprev + 1) >> 1 // # hashes total at level i
		nnode := nprev >> 1       // # new nodes at level i
		println("nprev", nprev, "nnext", nnext, "nnode", nnode)
		tree[d] = make([]HashId, nnext)
		tnext := tree[d]
		for i := 0; i < nnode; i++ {
			tnext[i] = c.hashNode(nil, tprev[i*2], tprev[i*2+1])
		}
		// If nnode < nhash, just leave the odd one nil.
		nprev = nnext
		tprev = tnext
	}
	if nprev != 1 {
		panic("oops")
	}
	root := tprev[0]

	// Build all the individual proofs from the tree.
	// Some towards the end may end up being shorter than depth.
	proofs := make([]Proof, nleaves)
	for i := 0; i < nleaves; i++ {
		p := make([]HashId, depth)[:0]
		for d := 0; d < depth; d++ {
			h := tree[d][i>>uint(depth-d)]
			if h != nil {
				p = append(p, h)
			}
		}
		proofs[i] = Proof(p)
	}
	return root, proofs
}

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
		// end := beg + suite.HashLen()
		end := beg + 256 // change me: find hash len
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

//type MerkleLog struct {
//}
