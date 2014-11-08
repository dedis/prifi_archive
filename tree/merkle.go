package tree

import (
	"errors"
	"github.com/dedis/crypto/abstract"
)


// MerklePath represents a downward path from a (root) node in a Merkle tree
// to a given (interior or leaf) descendant node,
// including all the data necessary to validate and extract the descendant.
// It is assumed the caller has a valid hash-pointer to the root/starting node,
// and that all nodes in the path can be retrieved via self-certifying hash-ID.
type MerklePath struct {
	Ptr []int	// Offsets of hash-pointers at each intermediate level
	Ofs int		// Offset of relevant object in last-level blob
	Len int		// Length of relevant object in last-level blob
}



// Retrieve an object in a Merkle tree,
// validating the entire path in the process.
// Returns a slice of a buffer obtained from HashGet.Get(),
// which might be shared and should be considered read-only.
func MerkleGet(suite abstract.Suite, root []byte, path MerklePath,
		ctx HashGet) ([]byte,error) {

	// Follow pointers through intermediate levels
	blob := root
	for i := range(path.Ptr) {
		beg := path.Ptr[i]
		end := beg + suite.HashLen()
		if end > len(blob) {
			return nil,errors.New("bad Merkle tree pointer offset")
		}
		id := HashId(blob[beg:end])
		b,e := ctx.Get(id)		// Lookup the next-level blob
		if e != nil {
			return nil,e
		}
		blob = b
	}

	// Validate and extract the actual object
	beg := path.Ofs
	end := beg + path.Len
	if end > len(blob) {
		return nil,errors.New("bad Merkle tree object offset/length")
	}
	return blob[beg:end],nil
}

