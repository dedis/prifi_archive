package dissent

import "crypto/aes"
import "crypto/cipher"
import "math/big"

//import "fmt"

const (
  CellLength = 1024
)

type Node struct {
  Key *PrivateKey
  Secrets []*big.Int
  Index int
}

func GenerateNode(key *PrivateKey, keys []*PublicKey) *Node {
  node := new(Node)
  node.Key = key
  node.Secrets = make([]*big.Int, len(keys) - 1)
  node.Index = -1
  ri := 0
  for i := 0; i < len(keys); i++ {
    if key.Y.Cmp(keys[i].Y) == 0 {
      node.Index = i
      continue
    }

    if ri == len(node.Secrets) {
      panic("Public key not found")
    }

    node.Secrets[ri] = key.Exchange(keys[i])
    ri++
  }
  return node
}

func (node *Node) GenerateCiphertext(cell int) []byte {
  ciphertext := make([]byte, CellLength)
  for i := 0; i < len(node.Secrets); i += 1 {
    seed := node.Secrets[i].Bytes()[0:16]

    block, err := aes.NewCipher(seed)
    if err != nil {
      panic(err)
    }

    stream := cipher.NewCTR(block, seed)
    stream.XORKeyStream(ciphertext, ciphertext)
  }
  return ciphertext
}
