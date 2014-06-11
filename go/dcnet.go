package dissent

import "crypto/aes"
import "crypto/cipher"
import "crypto/sha256"
import "math/big"

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

func (node *Node) GenerateCiphertext(cell int64) []byte {
  ciphertext := make([]byte, CellLength)
  for i := 0; i < len(node.Secrets); i += 1 {
    hash := sha256.New()
    hash.Write(node.Secrets[i].Bytes())
    hash.Write(big.NewInt(cell).Bytes())
    seed := hash.Sum(nil)[0:16]

    block, err := aes.NewCipher(seed)
    if err != nil {
      panic(err)
    }

    stream := cipher.NewCTR(block, seed)
    stream.XORKeyStream(ciphertext, ciphertext)
  }
  return ciphertext
}
