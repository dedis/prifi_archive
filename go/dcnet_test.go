package dissent

import "math/big"
import "testing"

func TestDCnet(*testing.T) {
  count := 100
  dhkeys := make([]*PrivateKey, count)
  pkeys := make([]*PublicKey, count)
  params := GetParameters()
  for i:= 0; i < count; i++ {
    dhkeys[i] = GeneratePrivateKey(params)
    pkeys[i] = &dhkeys[i].PublicKey
  }

  nodes := make([]*Node, count)
  for i:= 0; i < count; i++ {
    nodes[i] = GenerateNode(dhkeys[i], pkeys)
  }

  // big int style
  ciphertext := big.NewInt(0)
  for i := 0; i < count; i++ {
    tmp := new(big.Int).SetBytes(nodes[i].GenerateCiphertext(0))
    ciphertext.Xor(ciphertext, tmp)
  }
  iciphertext := ciphertext

  /*
  ciphertext := make([]byte, CellLength)
  for i := 0; i < count; i++ {
    lciphertext := nodes[i].GenerateCiphertext(0)
    for j := 0; j < len(lciphertext); j++ {
      ciphertext[j] ^= lciphertext[j]
    }
  }
  iciphertext = new(big.Int).SetBytes(ciphertext)
  */

  if iciphertext.Cmp(big.NewInt(0)) != 0 {
    panic("Invalid ciphertext")
  }
}
