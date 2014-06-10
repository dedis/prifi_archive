package dissent

import "testing"

func TestDh(*testing.T) {
  params := GetParameters()
  k0 := GeneratePrivateKey(params)
  k1 := GeneratePrivateKey(params)
  s0 := k0.Exchange(&k1.PublicKey)
  s1 := k1.Exchange(&k0.PublicKey)
  if s0.Cmp(s1) != 0 {
    panic("s0 != s1")
  }
}
