package coco

import (
	"fmt"
	"testing"

	"github.com/dedis/crypto/nist"
)

func TestReadWrite(t *testing.T) {
	return
	suite := nist.NewAES128SHA256P256()
	rand := suite.Cipher([]byte("example"))

	testBytes := []byte("Hello World")
	s := suite.Secret().Pick(rand)
	m := TestMessage{S: s, Bytes: testBytes}
	h := NewHostNode("exampleHost", nil)
	sn := NewSigningNode(h, suite, rand)

	dataBytes := sn.Write(m)
	dataInterface, err := sn.Read(dataBytes)
	if err != nil {
		t.Error("Decoding didn't work")
	}
	fmt.Println(dataInterface)

	switch mDecoded := dataInterface.(type) {
	case TestMessage:
		fmt.Println("Decoded annoucement message")
		fmt.Println(mDecoded)
	default:
		t.Error("Decoding didn't work")
	}

}
