package coco

import (
	"log"

	"github.com/dedis/crypto/nist"
	"github.com/dedis/prifi/coco/coconet"
)

func ExampleReadWrite() {
	suite := nist.NewAES128SHA256P256()
	rand := suite.Cipher([]byte("example"))

	testBytes := []byte("test")

	s := suite.Secret().Pick(rand)
	m := TestMessage{S: s, Bytes: testBytes}
	h := coconet.NewGoHost("exampleHost", nil)
	sn := NewSigningNode(h, suite, rand)

	dataBytes := sn.Write(m)
	dataInterface, err := sn.Read(dataBytes)
	if err != nil {
		log.Fatal("Decoding didn't work")
	}

	switch mDecoded := dataInterface.(type) {
	case TestMessage:
		log.Println(mDecoded)
	default:
		log.Fatal("Decoding didn't work")
	}

}
