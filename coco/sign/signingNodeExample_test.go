package sign_test

import (
	"log"

	"github.com/dedis/crypto/nist"
	"github.com/dedis/prifi/coco/coconet"
	"github.com/dedis/prifi/coco/sign"
)

func ExampleReadWrite() {
	suite := nist.NewAES128SHA256P256()
	rand := suite.Cipher([]byte("example"))

	testBytes := []byte("test")

	s := suite.Secret().Pick(rand)
	m := sign.TestMessage{S: s, Bytes: testBytes}
	h := coconet.NewGoHost("exampleHost", nil)
	sn := sign.NewSigningNode(h, suite, rand)

	dataBytes := sn.Write(m)
	dataInterface, err := sn.Read(dataBytes)
	if err != nil {
		log.Fatal("Decoding didn't work")
	}

	switch mDecoded := dataInterface.(type) {
	case sign.TestMessage:
		log.Println(mDecoded)
	default:
		log.Fatal("Decoding didn't work")
	}

}
