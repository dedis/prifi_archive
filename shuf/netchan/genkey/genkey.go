package main

import (
	"fmt"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/edwards/ed25519"
	"os"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Printf("Usage: genkey [pubkeyFile] [privkeyFile]\n")
		os.Exit(1)
	}

	// Open the files
	pubFile, err1 := os.Create(os.Args[1])
	if err1 != nil {
		fmt.Printf("%s\n", err1.Error())
		os.Exit(1)
	}
	privFile, err2 := os.Create(os.Args[2])
	if err2 != nil {
		fmt.Printf("%s\n", err2.Error())
		pubFile.Close()
		os.Exit(1)
	}

	// Generate the keys
	suite := ed25519.NewAES128SHA256Ed25519(true)
	rand := suite.Cipher(abstract.RandomKey)
	secret := suite.Secret().Pick(rand)
	public := suite.Point().Mul(nil, secret)

	// Write the keys
	secret.MarshalTo(privFile)
	public.MarshalTo(pubFile)
	pubFile.Close()
	privFile.Close()
}
