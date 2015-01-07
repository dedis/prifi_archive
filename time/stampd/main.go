package main

import (
	"github.com/dedis/crypto/config"
	"github.com/dedis/crypto/suites"
	"github.com/dedis/crypto/nist"
)

type ConfigData struct {
	Keys config.Keys	// Configured key-pairs for this timestap server
}

var keyPairs []config.KeyPair
var configData ConfigData
var configFile config.File

var defaultSuite = nist.NewAES128SHA256P256()
var cryptoSuites = suites.All()

func readConfig() error {

	// Load the configuration file
	configFile.Load("stampd", &configData)

	// Read or create our public/private keypairs
	pairs,err := configFile.Keys(&configData.Keys, cryptoSuites,
					defaultSuite)
	if err != nil {
		return err
	}
	keyPairs = pairs

	return nil
}

func main() {
	readConfig()
}

