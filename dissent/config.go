package main

import (
	"github.com/dedis/crypto/config"
	"github.com/dedis/crypto/suites"
)

var configFile config.File

// Dissent config file format
type ConfigData struct {
	Keys config.Keys		// Info on configured key-pairs
}

var configData ConfigData
var keyPairs []config.KeyPair

func readConfig() error {

	// Load the configuration file
	configFile.Load("dissent", &configData)

	// Read or create our public/private keypairs
	pairs,err := configFile.Keys(&configData.Keys, suites.All(),
					defaultSuite)
	if err != nil {
		return err
	}
	keyPairs = pairs
	println("Loaded",len(pairs),"key-pairs")

	return nil
}

