package main

import (
	"os"
	"errors"
	"encoding/base64"
	"dissent/util"
	"github.com/BurntSushi/toml"
	"github.com/dedis/crypto/abstract"
)

type Config struct {
	PubKey string		// XXX should support more than one
}

var config Config

var pubKey abstract.Point
var secKey abstract.Secret

func getConfDir() string {
	homedir := os.Getenv("HOME")	// XXX os-specific
	confdir := homedir + "/.dissent"

	// Create the .dissent config directory it doesn't already exist
	if err := os.MkdirAll(confdir, 0700); err != nil {
		panic("Error creating directory "+confdir+": "+err.Error())
	}

	// Sanity-check the .dissent directory permission bits for security
	if fi,err := os.Stat(confdir); err != nil || (fi.Mode() & 0077) != 0 {
		panic("Directory "+confdir+" has bad permissions")
	}

	return confdir
}

func keyString(pubkey abstract.Point) string {
	return base64.URLEncoding.EncodeToString(pubkey.Encode())
}

func getKey(confdir string) error {

	// XXX add support for passphrase-encrypted or system-keychain keys

	if config.PubKey == "" {
		return newKey(confdir)
	}
	pubStr := config.PubKey

	// Read the private key file
	secname := confdir+"/sec-"+pubStr
	f,err := os.Open(secname)
	if err != nil {
		return err
	}
	defer f.Close()

	if err := abstract.Read(f, &secKey, suite); err != nil {
		return err
	}

	pubKey := suite.Point().Mul(nil, secKey)
	if keyString(pubKey) != config.PubKey {
		return errors.New("Secret doesn't produce correct public key")
	}

	return nil
}

func newKey(confdir string) error {

	// Create a fresh public/private keypair
	secKey = suite.Secret().Pick(abstract.RandomStream)
	pubKey = suite.Point().Mul(nil,secKey)
	pubStr := keyString(pubKey)

	// Write the private key file
	secname := confdir+"/sec-"+pubStr
	r := util.Replacer{}
	if err := r.Open(secname); err != nil {
		return err
	}
	defer r.Abort()

	// Write the key
	if err := abstract.Write(r.File, &secKey, suite); err != nil {
		return err
	}

	// Commit the secret key
	if err := r.Commit(); err != nil {
		return err
	}

	// Re-write the config file with the new public key
	config.PubKey = keyString(pubKey)
	if err := writeConfig(); err != nil {
		return err
	}

	return nil
}

func readConfig() error {
	confdir := getConfDir()

	// Read the config file if it exists
	filename := confdir+"/config"
	_,err := toml.DecodeFile(filename, &config)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	// Read or create our private key.
	if err := getKey(confdir); err != nil {
		return err
	}

	return nil
}

func writeConfig() error {
	confdir := getConfDir()

	// Write the new config file
	filename := confdir+"/config"
	r := util.Replacer{}
	if err := r.Open(filename); err != nil {
		return err
	}
	defer r.Abort()

	// Encode the config
	enc := toml.NewEncoder(r.File)
	if err := enc.Encode(&config); err != nil {
		return err
	}

	// Commit the new config
	if err := r.Commit(); err != nil {
		return err
	} 

	return nil
}

