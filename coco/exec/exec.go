// usage exec:
//
// exec -name "hostname" -config "cfg.json"
//
// -name indicates the name of the node in the cfg.json
//
// -config points to the file that holds the configuration.
//     This configuration must be in terms of the final hostnames.

package main

import (
	"flag"
	"log"

	"github.com/dedis/crypto/nist"
	"github.com/dedis/prifi/coco"
)

var hostname string
var configFile string

func init() {
	flag.StringVar(&hostname, "hostname", "", "the hostname of this node")
	flag.StringVar(&configFile, "config", "cfg.json", "the json configuration file")
}

func main() {
	flag.Parse()
	suite := nist.NewAES128SHA256P256()
	rand := suite.Cipher([]byte("example"))
	if hostname == "" {
		log.Fatal("no hostname given")
	}
	// open the testfile
	coco.LoadConfig(configFile, ConfigOptions{ConnType: "tcp", Host: hostname})

	tcpHost := coco.NewTCPHost(hostname)
	coco.NewSigningNode(tcpHost, suite, rand)
	// parse config
	// add children and parent
	// listen for connections
	// connect to parent
	// connect to children
}
