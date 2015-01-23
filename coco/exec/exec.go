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
	"log"

	"github.com/dedis/crypto/nist"
	"github.com/dedis/prifi/coco"
)

func main() {
	suite := nist.NewAES128SHA256P256()
	rand := suite.Cipher([]byte("example"))
	addr, err := GetAddress()
	if err != nil {
		log.Fatal("unable to get address: ", addr)
	}
	tcpHost := coco.NewTCPHost()
	coco.NewSigningNode(tcpHost, suite, rand)
	// parse config
	// add children and parent
	// listen for connections
	// connect to parent
	// connect to children
}
