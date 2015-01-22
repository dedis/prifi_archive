package time

import (
	"testing"

	"github.com/dedis/crypto/nist"
	// "github.com/dedis/prifi/coco"
)

//      server-node
//       /
//  client node
func TestStatic(t *testing.T) {
	// Crypto setup
	suite := nist.NewAES128SHA256P256()
	rand := suite.Cipher([]byte("example"))

	// create new directory for communication between peers
	dir := newDirectory()

}
