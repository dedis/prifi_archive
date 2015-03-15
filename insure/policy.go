package insure

import (
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/edwards"
	"github.com/dedis/crypto/nist"
)

const (
	// The minimum number of private shares needed in order to reconstruct
	// the private secret. This parameter must be known in order to properly
	// decode public polynomial commits.
	TSHARES int = 10
)

// The group to be used for all shares and should be constant.
var INSURE_GROUP abstract.Group = new(edwards.ExtendedCurve).Init(
	edwards.Param25519(), false)

// The group to be used for all public/private key pairs and should be constant.
var KEY_SUITE abstract.Suite = nist.NewAES128SHA256P256()
