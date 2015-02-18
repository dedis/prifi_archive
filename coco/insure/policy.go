package insure

import (
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/edwards"
	"github.com/dedis/crypto/nist"
)

const (
	// The minimum number of private shares needed in order to reconstruct the
	// private secret. This parameter must be known in order to properly decode
	// public polynomial commits. This also ensures a uniform policy across nodes.
	TSHARES int = 10
)

// This is the group that will be used for all shares. This should be treated as
// a constant.
var INSURE_GROUP abstract.Group = new(edwards.ExtendedCurve).Init(
	edwards.Param25519(), false)

// This will be the group that all public keys are derived from. This will be
// needed when marshalling/unmarshalling messages.
var KEY_SUITE abstract.Suite = nist.NewAES128SHA256P256()

/* This is an abstract interface for an insurance policy. Coco servers
 * will each carry their own policies and will be required to take one out
 * before participating in the system. At any point, they should be ready to
 * prove that they carry a valid policy. For a detailed summary of the insurance
 * policy protocol, please see doc.go
 */

type Policy interface {

	// Returns the private key being insured
	GetPrivateKey() abstract.Secret

	// This function produces a new policy. Given the pub/pri key of a
	// server and a list of potential insurers, it selects a subset of these
	// servers of size "n" using the selectInsurers function. It then
	// distributes shares of the private key to each where only "t" are
	// needed to reconstruct the secret. Once it has achieved at least "r"
	// receipts from other servers verifying that it has taken out a policy
	// with them (where t <= r <= n), the function returns the new policy.
	TakeOutPolicy(serverList []abstract.Point,
		selectInsurers func([]abstract.Point, int) ([]abstract.Point, bool),
		n int) (*Policy, bool)

	// Returns the list of insurers for the policy
	GetInsurers() []abstract.Point

	// Returns a list of receipts from each of its insurers verifying that
	// it has taken out a policy with them.
	// TODO determine what type of receipt I want to use.
	GetPolicyProof() []PolicyApprovedMessage

	/*   The arrays returned by GetInsurers and GetPolicyProof should
	 *   satisfy:
	 *  		for all i, GetInsurers()[i] created GetPolicyProof()[i]
	 */
}
