package insure

import (
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/config"
)

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
	TakeOutPolicy(keyPair config.KeyPair, serverList []abstract.Point,
		selectInsurers func([]abstract.Point, int) ([]abstract.Point, bool),
		t, n int) (*Policy, bool)

	// Returns the list of insurers for the policy
	GetInsurers() []abstract.Point

	// Returns a list of receipts from each of its insurers verifying that
	// it has taken out a policy with them.
	// TODO determine what type of receipt I want to use.
	GetPolicyProof() int

	/*   The arrays returned by GetInsurers and GetPolicyProof should
	 *   satisfy:
	 *  		for all i, GetInsurers()[i] created GetPolicyProof()[i]
	 */
}
