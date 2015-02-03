package sign

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/dedis/crypto/nist"
	"github.com/dedis/prifi/coco/coconet"
	"github.com/dedis/prifi/coco/stamp"
)

// test marshalling and unmarshalling for
// the various types of signing messages

func TestMUAnnouncement(t *testing.T) {
	logTest := []byte("Hello World")
	am := AnnouncementMessage{LogTest: logTest}

	dataBytes, err := AnnouncementMessage.MarshalBinary(am)
	if err != nil {
		t.Error("Marshaling didn't work")
	}

	am2 := &AnnouncementMessage{}
	am2.UnmarshalBinary(dataBytes)
	if err != nil {
		t.Error("Unmarshaling didn't work")
	}

	fmt.Println(am2)
	fmt.Println("Marshal and Unmarshal work")
}

// Test for Marshalling and Unmarshalling Challenge Messages
// Important: when making empty HashIds len should be set to HASH_SIZE
func TestMUChallenge(t *testing.T) {
	nHashIds := 3

	var err error
	suite := nist.NewAES128SHA256P256()
	rand := suite.Cipher([]byte("example"))

	cm := ChallengeMessage{}
	cm.C = suite.Secret().Pick(rand)
	cm.MTRoot = make([]byte, HASH_SIZE)
	cm.Proof = stamp.Proof(make([]stamp.HashId, nHashIds))
	for i := 0; i < nHashIds; i++ {
		cm.Proof[i] = make([]byte, HASH_SIZE)
	}

	cmBytes, err := cm.MarshalBinary()
	if err != nil {
		t.Error(err)
	}

	var messg coconet.BinaryUnmarshaler
	messg = &ChallengeMessage{}
	err = messg.UnmarshalBinary(cmBytes)
	cm2 := messg.(*ChallengeMessage)

	// test for equality after marshal and unmarshal
	if !cm2.C.Equal(cm.C) ||
		bytes.Compare(cm2.MTRoot, cm.MTRoot) != 0 ||
		!byteArrayEqual(cm2.Proof, cm.Proof) {
		t.Error("challenge message MU failed")
	}

	// log.Println(cm)
	// log.Println()
	// log.Println(cm2)
}

// Test for Marshalling and Unmarshalling Comit Messages
// Important: when making empty HashIds len should be set to HASH_SIZE
func TestMUCommit(t *testing.T) {
	var err error
	suite := nist.NewAES128SHA256P256()
	rand := suite.Cipher([]byte("exampfsdjkhujgkjsgfjgle"))
	rand2 := suite.Cipher([]byte("examplsfhsjedgjhsge2"))

	cm := CommitmentMessage{}
	cm.V, _ = suite.Point().Pick(nil, rand)
	cm.V_hat, _ = suite.Point().Pick(nil, rand2)

	// log.Println("v and v_hat len", cm.V.Len(), cm.V_hat.Len())

	cm.MTRoot = make([]byte, HASH_SIZE)

	cmBytes, err := cm.MarshalBinary()
	if err != nil {
		t.Error(err)
	}

	var messg coconet.BinaryUnmarshaler
	messg = &CommitmentMessage{}
	err = messg.UnmarshalBinary(cmBytes)
	cm2 := messg.(*CommitmentMessage)

	// test for equality after marshal and unmarshal
	if !cm2.V.Equal(cm.V) ||
		!cm2.V_hat.Equal(cm.V_hat) ||
		bytes.Compare(cm2.MTRoot, cm.MTRoot) != 0 {
		t.Error("commit message MU failed")
	}

	// log.Println(cm)
	// log.Println()
	// log.Println(cm2)
}

func byteArrayEqual(a stamp.Proof, b stamp.Proof) bool {
	n := len(a)
	if n != len(b) {
		return false
	}

	for i := 0; i < n; i++ {
		if bytes.Compare(a[i], b[i]) != 0 {
			return false
		}
	}

	return true
}
