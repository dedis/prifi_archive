package insure

import (
	"testing"

	"github.com/dedis/crypto/config"
	"github.com/dedis/crypto/random"
	"github.com/dedis/crypto/poly"
)

var n int = 20
var secret    = INSURE_GROUP.Secret().Pick(random.Stream)
var point     = INSURE_GROUP.Point().Mul(INSURE_GROUP.Point().Base(), secret)
var point2    = INSURE_GROUP.Point().Mul(INSURE_GROUP.Point().Base(),
			INSURE_GROUP.Secret())
var pripoly   = new(poly.PriPoly).Pick(INSURE_GROUP, TSHARES, secret, random.Stream)
var prishares = new(poly.PriShares).Split(pripoly, n)
var pubCommit = producePubPoly()

var keyPair  = produceKeyPair()
var keyPair2 = produceKeyPair()

// Used to initialize the public commit polynomial.
func producePubPoly() *poly.PubPoly {
	testPubPoly := new(poly.PubPoly)
	testPubPoly.Init(INSURE_GROUP, n, nil)
	return testPubPoly.Commit(pripoly, nil)
}

// Used to initialize the key pairs.
func produceKeyPair() *config.KeyPair {
	keyPair := new(config.KeyPair)
	keyPair.Gen(KEY_SUITE, random.Stream)
	return keyPair
}


// Verifies that a RequestInsuranceMessage can be created properly.
func TestRequestInsuranceCreate(t *testing.T) {
	share := prishares.Share(0)
	msg := new(RequestInsuranceMessage).createMessage(share, pubCommit)

	if !share.Equal(msg.Share) || !pubCommit.Equal(msg.PubCommit) {
		t.Error("RequestInsuranceMessage was not initialized properly.")
	}
}

// Verifies that a RequestInsuranceMessage can be marshalled and unmarshalled
func TestRequestInsuranceMarshallUnMarshall(t *testing.T) {
	share := prishares.Share(0)
	msg := new(RequestInsuranceMessage).createMessage(share, pubCommit)
	encodedMsg, err := msg.MarshalBinary()
	if err != nil {
		t.Error("Marshalling failed!")
	}

	newMsg, err2 := new(RequestInsuranceMessage).UnmarshalBinary(encodedMsg)

	if err2 != nil {
		t.Error("Unmarshalling failed!", err2)
		t.FailNow()
	}
	if  !share.Equal(msg.Share) || !pubCommit.Equal(msg.PubCommit) ||
	    !msg.Share.Equal(newMsg.Share) ||
	    !msg.PubCommit.Equal(newMsg.PubCommit) {
		t.Error("Data was lost during marshalling.")
	}
}

// Verifies that a PolicyApprovedMessage can be created properly.
func TestPolicyApprovedCreate(t *testing.T) {

	msg := new(PolicyApprovedMessage).createMessage(keyPair, keyPair2.Public)
	
	expectedMessage := keyPair.Public.String() + " insures " + keyPair2.Public.String()

	if !keyPair.Public.Equal(msg.PubKey) ||
	   expectedMessage != (string(msg.Message)) {
		t.Error("RequestInsuranceMessage was not initialized properly.")
	}
}

// Verifies that a PolicyApprovedMessage can be marshalled and unmarshalled
// properly. It also checks the verifyCertificate method as well. It insures
// that the signature was properly preserved.
func TestPolicyApprovedMarshallUnMarshallVerify(t *testing.T) {
	msg := new(PolicyApprovedMessage).createMessage(keyPair, keyPair2.Public)

	encodedMsg, err := msg.MarshalBinary()
	if err != nil {
		t.Fatal("Marshalling failed! ", err)
	}

	newMsg, err2 := new(PolicyApprovedMessage).UnmarshalBinary(encodedMsg)
	if err2 != nil {
		t.Fatal("Unmarshalling failed! ", err2)
	}

	expectedMessage := keyPair.Public.String() + " insures " + keyPair2.Public.String()
	if  !keyPair.Public.Equal(msg.PubKey)      ||
	    expectedMessage != string(msg.Message) {
	    t.Error("The original message does not contain the proper values")
	}
	if !msg.PubKey.Equal(newMsg.PubKey) ||
	    string(msg.Message) != string(newMsg.Message) {
		t.Error("Data was lost during marshalling.")
	}
	if !msg.verifyCertificate(keyPair.Suite, keyPair2.Public) ||
  	   !newMsg.verifyCertificate(keyPair.Suite, keyPair2.Public) {
  		t.Error("The signature is invalid.")   
  	}
}
