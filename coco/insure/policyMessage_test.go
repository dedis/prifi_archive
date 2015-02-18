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
	msg := new(RequestInsuranceMessage).createMessage(keyPair.Public, 0, share, pubCommit)

	if !keyPair.Public.Equal(msg.PubKey) || !share.Equal(msg.Share) || !pubCommit.Equal(msg.PubCommit) ||
	   0 != msg.ShareNumber.V.Int64() {
		t.Error("RequestInsuranceMessage was not initialized properly.")
	}
}

// Verifies that the Equal method works.
func TestRequestInsuranceEqual(t *testing.T) {
	share := prishares.Share(0)
	msg := new(RequestInsuranceMessage).createMessage(keyPair.Public, 0, share, pubCommit)
	msgCopy := msg

	if !msg.Equal(msgCopy) {
		t.Error("Messages should be equal.")
	}
	
	// Fails if only the public keys are different.
	msg2 := new(RequestInsuranceMessage).createMessage(keyPair2.Public, 0, share, pubCommit)
	if msg.Equal(msg2) {
		t.Error("Messages should not be equal.")
	}
	
	// Fails if only the share number is different.
	msg2 = new(RequestInsuranceMessage).createMessage(keyPair.Public, 1, share, pubCommit)
	if msg.Equal(msg2) {
		t.Error("Messages should not be equal.")
	}

	// Fails if only the shares are different.
	msg2 = new(RequestInsuranceMessage).createMessage(keyPair.Public, 0, prishares.Share(1), pubCommit)
	if msg.Equal(msg2) {
		t.Error("Messages should not be equal.")
	}

	pripoly2 := new(poly.PriPoly).Pick(INSURE_GROUP, TSHARES, secret, random.Stream)
	otherPoly := new(poly.PubPoly)
	otherPoly.Init(INSURE_GROUP, TSHARES, nil)
	otherPoly.Commit(pripoly2, nil)

	// Fails if only the public polynomial is different
	msg2 = new(RequestInsuranceMessage).createMessage(keyPair.Public, 0, share, otherPoly)
	if msg.Equal(msg2) {
		t.Error("Messages should not be equal.")
	}
}

// Verifies that a RequestInsuranceMessage can be marshalled and unmarshalled
func TestRequestInsuranceMarshallUnMarshall(t *testing.T) {
	share := prishares.Share(5)
	msg := new(RequestInsuranceMessage).createMessage(keyPair.Public, 5, share, pubCommit)
	encodedMsg, err := msg.MarshalBinary()
	if err != nil {
		t.Error("Marshalling failed!")
	}

	newMsg, err2 := new(RequestInsuranceMessage).UnmarshalBinary(encodedMsg)

	if err2 != nil {
		t.Error("Unmarshalling failed!", err2)
		t.FailNow()
	}
	if  !keyPair.Public.Equal(msg.PubKey) || !share.Equal(msg.Share) ||
	    !pubCommit.Equal(msg.PubCommit) ||
	    !msg.Share.Equal(newMsg.Share) || !keyPair.Public.Equal(newMsg.PubKey) ||
	    !msg.PubCommit.Equal(newMsg.PubCommit) ||
	    msg.ShareNumber.V.Int64() != newMsg.ShareNumber.V.Int64() ||
	    !msg.PubCommit.Check(int(msg.ShareNumber.V.Int64()), msg.Share) ||
	    !newMsg.PubCommit.Check(int(newMsg.ShareNumber.V.Int64()), newMsg.Share) {
	    
	    
	    	if !msg.PubCommit.Check(int(newMsg.ShareNumber.V.Int64()), newMsg.Share) {
	    		t.Error("Share and number of new message corrupted")
	    	}
	    
	    	if !newMsg.PubCommit.Check(int(msg.ShareNumber.V.Int64()), msg.Share) {
	    		t.Error("New pub poly failed to verify old share")
	    	}

	    	if !msg.PubCommit.Equal(newMsg.PubCommit) {
	    		t.Error("Polynomials are not equal.")
	    	}
	    
	    
	    	t.Error("Share Number Original", int(msg.ShareNumber.V.Int64()))
	        t.Error("Share Number New", int(newMsg.ShareNumber.V.Int64()) )
	        
	    	bytes, _ := msg.PubCommit.MarshalBinary()
	    	bytes2, _ := newMsg.PubCommit.MarshalBinary()
	    
	    	if len(bytes) != len(bytes2) {
	    		t.Error("Polynomial has been corrupted.")
	    	}
	    
	    	for i := 0; i < len(bytes); i++ {
	    		if bytes[i] != bytes2[i] {
	    			t.Error("Byte corrupted at position: ", i)
	    		}
	    	}
	    	
	    	orgBytes, _ := pubCommit.MarshalBinary()
	    	
	    	for i := 0; i < len(bytes2); i++ {
	    		if orgBytes[i] != bytes2[i] {
	    			t.Error("Byte corrupted at position: ", i)
	    		}
	    	}
	    	
	    	
	    	secbytes, _ := msg.Share.MarshalBinary()
	    	secbytes2, _ := newMsg.Share.MarshalBinary()
	    
	    	if len(secbytes) != len(secbytes2) {
	    		t.Error("Polynomial has been corrupted.")
	    	}
	    
	    	for i := 0; i < len(secbytes); i++ {
	    		if secbytes[i] != secbytes2[i] {
	    			t.Error("Byte corrupted at position: ", i)
	    		}
	    	}
	    	
	    	orgSecButes, _ := share.MarshalBinary()
	    	
	    	for i := 0; i < len(secbytes2); i++ {
	    		if orgSecButes[i] != secbytes2[i] {
	    			t.Error("Byte corrupted at position: ", i)
	    		}
	    	}
	    	
	  	//t.Error("Bytes from original plynomial", orgBytes)
	    	//t.Error("Bytes from original message", bytes)
	    	//t.Error("Bytes from sent message", bytes2)
	    
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

// Verifies that the Equal method works.
func TestPolicyApprovedEqual(t *testing.T) {
	msg := new(PolicyApprovedMessage).createMessage(keyPair, keyPair2.Public)
	msgCopy := msg

	if !msg.Equal(msgCopy) {
		t.Error("Messages should be equal.")
	}
	
	// Fails if the public key pair is different.
	// A different key will generate a different message and signature.
	msg2 := new(PolicyApprovedMessage).createMessage(keyPair2, keyPair2.Public)
	if msg.Equal(msg2) {
		t.Error("Messages should not be equal.")
	}

	// Fails if the public key is different
	msg2 = new(PolicyApprovedMessage).createMessage(keyPair, keyPair.Public)
	if msg.Equal(msg2) {
		t.Error("Messages should not be equal.")
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
	if !keyPair.Public.Equal(msg.PubKey)      ||
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


func PolicyMessageHelper(t *testing.T, policy *PolicyMessage) {
	// Send an RequestInsuranceMessage
	encodedMsg, err := policy.MarshalBinary()
	if err != nil {
		t.Fatal("Marshalling failed!", err)
	}
	policyMsg2 := new(PolicyMessage)
	err = policyMsg2.UnmarshalBinary(encodedMsg)
	if err != nil {
		t.Fatal("Unmarshalling failed!", err)
	}
	
	if policy.Type != policyMsg2.Type {
		t.Error("Unexpected MessageType")
	}
	
	okay := false

	switch policyMsg2.Type {
		case RequestInsurance:
			msg1 := policy.getRIM()
			msg2 := policyMsg2.getRIM()
			if msg1.Share.Equal(msg2.Share) &&
			   msg1.PubCommit.Equal(msg2.PubCommit) {
			   okay = true
			}
		case PolicyApproved:
			msg1 := policy.getPAM()
			msg2 := policyMsg2.getPAM()
			if msg1.PubKey.Equal(msg2.PubKey) &&
			   string(msg1.Message) == string(msg2.Message)   &&
			   string(msg2.Signature) == string(msg2.Signature) {
			   okay = true
			}
	}

	if !okay {
		t.Error("Message corroded after encoding/decoding.")
	}
}

// Verifies that a PolicyApprovedMessage can be marshalled and unmarshalled
// properly. It also checks the verifyCertificate method as well. It insures
// that the signature was properly preserved.
func TestPolicyMessage(t *testing.T) {

	requestMsg := new(RequestInsuranceMessage).createMessage(keyPair.Public, 0, prishares.Share(0), pubCommit)
	approveMsg := new(PolicyApprovedMessage).createMessage(keyPair, keyPair2.Public)
	
	PolicyMessageHelper(t, new(PolicyMessage).createRIMessage(requestMsg))
	PolicyMessageHelper(t, new(PolicyMessage).createPAMessage(approveMsg))
}
