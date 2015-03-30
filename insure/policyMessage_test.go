package insure

import (
	"bytes"
	"testing"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/config"
	"github.com/dedis/crypto/edwards"
	"github.com/dedis/crypto/poly/promise"
	"github.com/dedis/crypto/nist"
	"github.com/dedis/crypto/random"
)

var suite = nist.NewAES128SHA256P256()
var altSuite = edwards.NewAES128SHA256Ed25519(false)

var basicShare = suite.Secret()
var secretKey = produceKeyPair()
var promiserKey = produceKeyPair()

var pt = 10
var r = 15
var numInsurers = 20

var insurerKeys = produceinsurerKeys()
var insurerList = produceinsurerList()

var basicPromise = new(promise.Promise).ConstructPromise(secretKey, promiserKey, pt, r, insurerList)
var basicPromise2 = new(promise.Promise).ConstructPromise(secretKey,  produceKeyPair(), 5, r, insurerList)

var basicResponse, _ = basicPromise.ProduceResponse(10, insurerKeys[10])

var basicCertifyMessage = new(CertifyPromiseMessage).createMessage(10, *basicPromise)
var basicResponseMessage = new(PromiseResponseMessage).createMessage(10, *basicPromise, basicResponse)

var basicShareRequest  = new(PromiseShareMessage).createRequestMessage(10, *basicPromise)
var basicShareResponse = new(PromiseShareMessage).createResponseMessage(10, *basicPromise, basicShare)

func produceKeyPair() *config.KeyPair {
	keyPair := new(config.KeyPair)
	keyPair.Gen(suite, random.Stream)
	return keyPair
}

func produceAltKeyPair() *config.KeyPair {
	keyPair := new(config.KeyPair)
	keyPair.Gen(altSuite, random.Stream)
	return keyPair
}

func produceinsurerKeys() []*config.KeyPair {
	newArray := make([]*config.KeyPair, numInsurers, numInsurers)
	for i := 0; i < numInsurers; i++ {
		newArray[i] = produceKeyPair()
	}
	return newArray
}

func produceinsurerList() []abstract.Point {
	newArray := make([]abstract.Point, numInsurers, numInsurers)
	for i := 0; i < numInsurers; i++ {
		newArray[i] = insurerKeys[i].Public
	}
	return newArray
}


// Verifies that a CertifyPromiseMessage can be created properly.
func TestCertifyPromiseMessageCreateMessage(t *testing.T) {
	msg := new(CertifyPromiseMessage).createMessage(10, *basicPromise)

	if msg.ShareIndex != 10 {
		t.Error("ShareIndex not properly set.")
	}

	if !msg.Promise.Equal(basicPromise) {
		t.Error("Promise not properly set.")
	}
}

// Verifies that the Equal method works.
func TestCertifyPromiseMessageEqual(t *testing.T) {

	if !basicCertifyMessage.Equal(basicCertifyMessage) {
		t.Error("Message should equal itself.")
	}

	msg2 := new(CertifyPromiseMessage).createMessage(1, *basicPromise)
	if basicCertifyMessage.Equal(msg2) {
		t.Error("Share Indices differ.")
	}

	msg2 = new(CertifyPromiseMessage).createMessage(10, *basicPromise2)
	if basicCertifyMessage.Equal(msg2) {
		t.Error("Promises differ.")
	}
}

// Verifies that a CertifyPromiseMessage can be marshalled and unmarshalled
func TestCertifyPromiseMessageUnMarshall(t *testing.T) {
	// Since Equal can't be used on a promise until it has been fully
	// unmarshalled, simply make sure this doesn't fail.
	new(CertifyPromiseMessage).UnmarshalInit(pt,r,numInsurers, suite)
}

// Verifies that blameProof's marshalling methods work properly.
func TestCertifyPromiseMessageMarshalling(t *testing.T) {
	// Tests BinaryMarshal, BinaryUnmarshal, and MarshalSize
	encodedCM, err := basicCertifyMessage.MarshalBinary()
	if err != nil || len(encodedCM) != basicCertifyMessage.MarshalSize() {
		t.Fatal("Marshalling failed: ", err)
	}

	decodedCM := new(CertifyPromiseMessage).UnmarshalInit(pt,r,numInsurers, suite)
	err = decodedCM.UnmarshalBinary(encodedCM)
	if err != nil {
		t.Fatal("UnMarshalling failed: ", err)
	}
	if !basicCertifyMessage.Equal(decodedCM) {
		t.Error("Decoded blameProof not equal to original")
	}
	if basicCertifyMessage.MarshalSize() != decodedCM.MarshalSize() {
		t.Error("MarshalSize of decoded and original differ: ",
			basicCertifyMessage.MarshalSize(), decodedCM.MarshalSize())
	}

	// Tests MarshlTo and UnmarshalFrom
	bufWriter := new(bytes.Buffer)
	bytesWritter, errs := basicCertifyMessage.MarshalTo(bufWriter)
	if bytesWritter != basicCertifyMessage.MarshalSize() || errs != nil {
		t.Fatal("MarshalTo failed: ", bytesWritter, err)
	}

	decodedCM = new(CertifyPromiseMessage).UnmarshalInit(pt,r,numInsurers, suite)
	bufReader := bytes.NewReader(bufWriter.Bytes())
	bytesRead, errs2 := decodedCM.UnmarshalFrom(bufReader)
	if bytesRead != decodedCM.MarshalSize() || errs2 != nil {
		t.Fatal("UnmarshalFrom failed: ", bytesRead, errs2)
	}
	if basicCertifyMessage.MarshalSize() != decodedCM.MarshalSize() {
		t.Error("MarshalSize of decoded and original differ: ",
			basicCertifyMessage.MarshalSize(), decodedCM.MarshalSize())
	}
	if !basicCertifyMessage.Equal(decodedCM) {
		t.Error("blameProof read does not equal original")
	}
}

// Verifies that a PromiseResponseMessage can be created properly.
func TestPromiseResponseMessageCreateMessage(t *testing.T) {

	responseMsg := new(PromiseResponseMessage).createMessage(10, *basicPromise, basicResponse)
	if responseMsg.ShareIndex != 10 {
		t.Error("ShareIndex not properly initialized")
	}
	if responseMsg.Id != basicPromise.Id() {
		t.Error("Promise Id differs")
	}
	if responseMsg.PromiserId != basicPromise.PromiserId() {
		t.Error("Id of the Promiser differs")
	}
	if !responseMsg.Response.Equal(basicResponse) {
		t.Error("Responses differ")
	}
}


// Verifies that a CertifyPromiseMessage can be marshalled and unmarshalled
func TestPromiseResponseMessageUnMarshall(t *testing.T) {
	// Since Equal can't be used on a promise until it has been fully
	// unmarshalled, simply make sure this doesn't fail.
	new(PromiseResponseMessage).UnmarshalInit(suite)
}

// Verifies that the Equal method works.
func TestPromiseResponseMessageEqual(t *testing.T) {

	if !basicResponseMessage.Equal(basicResponseMessage) {
		t.Error("Message should equal itself.")
	}

	msg2 := new(PromiseResponseMessage).createMessage(1, *basicPromise, basicResponse)
	if basicResponseMessage.Equal(msg2) {
		t.Error("Share Indices differ.")
	}

	newPromise := new(promise.Promise).ConstructPromise(secretKey,  produceKeyPair(), 5, r, insurerList)
	msg2 = new(PromiseResponseMessage).createMessage(10, *newPromise, basicResponse)
	if basicResponseMessage.Equal(msg2) {
		t.Error("PromiserId differs.")
	}

	newPromise = new(promise.Promise).ConstructPromise(produceKeyPair(),  promiserKey, 5, r, insurerList)
	msg2 = new(PromiseResponseMessage).createMessage(10, *newPromise, basicResponse)
	if basicResponseMessage.Equal(msg2) {
		t.Error("Id differs.")
	}

	response, _ := basicPromise.ProduceResponse(1, insurerKeys[1])
	msg2 = new(PromiseResponseMessage).createMessage(10, *basicPromise, response)
	if basicResponseMessage.Equal(msg2) {
		t.Error("Response differs.")
	}
}

// Verifies that blameProof's marshalling methods work properly.
func TestPromiseResponseMessageMarshalling(t *testing.T) {
	// Tests BinaryMarshal, BinaryUnmarshal, and MarshalSize
	encodedPRM, err := basicResponseMessage.MarshalBinary()
	if err != nil || len(encodedPRM) != basicResponseMessage.MarshalSize() {
		t.Fatal("Marshalling failed: ", err)
	}

	decodedPRM := new(PromiseResponseMessage).UnmarshalInit(suite)
	err = decodedPRM.UnmarshalBinary(encodedPRM)
	if err != nil {
		t.Fatal("UnMarshalling failed: ", err)
	}
	if !basicResponseMessage.Equal(decodedPRM) {
		t.Error("Decoded ResponseMessage not equal to original")
	}
	if basicResponseMessage.MarshalSize() != decodedPRM.MarshalSize() {
		t.Error("MarshalSize of decoded and original differ: ",
			basicResponseMessage.MarshalSize(), decodedPRM.MarshalSize())
	}

	// Tests MarshlTo and UnmarshalFrom
	bufWriter := new(bytes.Buffer)
	bytesWritter, errs := basicResponseMessage.MarshalTo(bufWriter)
	if bytesWritter != basicResponseMessage.MarshalSize() || errs != nil {
		t.Fatal("MarshalTo failed: ", bytesWritter, err)
	}

	decodedPRM = new(PromiseResponseMessage).UnmarshalInit(suite)
	bufReader := bytes.NewReader(bufWriter.Bytes())
	bytesRead, errs2 := decodedPRM.UnmarshalFrom(bufReader)
	if bytesRead != decodedPRM.MarshalSize() || errs2 != nil {
		t.Fatal("UnmarshalFrom failed: ", bytesRead, errs2)
	}
	if basicResponseMessage.MarshalSize() != decodedPRM.MarshalSize() {
		t.Error("MarshalSize of decoded and original differ: ",
			basicResponseMessage.MarshalSize(), decodedPRM.MarshalSize())
	}
	if !basicResponseMessage.Equal(decodedPRM) {
		t.Error("blameProof read does not equal original")
	}
}




// Verifies that a PromiseShareMessage can be created properly.
func TestPromiseShareMessageCreateRequestMessage(t *testing.T) {
	shareMsg := new(PromiseShareMessage).createRequestMessage(10, *basicPromise)
	if shareMsg.ShareIndex != 10 {
		t.Error("ShareIndex not properly initialized")
	}
	if shareMsg.Id != basicPromise.Id() {
		t.Error("Promise Id differs")
	}
	if shareMsg.PromiserId != basicPromise.PromiserId() {
		t.Error("Id of the Promiser differs")
	}
	if shareMsg.Share != nil {
		t.Error("Share should be nil")
	}
}

// Verifies that a PromiseShareMessage can be created properly.
func TestPromiseShareMessageCreateResponseMessage(t *testing.T) {
	shareMsg := new(PromiseShareMessage).createResponseMessage(10, *basicPromise, basicShare)
	if shareMsg.ShareIndex != 10 {
		t.Error("ShareIndex not properly initialized")
	}
	if shareMsg.Id != basicPromise.Id() {
		t.Error("Promise Id differs")
	}
	if shareMsg.PromiserId != basicPromise.PromiserId() {
		t.Error("Id of the Promiser differs")
	}
	if !shareMsg.Share.Equal(basicShare) {
		t.Error("Shares differ")
	}
}


// Verifies that a CertifyPromiseMessage can be marshalled and unmarshalled
func TestPromiseShareMessageUnMarshall(t *testing.T) {
	// Since Equal can't be used on a promise until it has been fully
	// unmarshalled, simply make sure this doesn't fail.
	new(PromiseShareMessage).UnmarshalInit(suite)
}

// Verifies that the Equal method works.
func TestPromiseShareMessageEqual(t *testing.T) {

	if !basicShareRequest.Equal(basicShareRequest) {
		t.Error("Message should equal itself.")
	}

	if !basicShareResponse.Equal(basicShareResponse) {
		t.Error("Message should equal itself.")
	}

	msg2 := new(PromiseShareMessage).createResponseMessage(1, *basicPromise, basicShare)
	if basicShareResponse.Equal(msg2) {
		t.Error("Share Indices differ.")
	}

	newPromise := new(promise.Promise).ConstructPromise(secretKey,  produceKeyPair(), 5, r, insurerList)
	msg2 = new(PromiseShareMessage).createResponseMessage(10, *newPromise, basicShare)
	if basicShareResponse.Equal(msg2) {
		t.Error("PromiserId differs.")
	}

	newPromise = new(promise.Promise).ConstructPromise(produceKeyPair(),  promiserKey, 5, r, insurerList)
	msg2 = new(PromiseShareMessage).createResponseMessage(10, *newPromise, basicShare)
	if basicShareResponse.Equal(msg2) {
		t.Error("Id differs.")
	}

	if basicShareResponse.Equal(basicShareRequest) {
		t.Error("Shares differ.")
	}
}

// Verifies that blameProof's marshalling methods work properly.
func TestPromiseShareMessageMarshalling(t *testing.T) {
	// Test with the request messages.
	// Tests BinaryMarshal, BinaryUnmarshal, and MarshalSize
	encodedMsg, err := basicShareRequest.MarshalBinary()
	if err != nil || len(encodedMsg) != basicShareRequest.MarshalSize() {
		t.Fatal("Marshalling failed: ", err)
	}

	decodedMsg := new(PromiseShareMessage).UnmarshalInit(suite)
	err = decodedMsg.UnmarshalBinary(encodedMsg)
	if err != nil {
		t.Fatal("UnMarshalling failed: ", err)
	}
	if !basicShareRequest.Equal(decodedMsg) {
		t.Error("Decoded PromiseShareMessage not equal to original")
	}
	if basicShareRequest.MarshalSize() != decodedMsg.MarshalSize() {
		t.Error("MarshalSize of decoded and original differ: ",
			basicShareRequest.MarshalSize(), decodedMsg.MarshalSize())
	}

	// Tests MarshlTo and UnmarshalFrom
	bufWriter := new(bytes.Buffer)
	bytesWritter, errs := basicShareRequest.MarshalTo(bufWriter)
	if bytesWritter != basicShareRequest.MarshalSize() || errs != nil {
		t.Fatal("MarshalTo failed: ", bytesWritter, err)
	}

	decodedMsg = new(PromiseShareMessage).UnmarshalInit(suite)
	bufReader := bytes.NewReader(bufWriter.Bytes())
	bytesRead, errs2 := decodedMsg.UnmarshalFrom(bufReader)
	if bytesRead != decodedMsg.MarshalSize() || errs2 != nil {
		t.Fatal("UnmarshalFrom failed: ", bytesRead, errs2)
	}
	if basicShareRequest.MarshalSize() != decodedMsg.MarshalSize() {
		t.Error("MarshalSize of decoded and original differ: ",
			basicShareRequest.MarshalSize(), decodedMsg.MarshalSize())
	}
	if !basicShareRequest.Equal(decodedMsg) {
		t.Error("Msg read does not equal original")
	}

	//Test with the response messages
	// Tests BinaryMarshal, BinaryUnmarshal, and MarshalSize
	encodedMsg, err = basicShareResponse.MarshalBinary()
	if err != nil || len(encodedMsg) != basicShareResponse.MarshalSize() {
		t.Fatal("Marshalling failed: ", err)
	}

	decodedMsg = new(PromiseShareMessage).UnmarshalInit(suite)
	err = decodedMsg.UnmarshalBinary(encodedMsg)
	if err != nil {
		t.Fatal("UnMarshalling failed: ", err)
	}
	if !basicShareResponse.Equal(decodedMsg) {
		t.Error("Decoded PromiseShareMessage not equal to original")
	}
	if basicShareResponse.MarshalSize() != decodedMsg.MarshalSize() {
		t.Error("MarshalSize of decoded and original differ: ",
			basicShareResponse.MarshalSize(), decodedMsg.MarshalSize())
	}

	// Tests MarshlTo and UnmarshalFrom
	bufWriter = new(bytes.Buffer)
	bytesWritter, errs = basicShareResponse.MarshalTo(bufWriter)
	if bytesWritter != basicShareResponse.MarshalSize() || errs != nil {
		t.Fatal("MarshalTo failed: ", bytesWritter, err)
	}

	decodedMsg = new(PromiseShareMessage).UnmarshalInit(suite)
	bufReader = bytes.NewReader(bufWriter.Bytes())
	bytesRead, errs2 = decodedMsg.UnmarshalFrom(bufReader)
	if bytesRead != decodedMsg.MarshalSize() || errs2 != nil {
		t.Fatal("UnmarshalFrom failed: ", bytesRead, errs2)
	}
	if basicShareResponse.MarshalSize() != decodedMsg.MarshalSize() {
		t.Error("MarshalSize of decoded and original differ: ",
			basicShareResponse.MarshalSize(), decodedMsg.MarshalSize())
	}
	if !basicShareResponse.Equal(decodedMsg) {
		t.Error("Msg read does not equal original")
	}
}




func PolicyMessageHelper(t *testing.T, policy *PolicyMessage) {
	// Send an RequestInsuranceMessage
	encodedMsg, err := policy.MarshalBinary()
	if err != nil {
		t.Fatal("Marshalling failed!", err)
	}
	policyMsg2 := new(PolicyMessage).UnmarshalInit(pt,r,numInsurers, suite)
	err = policyMsg2.UnmarshalBinary(encodedMsg)
	if err != nil {
		t.Fatal("Unmarshalling failed!", err)
	}

	if policy.Type != policyMsg2.Type {
		t.Error("Unexpected MessageType")
	}

	okay := false

	switch policyMsg2.Type {
		case CertifyPromise:
			msg1 := policy.getCPM()
			msg2 := policyMsg2.getCPM()
			okay = msg1.Equal(msg2)
		case PromiseResponse:
			msg1 := policy.getPRM()
			msg2 := policyMsg2.getPRM()
			okay = msg1.Equal(msg2)
		case PromiseToClient:
			msg1 := policy.getPTCM()
			msg2 := policyMsg2.getPTCM()
			okay  = msg1.Equal(msg2)
		case ShareRevealRequest:
			msg1 := policy.getSREQ()
			msg2 := policyMsg2.getSREQ()
			okay  = msg1.Equal(msg2)
		case ShareRevealResponse:
			msg1 := policy.getSRSP()
			msg2 := policyMsg2.getSRSP()
			okay  = msg1.Equal(msg2)

	}

	if !okay {
		t.Error("Message corroded after encoding/decoding.")
	}
}

// This method and its helper tests the methods of PolicyMessage. PolicyMessage
// is simply a wrapper around the other messages to help during sending messages.
// Hence, the functionality of PolicyMessage is tested here.
func TestPolicyMessage(t *testing.T) {

	PolicyMessageHelper(t, new(PolicyMessage).createCPMessage(basicCertifyMessage))
	PolicyMessageHelper(t, new(PolicyMessage).createPRMessage(basicResponseMessage))
	PolicyMessageHelper(t, new(PolicyMessage).createPTCMessage(basicPromise))
	PolicyMessageHelper(t, new(PolicyMessage).createSREQMessage(basicShareRequest))
	PolicyMessageHelper(t, new(PolicyMessage).createSRSPMessage(basicShareResponse))

}

// Tests all the string functions. Simply calls them to make sure they return.
func TestString(t *testing.T) {
	basicCertifyMessage.String()
	basicResponseMessage.String()
	basicShareRequest.String()
	basicShareResponse.String()
}
