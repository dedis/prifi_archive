package insure

import (
	"sync"
	"errors"
	"reflect"
	"time"
	"testing"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/config"
	"github.com/dedis/crypto/poly/promise"
	"github.com/dedis/crypto/random"

	"github.com/dedis/prifi/connMan"
	"github.com/dedis/prifi/coco/coconet"
)

// Note: These tests are divided into two main parts: unit tests and a functional
// test. The unit tests attempt to isolate the behavior of the functions. Hence, they often
// have helper functions that are written to send data over channels rather than useing
// methods defined in lifePolic.go. This is done so as to better isolate the cause of errors.
// The functional test makes sure that the entire system works as it should.

// NOTE: This code was build with gochans that can only receive messages one
// at a time and that block when waiting to receive a message. Changing the
// channel might break tests.

// NOTE: The same gochans are used throughout the tests. Make sure each test
// gets all the messages it puts. Otherwise, there may be problems.

var goDir = coconet.NewGoDirectory()

// Variables for the server to take out the policy.
var secretKeyT = produceKeyPairT()
var secretKeyT2 = produceKeyPairT()
var keyPairT   = produceKeyPairT()
var clientT   = produceKeyPairT()
var goConn     = produceChanConn(keyPairT)
var clientConn = produceChanConn(clientT)

// Alter this to easily scale the number of servers to test with. This
// represents the number of other servers waiting to approve policies.
var numServers = 10

var lpt = 5
var lpr = 7
var lpn = 10

var defaultTimeout = 5

// Variables for the servers to accept the policy
var serverKeys = produceKeys()
var secretKeys = produceKeys()
var insurerListT = produceInsuredList()
var connectionManagers = produceGoConnArray()
var setupOkay = setupConn()

func produceKeyPairT() *config.KeyPair {
	keyPair := new(config.KeyPair)
	keyPair.Gen(KEY_SUITE, random.Stream)
	return keyPair
}

func produceChanConn(k *config.KeyPair) *connMan.ChanConnManager {
	return new(connMan.ChanConnManager).Init(k.Public, goDir)
}

func produceKeys() []*config.KeyPair {
	newArray := make([]*config.KeyPair, numServers, numServers)
	for i := 0; i < numServers; i++ {
		newArray[i] = produceKeyPairT()
	}
	return newArray
}

func produceInsuredList() []abstract.Point {
	newArray := make([]abstract.Point, numServers, numServers)
	for i := 0; i < numServers; i++ {
		newArray[i] = serverKeys[i].Public
	}
	return newArray
}

func produceGoConnArray() []*connMan.ChanConnManager {
	newArray := make([]*connMan.ChanConnManager, numServers, numServers)
	for i := 0; i < numServers; i++ {
		newArray[i] = produceChanConn(serverKeys[i])
	}
	return newArray
}

func setupConn() bool {
	// Give server #1 and client #1 connections to everyone else.
	for i := 0; i < numServers; i++ {
		goConn.AddConn(insurerListT[i])
		clientConn.AddConn(insurerListT[i])
	}

	// Give server #1 and client #1 access to themselves and each other.
	goConn.AddConn(keyPairT.Public)
	goConn.AddConn(clientT.Public)

	clientConn.AddConn(keyPairT.Public)
	clientConn.AddConn(clientT.Public)

	// Give everyone else connections to server #1 and client #1
	for i := 0; i < numServers; i++ {
		connectionManagers[i].AddConn(keyPairT.Public)
		connectionManagers[i].AddConn(clientT.Public)
		
		// Give everyone access to everyone else
		for j := 0; j < numServers; j++ {
			connectionManagers[i].AddConn(insurerListT[j])
		}
	}

	return true
}

func produceBasicPolicy(key *config.KeyPair, conn connMan.ConnManager,
	timeout int)  *LifePolicyModule{
	return new(LifePolicyModule).Init(key, lpt,lpr,lpn, conn, timeout, nil) 
}

func produceNewServerPolicyWithPromise() (*LifePolicyModule,* promise.State) {
	policy := new(LifePolicyModule).Init(keyPairT, lpt,lpr,lpn, goConn, defaultTimeout, nil) 
	newPromise := promise.Promise{}
	newPromise.ConstructPromise(secretKeyT, policy.keyPair, policy.t,
		policy.r, insurerListT)
	state := new(promise.State).Init(newPromise)
	policy.promises[newPromise.Id()] = state
	return policy, state
}

// Tests that check whether a method panics can use this funcition
func deferTest(t *testing.T, message string) {
	if r := recover(); r == nil {
		t.Error(message)
	}
}

// Insures a LifePolicyModule can be properly initialized.
func TestLifePolicyModuleInit(t * testing.T) {
	policy := new(LifePolicyModule).Init(keyPairT, lpt,lpr,lpn, goConn, 10, nil)
	if policy.keyPair != keyPairT {
		t.Error("keypair not properly set")
	}
	if policy.serverId != keyPairT.Public.String() {
		t.Error("serverId not properly set")
	}
	if policy.t != lpt {
		t.Error("t not properly set")
	}
	if policy.r != lpr {
		t.Error("r not properly set")
	}
	if policy.n != lpn {
		t.Error("n not properly set")
	}
	if policy.n != lpn {
		t.Error("n not properly set")
	}
	if policy.cman != goConn {
		t.Error("ConnectionManager not properly set")
	}
	if policy.defaultTimeout != 10 {
		t.Error("Timeout not properly set")
	}
	if reflect.ValueOf(policy.verifyServerAlive).Pointer() != reflect.ValueOf(policy.verifyServerAliveDefault).Pointer() {
		t.Error("Server alive function not properly set")
	}
	if policy.promises == nil {
		t.Error("promises map not properly set")
	}
	if policy.serverPromises == nil {
		t.Error("serverPromises map not properly set")
	}
	
	// Verify that passing in a user defined verifyServerAlive works.
	temp := func(reason string, serverKey, clientKey abstract.Point, timeout int) error {
		return nil
	}
	policy = new(LifePolicyModule).Init(keyPairT, lpt,lpr,lpn, goConn, 10, temp)
	if reflect.ValueOf(policy.verifyServerAlive).Pointer() != reflect.ValueOf(temp).Pointer() {
		t.Error("Server alive function not properly set")
	}
}

// This is a helper method that is used to send ServerAliveResponseMessage's to an insurer
func sendServerAliveResponseBasice(t *testing.T, i int) {

	msg := new(PolicyMessage).UnmarshalInit(lpt,lpr, lpn,
				keyPairT.Suite)
	goConn.Get(serverKeys[i].Public, msg)
	if msg.Type != ServerAliveRequest {
		panic("Server should have sent a server alive request.")
	}

	// Send response off to the insurer
	goConn.Put(serverKeys[i].Public, new(PolicyMessage).createSARSPMessage())

	msg = new(PolicyMessage).UnmarshalInit(lpt,lpr, lpn,
				keyPairT.Suite)
	goConn.Get(serverKeys[i].Public, msg)
	if msg.Type != ServerAliveRequest {
		panic("Server should have sent a server alive request.")
	}

	// Send a request message just to bye time
	goConn.Put(serverKeys[i].Public, new(PolicyMessage).createSAREQMessage())

	// Clear the message the server will send back.
	msg = new(PolicyMessage).UnmarshalInit(lpt,lpr, lpn,
				keyPairT.Suite)
	goConn.Get(serverKeys[i].Public, msg)
	if msg.Type != ServerAliveResponse {
		panic("Server should have sent a server alive request.")
	}
}

// Verifies that verifyServerAliveDefault can properly recognize when the server is
// alive.
func TestLifePolicyModuleVerifyServerAliveDefault(t *testing.T) {

	i := 1
	policy := produceBasicPolicy(serverKeys[i], connectionManagers[i], 5)

	go sendServerAliveResponseBasice(t, i)

	err := policy.verifyServerAliveDefault("test", keyPairT.Public, clientT.Public, 1)
	if err != nil {
		t.Error("Server should have been reported alive.")
	}

	// Next, test the timeout. Since goChans block immediately, I will do
	// this by having a timeout of 0.
	err = policy.verifyServerAliveDefault("test", keyPairT.Public, clientT.Public, 0)
	if err == nil {
		t.Error("Server should have been reported dead.")
	}
}

// Insures that SelectBasicInsurer can properly select a list of insurers.
func TestSelectBasicInsurers(t * testing.T) {
	
	result := selectInsurersBasic(insurerListT, numServers)
	if len(result) != numServers {
		t.Fatal("List returned is the wrong size.")
	}
	for i := 0; i < numServers; i++ {
		if !result[i].Equal(insurerListT[i]) {
			t.Fatal("List returned contains unexpected elements.")
		}
	}

	result = selectInsurersBasic(insurerListT, numServers-1)
	if len(result) != numServers-1 {
		t.Fatal("List returned is the wrong size.")
	}
	for i := 0; i < numServers-1; i++ {
		if !result[i].Equal(insurerListT[i]) {
			t.Fatal("List returned contains unexpected elements.")
		}
	}
}

// Verifies the timeout function works.
func TestHandleTimeout(t * testing.T) {
	timeoutChan  := make(chan bool, 1)
	go handleTimeout(1, timeoutChan)
	time.Sleep(1 * time.Second)
	if <-timeoutChan != true {
		t.Error("Expected timout to send timeout after time expired.")
	}
}



// This is a helper method to be run by gochan's simulating insurers.
// The server listens for a CertifyPromiseMessage, sends a response, and then exits.
func insurersBasic(t *testing.T, k, returnKey *config.KeyPair,  cm connMan.ConnManager) {

	for true {
		msg := new(PolicyMessage).UnmarshalInit(lpt,lpr,lpn, k.Suite)
		cm.Get(returnKey.Public, msg)

		// If a CertifyPromiseMessage, exit
		if msg.Type == CertifyPromise {
			certMsg := msg.getCPM()
			response, _ := certMsg.Promise.ProduceResponse(certMsg.ShareIndex, k)
			replyMsg := new(PromiseResponseMessage).createMessage(certMsg.ShareIndex, certMsg.Promise, response)
			cm.Put(returnKey.Public, new(PolicyMessage).createPRMessage(replyMsg))
			return
		}
	}
}

// Verifies that certifyPromise can properly communicate with other servers.
func TestLifePolicyModuleCertifyPromise(t *testing.T) {

	// Create a new policy module and manually create a secret.
	policy, state := produceNewServerPolicyWithPromise()

	// Start up the other insurers.
	for i := 0; i < numServers; i++ {
		go insurersBasic(t, serverKeys[i], keyPairT, connectionManagers[i])
	}
	
	err := policy.certifyPromise(state)
	if err != nil {
		t.Error("The promise failed to be certified: ", err)
	}
	finalState := policy.promises[secretKeyT.Public.String()]
	if err := finalState.PromiseCertified(); err != nil {
		t.Error("The promise should now be certified:  ", err)
	}
	
	// Now that the promise is certified, it should simply return without
	// contacting the insurers. Since the insurers all should have exitted
	// by now, this will hang if it attempts to contact the network.
	err = policy.certifyPromise(finalState)
	if err != nil {
		t.Error("The promise failed to be certified: ", err)
	}
}

// Verifies that the public CertifyPromise returns errors properly. Since it is just
// a simple wrapper over the private certifyPromise, the error cases unique to the
// public method are checked here. The functional tests ensure it calls the
// private method properly.
func TestLifePolicyModuleCertifyPromisePublic(t *testing.T) {
	// Verify that it returns an error if asked to certify a promise that
	// doesn't exist.
	policy := produceBasicPolicy(keyPairT, goConn, 5)
	err := policy.CertifyPromise(keyPairT.Public, secretKeyT.Public)
	if err == nil {
		panic("The lookup should have failed.")
	}
}

// Verifies that revealShare can properly communicate with other servers.
func TestLifePolicyModuleRevealShare(t *testing.T) {

	// Create the policy for the client
	clientPolicy := produceBasicPolicy(clientT, clientConn, 1)

	// Create a policy for the first insurer. Give it a promise from the
	// promiser server.
	insurerPolicy := produceBasicPolicy(serverKeys[0], connectionManagers[0], 1)
	newPromise := promise.Promise{}
	newPromise.ConstructPromise(secretKeyT, keyPairT, lpt, lpr, insurerListT)
	insurerPolicy.addServerPromise(newPromise)
	state := insurerPolicy.serverPromises[newPromise.PromiserId()][newPromise.Id()]

	// Start up the other insurers.
	for i := 1; i < numServers; i++ {
		go insurersBasic(t, serverKeys[i], serverKeys[0], connectionManagers[i])
	}
	
	// Send the share off to the client. The first time should require
	// the promise to be certified
	err := insurerPolicy.revealShare(0, state, clientT.Public)
	if err != nil {
		t.Error("The share should have been sent: ", err)
	}
	
	// Clearing out the gochan. The insurer will first send a CertifyPromise
	// to itself and then send a PromiseResponse. However, the promise will already
	// be certified and a second iteration within certifyPromise will not be
	// needed. Hence, the channel needs to be cleaned for future tests.
	msg := new(PolicyMessage).UnmarshalInit(lpt,lpr,lpn, serverKeys[0].Suite)
	insurerPolicy.cman.Get(serverKeys[0].Public, msg)
	if msg.Type != PromiseResponse {
		t.Fatal("Unexpected message received")
	}
	
	// Check that the first message was sent.
	msg = new(PolicyMessage).UnmarshalInit(lpt,lpr,lpn, clientT.Suite)
	clientPolicy.cman.Get(serverKeys[0].Public, msg)
	if msg.Type != ShareRevealResponse {
		t.Fatal("ShareRevealResponse Message expected")
	}
	
	// Send the share off a second time. The promise should be sent immediately
	// since the promise is now certified. Since the other insurers have
	// already quit, this will hang if it tries to contact the network
	err = insurerPolicy.revealShare(0, state, clientT.Public)
	if err != nil {
		t.Error("The share should have been sent: ", err)
	}
	
	// Check that the second message was sent.
	msg = new(PolicyMessage).UnmarshalInit(lpt,lpr,lpn, clientT.Suite)
	clientPolicy.cman.Get(serverKeys[0].Public, msg)
	if msg.Type != ShareRevealResponse {
		t.Fatal("ShareRevealResponse Message expected")
	}
}

// Verifies that a sever can properly take out a policy.
func TestLifePolicyModuleTakeOutPolicy(t *testing.T) {

	// Start up the other insurers.
	for i := 0; i < numServers; i++ {
		go insurersBasic(t, serverKeys[i], keyPairT, connectionManagers[i])
	}
	
	policy:= produceBasicPolicy(keyPairT, goConn, 3)
	err := policy.TakeOutPolicy(secretKeyT, insurerListT, nil)
	if err != nil {
		t.Error("The promise failed to be certified: ", err)
	}
	finalState := policy.promises[secretKeyT.Public.String()]
	if err := finalState.PromiseCertified(); err != nil {
		t.Error("The promise should now be certified:  ", err)
	}

	// Verify that if a promise is already certified that it is not
	// overwritten.
	err = policy.TakeOutPolicy(secretKeyT, insurerListT, nil)
	if err != nil {
		t.Error("No error should have been raised: ", err)
	}
	if finalState != policy.promises[secretKeyT.Public.String()] {
		t.Error("No new state should have been created.")
	}
	if err := finalState.PromiseCertified(); err != nil {
		t.Error("The promise should now be certified:  ", err)
	}
	

	// Verify that a promise that is not yet certified is not overwritten.
	// The code should attempt to have the promise verified.
	policy, state := produceNewServerPolicyWithPromise()

	// Start up the other insurers.
	for i := 0; i < numServers; i++ {
		go insurersBasic(t, serverKeys[i], keyPairT, connectionManagers[i])
	}
	
	err = policy.TakeOutPolicy(secretKeyT, insurerListT, nil)
	if err != nil {
		t.Error("The promise failed to be certified: ", err)
	}
	if state != policy.promises[secretKeyT.Public.String()] {
		t.Error("No new state should have been created.")
	}
	if err := state.PromiseCertified(); err != nil {
		t.Error("The promise should now be certified:  ", err)
	}
	
	
	// Verify that the policy is properly created when a good function is
	// provided.
	called := false
	
	goodFunc := func(serverList []abstract.Point, n int) []abstract.Point {
		called = true
		return serverList
	}
	// Start up the other insurers.
	for i := 0; i < numServers; i++ {
		go insurersBasic(t, serverKeys[i], keyPairT, connectionManagers[i])
	}
	
	policy = produceBasicPolicy(keyPairT, goConn, 3)
	err    = policy.TakeOutPolicy(secretKeyT, insurerListT, goodFunc)
	if !called {
		t.Error("The method should have used the provided method")
	}
	
	
	// Error Handling
	badFunc := func(serverList []abstract.Point, n int) []abstract.Point {
		return serverList[:n-1]
	}
	
	// Verify that TakeOutPolicy panics if the insurerList is not the right size.
	test := func() {
		defer deferTest(t, "TakeOutPolicy should have paniced")
		policy := produceBasicPolicy(keyPairT, goConn, 3)
		policy.TakeOutPolicy(secretKeyT, insurerListT, badFunc)
	}
	test()
}


// This is a helper method to be run by gochan's simulating insurers.
// The server listens for a CertifyPromiseMessage, sends a response, and then exits.
func receivePromiseBasic(t *testing.T, k *config.KeyPair, cm connMan.ConnManager, promise promise.Promise) {

	for true {
		msg := new(PolicyMessage).UnmarshalInit(lpt,lpr,lpn, k.Suite)
		cm.Get(keyPairT.Public, msg)
		
		if msg.Type == PromiseToClient {
			if !promise.Equal(msg.getPTCM()) {
				panic("Promise sent is not what was expected.")
			}
			return
		}
	}
}

// Verifies that a sever can properly take out a policy.
func TestLifePolicyModuleSendPromiseToClient(t *testing.T) {

	// Start up the other insurer.
	policy, state := produceNewServerPolicyWithPromise()

	i := 0
	go receivePromiseBasic(t, serverKeys[i], connectionManagers[i], state.Promise)
	
	// Send the promise off
	err := policy.SendPromiseToClient(serverKeys[i].Public, secretKeyT.Public)
	if err != nil {
		t.Error("The promise should have been sent.")
	}

	err = policy.SendPromiseToClient(serverKeys[i].Public, keyPairT.Public)
	if err == nil {
		t.Error("The promise does not exist. An eror should have been ")
	}
}

// Verifies that a promise can be properly added to the serverPromise hash
func TestLifePolicyModuleAddServerPromise(t *testing.T) {
	i := 0
	policy := produceBasicPolicy(keyPairT, goConn, 3) 
	newPromise := promise.Promise{}
	newPromise.ConstructPromise(secretKeyT,serverKeys[i], lpt, lpr, insurerListT)
	
	// When adding the first promise for a server, make sure a hash for that
	// server is created and the promise is added to that hash.
	policy.addServerPromise(newPromise)
	serverHash, ok := policy.serverPromises[newPromise.PromiserId()]
	
	if !ok {
		t.Fatal("New server failed to be added to severPromises hash.")
	}
	
	promiseState, ok := policy.serverPromises[newPromise.PromiserId()][newPromise.Id()]
	if !ok {
		t.Fatal("Promise failed to be added to the hash.")
	}
	
	if !promiseState.Promise.Equal(&newPromise) {
		t.Error("Stored Promise does not equal promise entered.")
	}
	
	
	// Adding the same promise should not result in any changes.
	policy.addServerPromise(newPromise)
	
	temp := policy.serverPromises[newPromise.PromiserId()]
	if reflect.ValueOf(serverHash).Pointer() != reflect.ValueOf(temp).Pointer() {
		t.Fatal("Server hash should not have changed.")
	}
	if promiseState != policy.serverPromises[newPromise.PromiserId()][newPromise.Id()] {
		t.Fatal("Promise state should not have changed.")
	}
	
	// Adding a new promise to an existing server should only add the new key.
	newPromise = promise.Promise{}
	newPromise.ConstructPromise(secretKeyT2,serverKeys[i], lpt, lpr, insurerListT)
	
	policy.addServerPromise(newPromise)
	
	temp = policy.serverPromises[newPromise.PromiserId()]
	if reflect.ValueOf(serverHash).Pointer() != reflect.ValueOf(temp).Pointer() {
		t.Fatal("Server hash should not have changed.")
	}

	promiseState, ok = policy.serverPromises[newPromise.PromiserId()][newPromise.Id()]
	if !ok {
		t.Fatal("Promise failed to be added to the hash.")
	}
	
	if !promiseState.Promise.Equal(&newPromise) {
		t.Error("Stored Promise does not equal promise entered.")
	}
}

// This is a helper method that is used to send CertifyPromiseMessages to an
// insurer
func sendCertifyMessagesBasic(t *testing.T, insurerI int, promiserCm, clientCm connMan.ConnManager) {

	newPromise := promise.Promise{}
	newPromise.ConstructPromise(secretKeyT, keyPairT, lpt,lpr, insurerListT)
	requestMsg := new(CertifyPromiseMessage).createMessage(insurerI, newPromise)
	policyMsg  := new(PolicyMessage).createCPMessage(requestMsg)
	
	// As a client, first request a promise that has not been added yet.
	clientCm.Put(serverKeys[insurerI].Public, policyMsg)
	
	// As a promiser, request a promise that has not been added yet.
	promiserCm.Put(serverKeys[insurerI].Public, policyMsg)
	
	// As a client, request the promise added.
	clientCm.Put(serverKeys[insurerI].Public, policyMsg)
	
	
	// Verify the server sent a response to the promiser.
	msg := new(PolicyMessage).UnmarshalInit(lpt,lpr,lpn, keyPairT.Suite)
	promiserCm.Get(serverKeys[insurerI].Public, msg)
	if msg.Type != PromiseResponse {
		panic("A valid certifyPromise message should have been sent.")
	}
	
	// Verify that the second client request produced a response.
	msg = new(PolicyMessage).UnmarshalInit(lpt,lpr,lpn, keyPairT.Suite)
	clientCm.Get(serverKeys[insurerI].Public, msg)
	if msg.Type != PromiseResponse {
		panic("A valid certifyPromise message should have been sent.")
	}
}

// This is a helper method to listen for RevealShareRequests and to send a response
func sendRevealShareResponses(t *testing.T, i int, state *promise.State,  cm connMan.ConnManager) {

	for true {
		msg := new(PolicyMessage).UnmarshalInit(lpt,lpr,lpn, serverKeys[i].Suite)
		cm.Get(keyPairT.Public, msg)

		if msg.Type == ShareRevealRequest {
			share := state.RevealShare(i, serverKeys[i])
			responseMsg := new(PromiseShareMessage).createResponseMessage(
				i, state.Promise, share)
			cm.Put(keyPairT.Public, new(PolicyMessage).createSRSPMessage(responseMsg))
			return
		}
	}
}

// Verifies that ReconstructSecret can properly reconstruct a promised secret
// Although this would be done by the client and not the server who took out the
// policy, I use the server here for simplicity.
func TestLifePolicyModuleReconstructSecret(t *testing.T) {

	// Create a new policy module and manually create a secret.
	policy, state := produceNewServerPolicyWithPromise()

	// First certify the promise as an uncertified promise can't reveal
	// shares
	for i := 0; i < numServers; i++ {
		go insurersBasic(t, serverKeys[i], keyPairT, connectionManagers[i])
	}
	err := policy.certifyPromise(state)
	if err != nil {
		t.Error("The promise failed to be certified: ", err)
	}
	finalState := policy.promises[secretKeyT.Public.String()]
	if err := finalState.PromiseCertified(); err != nil {
		t.Error("The promise should now be certified:  ", err)
	}
	
	// Error handling
	// First, verify that a promise not added to the serverPromises hash produces
	// an error. The promise is currently in the promises hash, so this should
	// fail.
	key, err := policy.ReconstructSecret("test", keyPairT.Public, secretKeyT.Public)	
	if err == nil  {
		t.Error("Reconstruction should have failed.")
	}
	if key != nil {
		t.Error("Key should be nil.")
	}

	// Remove the promise from the promises hash and move to the serverPromises
	// hash to simulate another a client trying to reconstruct a promise.
	policy.promises[secretKeyT.Public.String()] = nil
	policy.addServerPromise(state.Promise)
	policy.serverPromises[state.Promise.PromiserId()][state.Promise.Id()] = finalState

	
	// Start up the other insurers for revealing the share.
	for i := 0; i < numServers; i++ {
		go sendRevealShareResponses(t, i, finalState, connectionManagers[i])
	}
	
	key, err = policy.ReconstructSecret("test", keyPairT.Public, secretKeyT.Public)	
	if err != nil  {
		t.Error("Unexpected error", err)
	}
	if !key.Equal(secretKeyT.Secret) {
		t.Error("Failed to construct secret")
	}
}

// Verifies that an insurer can handle CertifyPromiseMessages from promisers and clients
func TestLifePolicyModuleHandleCertifyPromiseMessage(t *testing.T) {

	clientI  := 1
	insurerI := 2 
	policy := produceBasicPolicy(serverKeys[insurerI], connectionManagers[insurerI], 3)
	go sendCertifyMessagesBasic(t, insurerI, goConn, connectionManagers[clientI])

	// The first message to be received will be from a client. This will
	// be before the promise has actually been sen by the promiser.
	msg := new(PolicyMessage).UnmarshalInit(lpt,lpr,lpn, keyPairT.Suite)
	policy.cman.Get(serverKeys[clientI].Public, msg)
	if msg.Type != CertifyPromise {
		t.Error("CertifyPromise Message expected")
	}
	certMsg := msg.getCPM()
	err := policy.handleCertifyPromiseMessage(serverKeys[clientI].Public, certMsg)

	if err == nil {
		t.Error("Promise doesn't exist and an error should have been produced.")
	}
	if _, assigned := policy.serverPromises[certMsg.Promise.PromiserId()]; assigned{
		t.Error("A client should not be able to add promises for others.")
	}
	

	// The second message will be from the promiser. The promiser is adding
	// the promise to the insurer.
	msg = new(PolicyMessage).UnmarshalInit(lpt,lpr,lpn, keyPairT.Suite)
	policy.cman.Get(keyPairT.Public, msg)
	if msg.Type != CertifyPromise {
		t.Fatal("CertifyPromise Message expected")
	}
	certMsg = msg.getCPM()
	err = policy.handleCertifyPromiseMessage(keyPairT.Public, certMsg)

	if err != nil {
		t.Error("Message should have been sent successfully.", err)
	}

	_, assigned := policy.serverPromises[certMsg.Promise.PromiserId()][certMsg.Promise.Id()]
	if !assigned{
		t.Error("Message should have been assigned.")
	}

	// The final message will be from a client attempting to receive a
	// response after the promise has been added.
	msg = new(PolicyMessage).UnmarshalInit(lpt,lpr,lpn, keyPairT.Suite)
	policy.cman.Get(serverKeys[clientI].Public, msg)
	if msg.Type != CertifyPromise {
		t.Fatal("CertifyPromise Message expected")
	}
	certMsg = msg.getCPM()
	err = policy.handleCertifyPromiseMessage(serverKeys[clientI].Public, certMsg)

	if err != nil {
		t.Error("Response should have been sent successfully.", err)
	}
}


// This is a helper method that is used to send PromiseResponseMessage's to a server
func sendPromiseResponseMessagesBasic(t *testing.T, i int, promise1, promise2 promise.Promise, cm connMan.ConnManager) {

	// First, send the server a response to a promise it created.
	response, _ := promise1.ProduceResponse(i, serverKeys[i])
	responseMsg := new(PromiseResponseMessage).createMessage(i, promise1, response)
	policyMsg  := new(PolicyMessage).createPRMessage(responseMsg)
	cm.Put(keyPairT.Public, policyMsg)


	// Next, send the server two responses for a promise another server created.
	response, _ = promise2.ProduceResponse(i, serverKeys[i])
	responseMsg = new(PromiseResponseMessage).createMessage(i, promise2, response)
	policyMsg   = new(PolicyMessage).createPRMessage(responseMsg)
	cm.Put(keyPairT.Public, policyMsg)
	cm.Put(keyPairT.Public, policyMsg)	
}

// Verifies that a server can handle PromiseResponseMessage from insurers
func TestLifePolicyModuleHandlePromiseResponseMessage(t *testing.T) {

	i := 1
	policy, state := produceNewServerPolicyWithPromise()

	newPromise := promise.Promise{}
	newPromise.ConstructPromise(secretKeyT2, serverKeys[i], lpt, lpr, insurerListT)

	go sendPromiseResponseMessagesBasic(t, i, state.Promise, newPromise, connectionManagers[i])

	// Test that a response for one's own promise can be received.
	msg := new(PolicyMessage).UnmarshalInit(lpt,lpr,lpn, keyPairT.Suite)
	policy.cman.Get(serverKeys[i].Public, msg)
	responseMsg := msg.getPRM()
	err := policy.handlePromiseResponseMessage(responseMsg)
	if err != nil {
		t.Error("Response should have been added to Promise", err)
	}

	// Test that a response for an unknown promise produces an error.
	msg = new(PolicyMessage).UnmarshalInit(lpt,lpr,lpn, keyPairT.Suite)
	policy.cman.Get(serverKeys[i].Public, msg)
	responseMsg = msg.getPRM()
	err = policy.handlePromiseResponseMessage(responseMsg)
	if err == nil {
		t.Error("An error should have been produced.")
	}

	// Test that adding the unknown promise to the serverPromises hash makes
	// it work.
	policy.addServerPromise(newPromise)
	msg = new(PolicyMessage).UnmarshalInit(lpt,lpr,lpn, keyPairT.Suite)
	policy.cman.Get(serverKeys[i].Public, msg)
	responseMsg = msg.getPRM()
	err = policy.handlePromiseResponseMessage(responseMsg)
	if err != nil {
		t.Error("Response should have been added to Promise", err)
	}
}

// This is a helper method that is used to send ServerAliveRequestMessage's to a server
func sendServerAliveRequestBasics(t *testing.T, i int) {

	goConn.Put(serverKeys[i].Public, new(PolicyMessage).createSAREQMessage())

	msg  := new(PolicyMessage).UnmarshalInit(lpt,lpr,lpn, keyPairT.Suite)
	goConn.Get(serverKeys[i].Public, msg)
	if msg.Type != ServerAliveResponse {
		panic("The Message should have been a ServerAliveResponse.")
	}
}

// Verifies that verifyServerAliveDefault can properly recognize when the server is
// alive.
func TestLifePolicyModuleHandleServerAliveRequestMessage(t *testing.T) {

	i := 1
	policy := produceBasicPolicy(serverKeys[i], connectionManagers[i], 5)

	go sendServerAliveRequestBasics(t, i)
	
	msg  := new(PolicyMessage).UnmarshalInit(lpt,lpr,lpn, keyPairT.Suite)
	policy.cman.Get(keyPairT.Public, msg)
	if msg.Type != ServerAliveRequest {
		panic("The Message should have been a ServerAliveRequest.")
	}
	err := policy.handleServerAliveRequestMessage(keyPairT.Public)
	if err != nil {
		panic("The request message should have been handled properly.")
	}
}

// This is a helper method that is used to send RevealShareRequestMessage's to a server
func sendRevealShareRequestMessageBasic(t *testing.T, i int, reason string, state1, state2 *promise.State) {

	// First, send the insurer a promise it does not have.
	requestMsg := new(PromiseShareMessage).createRequestMessage(i, reason, state2.Promise)
	policyMsg  := new(PolicyMessage).createSREQMessage(requestMsg)
	clientConn.Put(serverKeys[i].Public, policyMsg)

	// Next, send the insurer two requests with a promise it has.
	requestMsg = new(PromiseShareMessage).createRequestMessage(i, reason, state1.Promise)
	policyMsg  = new(PolicyMessage).createSREQMessage(requestMsg)
	clientConn.Put(serverKeys[i].Public, policyMsg)
	clientConn.Put(serverKeys[i].Public, policyMsg)

	// Reverify that the insurer sent a response.
	msg  := new(PolicyMessage).UnmarshalInit(lpt,lpr,lpn, clientT.Suite)
	clientConn.Get(serverKeys[i].Public, msg)
	if msg.Type != ShareRevealResponse {
		panic("Expected a ShareRevealResponse")
	}
}

// Verifies that a server can handle RevealShareRequestMessage's from clients
func TestLifePolicyModuleHandleRevealShareRequestMessage(t *testing.T) {

	// Index of the insurer to use for testing.
	i := 0

	// Create a policy for the first insurer. Give it a promise from the
	// promiser server.
	policy := new(LifePolicyModule).Init(serverKeys[i], lpt,lpr,lpn, connectionManagers[i], defaultTimeout, nil)
	newPromise := promise.Promise{}
	newPromise.ConstructPromise(secretKeyT, keyPairT, lpt, lpr, insurerListT)
	policy.addServerPromise(newPromise)
	state := policy.serverPromises[newPromise.PromiserId()][newPromise.Id()]

	newPromise2 := promise.Promise{}
	newPromise2.ConstructPromise(secretKeyT2, serverKeys[i+1], lpt, lpr, insurerListT)
	state2 := new(promise.State).Init(newPromise2)

	for j := 1; j < numServers; j++ {
		go insurersBasic(t, serverKeys[j], serverKeys[i], connectionManagers[j])
	}
	// First, get the first promise certified so that the share can be revealed
	err := policy.certifyPromise(state)
	if err != nil {
		t.Fatal("Promise should have been certified")
	}
	state = policy.serverPromises[newPromise.PromiserId()][newPromise.Id()]

	// The insure sent a certify message to itself. Make sure to handle it.
	msg  := new(PolicyMessage).UnmarshalInit(lpt,lpr,lpn, serverKeys[i].Suite)
	policy.cman.Get(serverKeys[i].Public, msg)
	policy.handlePolicyMessage(serverKeys[i].Public, msg)

	reasonTest := "test"
	go sendRevealShareRequestMessageBasic(t, i, reasonTest, state, state2)

	// Test that a response for an unknown promise produces an error.
	msg = new(PolicyMessage).UnmarshalInit(lpt,lpr,lpn, clientT.Suite)
	policy.cman.Get(clientT.Public, msg)
	requestMsg := msg.getSREQ()
	err = policy.handleRevealShareRequestMessage(clientT.Public, requestMsg)
	if err == nil {
		t.Error("The promise specified shouldn't exist in the policy", err)
	}
	
	// Test with the promise alive by default.
	policy.verifyServerAlive = func (reason string,
		serverKey, clientKey abstract.Point, timeout int) error {
		if reason != reasonTest {
			t.Error("Reason not as expected")
		}
		if !keyPairT.Public.Equal(serverKey) {
			t.Error("serverKey not as expected")
		}
		if !clientT.Public.Equal(clientKey) {
			t.Error("clientKey not as expected")
		}
		if timeout != policy.defaultTimeout {
			t.Error("timeout not as expected")
		}
		return nil
	}

	// Test that an error is returned when the server is reported down.
	msg = new(PolicyMessage).UnmarshalInit(lpt,lpr,lpn, clientT.Suite)
	policy.cman.Get(clientT.Public, msg)
	requestMsg = msg.getSREQ()
	err = policy.handleRevealShareRequestMessage(clientT.Public, requestMsg)
	if err == nil {
		t.Error("Server is alive. No share should be revealed.", err)
	}

	// Test with the promise down by default.
	policy.verifyServerAlive = func(reason string,
		serverKey abstract.Point, clientKey abstract.Point, timeout int) error {
		if reason != reasonTest {
			t.Error("Reason not as expected")
		}
		if !keyPairT.Public.Equal(serverKey) {
			t.Error("serverKey not as expected")
		}
		if !clientT.Public.Equal(clientKey) {
			t.Error("clientKey not as expected")
		}
		if timeout != policy.defaultTimeout {
			t.Error("timeout not as expected")
		}
		return errors.New("Server is down")
	}

	// Test that the share is successfully revealed when the server is down.
	msg = new(PolicyMessage).UnmarshalInit(lpt,lpr,lpn, clientT.Suite)
	policy.cman.Get(clientT.Public, msg)
	requestMsg = msg.getSREQ()
	err = policy.handleRevealShareRequestMessage(clientT.Public, requestMsg)
	if err != nil {
		t.Error("Server is dead. Share should be revealed.", err)
	}
}


// This is a helper method that is used to send RevealShareResponseMessage's to a server
func sendRevealShareResponseMessageBasic(t *testing.T, i int, state1, state2 *promise.State, cm connMan.ConnManager) {

	// First, send the promise a response to a promise it has.
	response := state1.RevealShare(i, serverKeys[i])
	responseMsg := new(PromiseShareMessage).createResponseMessage(i,
		state1.Promise, response)
	policyMsg  := new(PolicyMessage).createSRSPMessage(responseMsg)
	cm.Put(clientT.Public, policyMsg)

	// Next, send a bad share
	responseMsg = new(PromiseShareMessage).createResponseMessage(i,
		state1.Promise, clientT.Suite.Secret())
	policyMsg  = new(PolicyMessage).createSRSPMessage(responseMsg)
	cm.Put(clientT.Public, policyMsg)

	// Next, send the client a promise it does not have.
	responseMsg = new(PromiseShareMessage).createResponseMessage(i,
		state2.Promise, response)
	policyMsg  = new(PolicyMessage).createSRSPMessage(responseMsg)
	cm.Put(clientT.Public, policyMsg)
}

// Verifies that a server can handle RevealShareResponseMessage's from insurers
func TestLifePolicyModulehandleRevealShareResponseMessage(t *testing.T) {

	// Index of the insurer to use for testing.
	i := 1

	// Create a policy for the first client. Give it a promise from the
	// promiser server.
	policy := produceBasicPolicy(clientT, clientConn, 3)
	newPromise := promise.Promise{}
	newPromise.ConstructPromise(secretKeyT, keyPairT, lpt, lpr, insurerListT)
	policy.addServerPromise(newPromise)
	state := policy.serverPromises[newPromise.PromiserId()][newPromise.Id()]

	newPromise2 := promise.Promise{}
	newPromise2.ConstructPromise(secretKeyT2, serverKeys[i], lpt, lpr, insurerListT)
	state2 := new(promise.State).Init(newPromise2)

	for j := 0; j < numServers; j++ {
		go insurersBasic(t, serverKeys[j], clientT, connectionManagers[j])
	}
	// First, get the first promise certified so that the share can be revealed
	err := policy.certifyPromise(state)
	if err != nil {
		t.Fatal("Promise should have been certified")
	}

	go sendRevealShareResponseMessageBasic(t, i, state, state2, connectionManagers[i])

	// Test that a valid share can be received
	msg := new(PolicyMessage).UnmarshalInit(lpt,lpr,lpn, clientT.Suite)
	policy.cman.Get(serverKeys[i].Public, msg)
	responseMsg := msg.getSRSP()
	err = policy.handleRevealShareResponseMessage(responseMsg)
	if err != nil {
		t.Error("Share should have been added to Promise", err)
	}

	// Test that an invalid share produces an error
	msg  = new(PolicyMessage).UnmarshalInit(lpt,lpr,lpn, clientT.Suite)
	policy.cman.Get(serverKeys[i].Public, msg)
	responseMsg = msg.getSRSP()
	err = policy.handleRevealShareResponseMessage(responseMsg)
	if err == nil {
		t.Error("The share is invalid", err)
	}

	// Test that a response for an unknown promise produces an error.
	msg  = new(PolicyMessage).UnmarshalInit(lpt,lpr,lpn, clientT.Suite)
	policy.cman.Get(serverKeys[i].Public, msg)
	responseMsg = msg.getSRSP()
	err = policy.handleRevealShareResponseMessage(responseMsg)
	if err == nil {
		t.Error("The promise specified shouldn't exist in the policy", err)
	}
}
 
// This is a helper method that is used to send PromiseToClientMessage's to a server
func sendPromiseToClientMessagesBasic(t *testing.T, i int, serverCm, clientCm connMan.ConnManager) {

	// First, send off a valid promise this server has created.
	newPromise := new(promise.Promise)
	newPromise.ConstructPromise(secretKeyT2, serverKeys[i], lpt, lpr, insurerListT)
	policyMsg  := new(PolicyMessage).createPTCMessage(newPromise)
	serverCm.Put(keyPairT.Public, policyMsg)

	// Then, have the client send itself its own promise.
	newPromise = new(promise.Promise)
	newPromise.ConstructPromise(secretKeyT2, keyPairT, lpt, lpr, insurerListT)
	policyMsg  = new(PolicyMessage).createPTCMessage(newPromise)
	clientCm.Put(keyPairT.Public, policyMsg)
	
	// Lastly, have a server try to send a promise it doesn't own.
	newPromise = new(promise.Promise)
	newPromise.ConstructPromise(secretKeyT2, keyPairT, lpt, lpr, insurerListT)
	policyMsg  = new(PolicyMessage).createPTCMessage(newPromise)
	serverCm.Put(keyPairT.Public, policyMsg)
}

// Verifies that a client can handle PromiseToClientMessages from servers
func TestLifePolicyModuleHandlePromiseToClientMessage(t *testing.T) {

	i := 1
	policy := produceBasicPolicy(keyPairT, goConn, 3)
	go sendPromiseToClientMessagesBasic(t, i, connectionManagers[i], goConn)

	// Verify that a client can properly receive a promise from a server
	msg := new(PolicyMessage).UnmarshalInit(lpt,lpr,lpn, keyPairT.Suite)
	policy.cman.Get(serverKeys[i].Public, msg)
	prom := msg.getPTCM()
	err := policy.handlePromiseToClientMessage(serverKeys[i].Public, prom)
	if err != nil {
		t.Error("Method should have succeeded. Error: ", err)
	}
	if policy.serverPromises[prom.PromiserId()][prom.Id()] == nil {
		t.Error("Promise should have been added to hash.")
	}

	// Verify that a client ignores promises from itself.
	msg = new(PolicyMessage).UnmarshalInit(lpt,lpr,lpn, keyPairT.Suite)
	policy.cman.Get(keyPairT.Public, msg)
	prom = msg.getPTCM()
	err = policy.handlePromiseToClientMessage(keyPairT.Public, prom)
	if err == nil {
		t.Error("Method should have failed.")
	}

	// Verifies that a client ignores a promise sent by a server that didn't
	// create the promise.
	msg = new(PolicyMessage).UnmarshalInit(lpt,lpr,lpn, keyPairT.Suite)
	policy.cman.Get(serverKeys[i].Public, msg)
	prom = msg.getPTCM()
	err = policy.handlePromiseToClientMessage(serverKeys[i].Public, prom)
	if err == nil {
		t.Error("Method should have failed.")
	}
}

/****************************** FUNCTIONAL TESTS ******************************/

/* This functional test is designed to test the code under conditions similar to
 * production. It uses gochanns to simulate the network. It has three main types
 * of channels:
 *
 *   - Server channel = this is the channel of the main server who creates the
 *                      promise. This is the TestLifePolicyFunctional method.
 *
 *   - Insurer channel = these are a set of channels for representing insurer
 *                       logic. There is one channel per insurer.
 *
 *   - Client channel = this channel simulates requests by clients.
 *
 * The test undergoes several main phases that may involve all the channels or just
 * a subset:
 *
 *   Phase 1: Create a new Promise
 *
 *     The server creates a new promise and sends it to the insurers to certify
 *
 *   Phase 2: Send the Promise to a Client
 *
 *      The server sends the Promise to the client. The client receives it and
 *      then contacts the insurers to certify the promise.
 *
 *   Phase 3: Certify insurer promises
 *
 *      This is in preparation for the final stage. A promised secret can be
 *      revealed only if the promise is certified. Go ahead and certify all
 *      the insurers' promises.
 * 
 *      While this would be done automatically if a server received a
 *      RevealShareRequest, it is much easier due to the limitations of blocking
 *      channels to do this independently.
 *
 *   Phase 4: Reconstruct Secret
 *
 *      The client contacts the insurers to reconstruct the promised secret.
 *      The insurers contact the server, verify it is dead, and then reveal their
 *      shares.
 */


// This is a helper method that simulates the insurer channel
func insurersFunctional(t *testing.T, k *config.KeyPair, cm connMan.ConnManager, finished *sync.WaitGroup) {
	defer finished.Done()
	policy := produceBasicPolicy(k, cm, 3)

	// Phase 1: Create a new Promise
	// First, wait for the server to send a CertifyPromise message. Once
	// a response has been sent, break
	for true {
		msg := new(PolicyMessage).UnmarshalInit(lpt,lpr,lpn, k.Suite)
		cm.Get(keyPairT.Public, msg)
		msgTyp, err := policy.handlePolicyMessage(keyPairT.Public, msg)
		if msgTyp == CertifyPromise && err == nil {
			break
		}
	}
	
	// Phase 2: Send the Promise to a Client
	for true {
		msg := new(PolicyMessage).UnmarshalInit(lpt,lpr,lpn, k.Suite)
		cm.Get(clientT.Public, msg)
		msgTyp, err := policy.handlePolicyMessage(clientT.Public, msg)
		if msgTyp == CertifyPromise && err == nil {
			break
		}
	}

	// Phase 3: Certify insurer promises.
	for i := 0; i < numServers; i++ {
		if k.Public.Equal(serverKeys[i].Public) {
			policy.CertifyPromise(keyPairT.Public, secretKeyT.Public)
			// Simply get the message sent to oneself and ignore it.
			msg := new(PolicyMessage).UnmarshalInit(lpt,lpr,lpn, k.Suite)
			cm.Get(serverKeys[i].Public, msg)
		} else {
			for true {
				msg := new(PolicyMessage).UnmarshalInit(lpt,lpr,lpn, k.Suite)
				cm.Get(serverKeys[i].Public, msg)
				msgTyp, err := policy.handlePolicyMessage(serverKeys[i].Public, msg)
				if msgTyp == CertifyPromise && err == nil {
					break
				}
			}	
		}
	}
	
	// Phase 4: Reconstruct Secret
	for true {
		msg := new(PolicyMessage).UnmarshalInit(lpt,lpr,lpn, k.Suite)
		cm.Get(clientT.Public, msg)
		msgTyp, err := policy.handlePolicyMessage(clientT.Public, msg)
		if msgTyp == ShareRevealRequest && err == nil {
			break
		}
	}
}

// This method simulates the client channel
func clientFunctional(t *testing.T, finished *sync.WaitGroup) {
	defer finished.Done()
	policy := produceBasicPolicy(clientT, clientConn, 3)

	// Phase 2: Send the Promise to a Client
	msg := new(PolicyMessage).UnmarshalInit(lpt,lpr,lpn, clientT.Suite)
	clientConn.Get(keyPairT.Public, msg)
	msgTyp, err := policy.handlePolicyMessage(keyPairT.Public, msg)	

	if msgTyp != PromiseToClient || err != nil {
		panic("Expected to receive a promise from the server")
	}

	err = policy.CertifyPromise(keyPairT.Public, secretKeyT.Public)
	if err != nil {
		panic("Promise should be certified")
	}
	
	// Phase 4 Reconstruct Secret
	key, err := policy.ReconstructSecret("test", keyPairT.Public, secretKeyT.Public)
	if err != nil {
		panic("Expected promise.")
	}
	if !key.Equal(secretKeyT.Secret) {
		panic("Secret Failed to be reconstructed.")
	}
}

// Performs the functional test for LifePolicyModule and simulates the server channel
func TestLifePolicyModuleFunctionalTest(t *testing.T) {

	finished := new(sync.WaitGroup)
	finished.Add(numServers + 1)

	// Start up the insurers and the client
	for i := 0; i< numServers; i++ {
		go insurersFunctional(t, serverKeys[i], connectionManagers[i], finished)
	}
	go clientFunctional(t, finished)

	
	// Phase 1: Create a new Promise
	policy := produceBasicPolicy(keyPairT, goConn, 3)
	err    := policy.TakeOutPolicy(secretKeyT, insurerListT, nil)
	if err != nil {
		t.Fatal("The promise should have been certified.")
	}
	
	// Phase 2: Send the Promise to a Client
	err = policy.SendPromiseToClient(clientT.Public, secretKeyT.Public)
	if err != nil {
		t.Fatal("Message should have been sent.")
	}

	// Phase 4: Reconstruct Secret
	// 
	// This code would not be replicated in production. Since the tests use
	// blocking go channels, the insurers would hang indefinitely while trying
	// to see if the server is alive. Hence, the server must actually send
	// them an irrelevant message so the insurers will not hang waiting for
	// a response.

	// First get all the server alive requests and ignore them.
	for i := 0; i< numServers; i++ {
		msg := new(PolicyMessage).UnmarshalInit(lpt,lpr,lpn, keyPairT.Suite)
		goConn.Get(serverKeys[i].Public, msg)
		if msg.Type != ServerAliveRequest {
			t.Fatal("Expecting to receive a request from the insurer")
		}
	}

	// Sleep to ensure the timelimit expires
	time.Sleep(4 * time.Second)

	// Then send out a server alive request to simply give the insurers a message
	// to process so they won't be waiting to hear back forever.
	for i := 0; i< numServers; i++ {
		goConn.Put(serverKeys[i].Public, new(PolicyMessage).createSAREQMessage())
	}
	
	// Verify the insurers got the message.
	for i := 0; i< numServers; i++ {
		msg := new(PolicyMessage).UnmarshalInit(lpt,lpr,lpn, keyPairT.Suite)
		goConn.Get(serverKeys[i].Public, msg)
		if msg.Type != ServerAliveResponse {
			t.Fatal("Expecting to receive a response from the insurer")
		}
	}

	finished.Wait()
}

