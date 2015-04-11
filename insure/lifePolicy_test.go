package insure

import (
	//"sync"
	"reflect"
	"testing"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/config"
	"github.com/dedis/crypto/poly/promise"
	"github.com/dedis/crypto/random"

	"github.com/dedis/prifi/connMan"
	"github.com/dedis/prifi/coco/coconet"
)

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

func produceNewServerPolicyWithPromise() (*LifePolicyModule,* promise.State) {
	policy := new(LifePolicyModule).Init(keyPairT, lpt,lpr,lpn, goConn) 
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
	policy := new(LifePolicyModule).Init(keyPairT, lpt,lpr,lpn, goConn)
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
	if policy.promises == nil {
		t.Error("promises map not properly set")
	}

	if policy.serverPromises == nil {
		t.Error("serverPromises map not properly set")
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
	err = policy.certifyPromise(state)
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
	policy := new(LifePolicyModule).Init(keyPairT, lpt,lpr,lpn, goConn)
	err := policy.CertifyPromise(keyPairT.Public, secretKeyT.Public)
	if err == nil {
		t.Error("The lookup should have failed.")
	}
}

// Verifies that revealShare can properly communicate with other servers.
func TestLifePolicyModuleRevealShare(t *testing.T) {

	// Create the policy for the client
	clientPolicy := new(LifePolicyModule).Init(clientT, lpt,lpr,lpn, clientConn)

	// Create a policy for the first insurer. Give it a promise from the
	// promiser server.
	insurerPolicy := new(LifePolicyModule).Init(serverKeys[0], lpt,lpr,lpn, connectionManagers[0])
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
	
	policy:= new(LifePolicyModule).Init(keyPairT, lpt,lpr,lpn, goConn) 
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
	
	policy = new(LifePolicyModule).Init(keyPairT, lpt,lpr,lpn, goConn) 
	err    = policy.TakeOutPolicy(secretKeyT, insurerListT, goodFunc)
	if !called {
		t.Error("The method should have used the provided method")
	}
	
	
	// Error Handling
	badFunc := func(serverList []abstract.Point, n int) []abstract.Point {
		return serverList[:n-1]
	}
	
	// Verify that equal panics if the messages are uninitialized
	test := func() {
		defer deferTest(t, "TakeOutPolicy should have paniced")
		policy := new(LifePolicyModule).Init(keyPairT, lpt,lpr,lpn, goConn) 
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
	policy := new(LifePolicyModule).Init(keyPairT, lpt,lpr,lpn, goConn) 
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

// Verifies that an insurer can handle CertifyPromiseMessages from promisers and clients
func TestLifePolicyModuleHandleCertifyPromiseMessage(t *testing.T) {

	clientI  := 1
	insurerI := 2 
	policy := new(LifePolicyModule).Init(serverKeys[insurerI], lpt,lpr,lpn, connectionManagers[insurerI]) 
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
	policy := new(LifePolicyModule).Init(clientT, lpt,lpr,lpn, clientConn)
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
	policy := new(LifePolicyModule).Init(keyPairT, lpt,lpr,lpn, goConn) 
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
 * what it would be in production. It uses gochanns to simulate the network. It
 * has three main type of channesl:
 *
 *   - Server channel = this is the channel of the main server who creates the
 *                      promise. This is the TestLifePolicyFunctional method.
 *
 *   - Insurer channel = these are a set of channels for representing insurer
 *                       logic with one per insurer.
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
 *
 *   Phase 2: Send the Promise to a Client
 *
 *      The server sends the Promise to the client. The client receives it and
 *      then contacts the insurers to certify the promise.
 *
 *
 */


// This is a helper method that simulates the insurer channel
func insurersFunctional(t *testing.T, k *config.KeyPair, cm connMan.ConnManager) {

	policy := new(LifePolicyModule).Init(k, lpt,lpr,lpn, cm) 

	// Phase 1: Create a new Promise
	// First, wait for the server to send a CertifyPromise message. Once
	// a response has been sent, break
	for true {
		msg := new(PolicyMessage).UnmarshalInit(lpt,lpr,lpn, k.Suite)
		cm.Get(keyPairT.Public, msg)
		msgTyp, err := policy.handlePolicyMessage(keyPairT.Public, msg)
		if msgTyp == CertifyPromise && err != nil {
			break
		}
	}
	
	// Phase 2: Send the Promise to a Client
	for true {
		msg := new(PolicyMessage).UnmarshalInit(lpt,lpr,lpn, k.Suite)
		cm.Get(clientT.Public, msg)
		msgTyp, err := policy.handlePolicyMessage(serverKeys[0].Public, msg)
		if msgTyp == CertifyPromise && err != nil {
			break
		}
	}
}

// This method simulates the client channel
func clientFunctional(t *testing.T) {

	policy := new(LifePolicyModule).Init(clientT, lpt,lpr,lpn, clientConn) 

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
}

// Performs the functional test for LifePolicyModule and simulates the server channel
func TestLifePolicyModuleFunctionalTest(t *testing.T) {

	// Start up the insurers and the client
	for i := 0; i< numServers; i++ {
		go insurersFunctional(t, serverKeys[i], connectionManagers[i])
	}
	go clientFunctional(t)

	
	// Phase 1: Create a new Promise
	policy := new(LifePolicyModule).Init(keyPairT, lpt,lpr,lpn, goConn) 
	err    := policy.TakeOutPolicy(secretKeyT, insurerListT, nil)
	if err != nil {
		t.Fatal("The promise should have been certified.")
	}
	
	// Phase 2: Send the Promise to a Client
	err = policy.SendPromiseToClient(clientT.Public, secretKeyT.Public)
	if err != nil {
		t.Fatal("Message should have been sent.")
	}
}



/*

func TestTakeOutPolicyBasic(t *testing.T) {

	// ERROR CHECKING

	// Invalid n
/ *	_, ok1 := new(LifePolicy).Init(keyPairT, goConn).TakeOutPolicy(
		insurerListT, nil, INSURE_GROUP, TSHARES, 0)

	if ok1 {
		t.Fatal("Policy should fail if n < TSHARES.")
	}

	// Too small insurersList
	_, ok2 := new(LifePolicy).Init(keyPairT, goConn).TakeOutPolicy(
		[]abstract.Point{produceKeyPairT().Public}, nil, INSURE_GROUP,
		TSHARES, 1)

	if ok2 {
		t.Fatal("Policy should fail not enough servers are given.")
	}

	// The function selection is bad
	badFunc := func(sl []abstract.Point, n int) []abstract.Point {
		return []abstract.Point{produceKeyPairT().Public,
			produceKeyPairT().Public}
	}

	_, ok3 := new(LifePolicy).Init(keyPairT, goConn).TakeOutPolicy(
		insurerListT, badFunc, INSURE_GROUP, TSHARES, numServers)

	if ok3 {
		t.Fatal("Policy should fail not enough servers are given.")
	}* /

	// Success Cases

	// Start up the other insurers.
	for i := 0; i < numServers; i++ {
		go insurersBasic(t, serverKeys[i], connectionManagers[i])
	}

	policy:= new(LifePolicyModule).Init(keyPairT, lpt,lpr,lpn, goConn) 
	err := policy.TakeOutPolicy(secretKeyT, insurerListT, nil)

	if err != nil {
		t.Error("Policy failed to be created: ", err)
	}
	
	newPromiseState, ok := policy.promises[secretKeyT.Public.String()]
	
	if !ok || newPromiseState.Promise.Id() != secretKeyT.Public.String() {
		t.Error("Promise failed to be stored.")
	}

	if newPromiseState.PromiseCertified() != nil {
		t.Error("Promise should be certified.")
	}
}



// This function is the code run by the insurers. The server listens for a
// CertifyPromiseMessage, sends a response, and then exits.
func serversIntermediate(t *testing.T, finished, start *sync.WaitGroup,
	secret,key *config.KeyPair, cm connMan.ConnManager) *LifePolicyModule {
	defer finished.Done()
	start.Wait()
	policy := new(LifePolicyModule).Init(key, lpt,lpr,lpn-1, cm)
	
	// The insurer list should not include the server itself.
	newInsurersList := make([]abstract.Point, numServers-1, numServers-1)
	for i, j := 0, 0; i < numServers; i++ {
		if !key.Public.Equal(insurerListT[i]) {
			newInsurersList[j] = insurerListT[i]
			j += 1
		}
	}
	
	err := policy.TakeOutPolicy(secret, newInsurersList, nil)
	
	if err != nil {
		panic(err)
	}
	
	newPromiseState, ok := policy.promises[secret.Public.String()]
	
	if !ok || newPromiseState.Promise.Id() != secret.Public.String() {
		panic("Promise failed to be stored.")
	}

	if newPromiseState.PromiseCertified() != nil {
		panic("Promise should be certified.")
	}
	
	return policy
}

// This is a larger scale test. It insurers that all servers participating can
// take out policies, ask each other for insurance, and produce a verified policy
func TestTakeOutPolicyIntermediate(t *testing.T) {

	start := new(sync.WaitGroup)
	start.Add(1)
	finished := new(sync.WaitGroup)
	finished.Add(numServers)
	// Start up the other insurers.
	for i := 0; i < numServers; i++ {
		go serversIntermediate(t, finished, start, secretKeys[i], serverKeys[i], connectionManagers[i])
	}
	start.Done()
	finished.Wait()
}



// This function is the code run by the insurers. The server listens for a
// CertifyPromiseMessage, sends a response, and then exits.
func serversAdvanced(t *testing.T, start, middle, end *sync.WaitGroup,
	secret,key *config.KeyPair, secretKeys []*config.KeyPair, cm connMan.ConnManager) *LifePolicyModule{

	defer end.Done()

	policy := serversIntermediate(t, middle, start, secret, key, cm)
	
	// The insurer list should not include the server itself.
	policy.promises[secret.Public.String()].Promise.Insurers()
	for i := 0; i < numServers; i++ {
		err := policy.SendClientPolicy(insurerListT[i], secret.Public)
		if err != nil {
			panic(err)
		}
	}
	middle.Done()
	middle.Wait()
	//for repeat :=0; repeat < 10; repeat++ {
		for i := 0; i < numServers; i++ {	
			msg := new(PolicyMessage).UnmarshalInit(policy.t,policy.r,policy.n, policy.keyPair.Suite)
			policy.cman.Get(insurerListT[i], msg)
			policy.handlePolicyMessage(insurerListT[i], msg)
		}
	//}

	for i := 0; i < len(secretKeys); i++ {
		if secret.Public.Equal(secretKeys[i].Public) ||
		   key.Public.Equal(insurerListT[i])  {
			continue
		}
		promiserId := insurerListT[i].String()
		id := secretKeys[i].Public.String()
		if policy.serverPromises[promiserId][id].PromiseCertified() != nil {
			panic("Promise expected to be certified")
		}
	}
	return policy
}

// This is builds upon the intermediate test. After every server takes out
// a policy, it then sends the policy to everyone else. Everyone else then checks
// with the insurers to make sure the promise is certified and then accepts it as
// certified
func TestTakeOutPolicyAdvanced(t *testing.T) {

	start := new(sync.WaitGroup)
	start.Add(1)
	middle := new(sync.WaitGroup)
	middle.Add(numServers*2)
	end := new(sync.WaitGroup)
	end.Add(numServers)
	// Start up the other insurers.
	for i := 0; i < numServers; i++ {
		go serversAdvanced(t, start, middle, end, secretKeys[i], serverKeys[i], 
			secretKeys, connectionManagers[i]) 
	}
	start.Done()
	end.Wait()
}


// This function is the code run by the insurers. The server listens for a
// CertifyPromiseMessage, sends a response, and then exits.
func serversReconstruct(t *testing.T, start, middle, end *sync.WaitGroup,
	secret,key *config.KeyPair, secretKeys []*config.KeyPair, cm connMan.ConnManager) {

	defer end.Done()

	policy := serversIntermediate(t, middle, start, secret, key, cm)
	
	middle.Done()
	middle.Wait()
	
	// The insurer list should not include the server itself.
	// Don't reconstruct ones own key.
	if !insurerListT[3].Equal(key.Public) {
	   for repeat :=0; repeat < 1000; repeat++ {
		for i := 0; i < numServers; i++ {	
			msg := new(PolicyMessage).UnmarshalInit(policy.t,policy.r,policy.n, policy.keyPair.Suite)
			policy.cman.Get(insurerListT[i], msg)
			policy.handlePolicyMessage(insurerListT[i], msg)
		}
	   }
	   return
	}
	recoveredSecret := policy.ReconstructSecret(insurerListT[0], secretKeys[0].Public)
	if !recoveredSecret.Equal(secretKeys[0].Secret) {
		panic("Secret failed to be reconstructed")
	}
}

// This is builds upon the intermediate test. After every server takes out
// a policy, it then sends the policy to everyone else. Everyone else then checks
// with the insurers to make sure the promise is certified and then accepts it as
// certified
func TestSecretReconstruction(t *testing.T) {

	start := new(sync.WaitGroup)
	start.Add(1)
	middle := new(sync.WaitGroup)
	middle.Add(numServers*2)
	end := new(sync.WaitGroup)
	end.Add(numServers)
	// Start up the other insurers.
	for i := 0; i < numServers; i++ {
		go serversReconstruct(t, start, middle, end, secretKeys[i], serverKeys[i], 
			secretKeys, connectionManagers[i]) 
	}
	start.Done()
	end.Wait()
}*/
