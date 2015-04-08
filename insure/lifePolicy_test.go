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

var goDir = coconet.NewGoDirectory()

// Variables for the server to take out the policy.
var secretKeyT = produceKeyPairT()
var secretKeyT2 = produceKeyPairT()
var keyPairT   = produceKeyPairT()
var goConn     = produceChanConn(keyPairT)

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
	// Give server #1 connections to everyone else.
	for i := 0; i < numServers; i++ {
		goConn.AddConn(insurerListT[i])
	}

	// Give everyone else connections to server #1
	for i := 0; i < numServers; i++ {
		connectionManagers[i].AddConn(keyPairT.Public)
		
		// Give everyone access to everyone else (Don't give access
		// to oneself)
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
func insurersBasic(t *testing.T, k *config.KeyPair, cm connMan.ConnManager) {

	for true {
		msg := new(PolicyMessage).UnmarshalInit(lpt,lpr,lpn, k.Suite)
		cm.Get(keyPairT.Public, msg)
		
		certMsg := msg.getCPM()

		// If a CertifyPromiseMessage, exit
		if msg.Type == CertifyPromise {
			response, _ := certMsg.Promise.ProduceResponse(certMsg.ShareIndex, k)
			replyMsg := new(PromiseResponseMessage).createMessage(certMsg.ShareIndex, certMsg.Promise, response)
			cm.Put(keyPairT.Public, new(PolicyMessage).createPRMessage(replyMsg))
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
		go insurersBasic(t, serverKeys[i], connectionManagers[i])
	}
	
	err := policy.certifyPromise(state)
	if err != nil {
		t.Error("The promise failed to be certified: ", err)
	}
	finalState := policy.promises[secretKeyT.Public.String()]
	if err := finalState.PromiseCertified(); err != nil {
		t.Error("The promise should now be certified:  ", err)
	}
}


// Verifies that a sever can properly take out a policy.
func TestLifePolicyModuleTakeOutPolicy(t *testing.T) {

	// Start up the other insurers.
	for i := 0; i < numServers; i++ {
		go insurersBasic(t, serverKeys[i], connectionManagers[i])
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
		go insurersBasic(t, serverKeys[i], connectionManagers[i])
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
		go insurersBasic(t, serverKeys[i], connectionManagers[i])
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
