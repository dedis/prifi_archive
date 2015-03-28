package insure

import (
	"testing"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/config"
	"github.com/dedis/crypto/random"

	"github.com/dedis/prifi/connMan"
	"github.com/dedis/prifi/coco/coconet"
)

var goDir = coconet.NewGoDirectory()

// Variables for the server to take out the policy.
var secretKeyT = produceKeyPairT()
var keyPairT = produceKeyPairT()
var goConn = produceChanConn(keyPairT)

// Alter this to easily scale the number of servers to test with. This
// represents the number of other servers waiting to approve policies.
var numServers = 10

var lpt = 5
var lpr = 7
var lpn = 10

// Variables for the servers to accept the policy
var serverKeys = produceKeys()
var secretKeys = produceKeys()
var insurerList = produceInsuredList()
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
		goConn.AddConn(insurerList[i])
	}

	// Give everyone else connections to server #1
	for i := 0; i < numServers; i++ {
		connectionManagers[i].AddConn(keyPairT.Public)
	}

	return true
}

// This function is the code run by the insurers. The server listens for a
// CertifyPromiseMessage, sends a response, and then exits.
func insurersBasic(t *testing.T, k *config.KeyPair, cm connMan.ConnManager) {

	policy := new(LifePolicyModule).Init(k, cm)

	for true {
		msg := new(PolicyMessage).UnmarshalInit(lpt,lpr,lpn, k.Suite)
		cm.Get(keyPairT.Public, msg)

		msgType, ok := policy.handlePolicyMessage(keyPairT.Public, msg)

		// If a CertifyPromiseMessage, exit
		if msgType == CertifyPromise && ok == nil {
			cpmMsg        := msg.getCPM()
			storedPromise := policy.insuredPromises[keyPairT.Public.String()][cpmMsg.Promise.Id()]
			if !cpmMsg.Promise.Equal(&storedPromise) {
				t.Error("Promise not stored.")
			}
			return
		}
	}
}

func TestTakeOutPolicyBasic(t *testing.T) {

	// ERROR CHECKING

	// Invalid n
/*	_, ok1 := new(LifePolicy).Init(keyPairT, goConn).TakeOutPolicy(
		insurerList, nil, INSURE_GROUP, TSHARES, 0)

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
		insurerList, badFunc, INSURE_GROUP, TSHARES, numServers)

	if ok3 {
		t.Fatal("Policy should fail not enough servers are given.")
	}*/

	// Success Cases

	// Start up the other insurers.
	for i := 0; i < numServers; i++ {
		go insurersBasic(t, serverKeys[i], connectionManagers[i])
	}

	policy:= new(LifePolicyModule).Init(keyPairT, goConn) 
	ok := policy.TakeOutPolicy(secretKeyT, lpt, lpr, lpn, insurerList, nil)

	if !ok {
		t.Error("Policy failed to be created.")
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
func serversIntermediate(t *testing.T, secret,key *config.KeyPair, cm connMan.ConnManager) {

	policy := new(LifePolicyModule).Init(key, cm)
	
	// The insurer list should not include the server itself.
	newInsurersList := make([]abstract.Point, numServers-1, numServers-1)
	for i, j := 0, 0; i < numServers-1; i++ {
		if !key.Public.Equal(insurerList[i]) {
			newInsurersList[j] = insurerList[i]
			j += 1
		}
	}
	
	ok := policy.TakeOutPolicy(secret, lpt, lpr, lpn-1, newInsurersList, nil)

	if !ok {
		t.Error("Policy failed to be created.")
	}
	
	newPromiseState, ok := policy.promises[secretKeyT.Public.String()]
	
	if !ok || newPromiseState.Promise.Id() != secretKeyT.Public.String() {
		t.Error("Promise failed to be stored.")
	}

	if newPromiseState.PromiseCertified() != nil {
		t.Error("Promise should be certified.")
	}
}

// This is a larger scale test. It insurers that all servers participating can
// take out policies, ask each other for insurance, and produce a verified policy
func TestTakeOutPolicyIntermediate(t *testing.T) {

	// Start up the other insurers.
	for i := 0; i < numServers; i++ {
		go serversIntermediate(t, secretKeys[i], serverKeys[i], connectionManagers[i])
	}
}
