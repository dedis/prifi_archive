package insure

import (
	"testing"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/config"
	"github.com/dedis/crypto/random"

	"github.com/dedis/prifi/coco/connMan"
	"github.com/dedis/prifi/coconet"
)

var goDir = coconet.NewGoDirectory()

// Variables for the server to take out the policy.
var keyPairT = produceKeyPairT()
var goConn = produceChanConn(keyPairT)

// Alter this to easily scale the number of servers to test with. This
// represents the number of other servers waiting to approve policies.
var numServers int = 10

// Variables for the servers to accept the policy
var serverKeys = produceServerKeys()
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

func produceServerKeys() []*config.KeyPair {
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

// This function is the code ran by the insurers. The server listens for a
// RequestInsuranceMessage, sends a response, and then exits.
func insurers(t *testing.T, k *config.KeyPair, cm connMan.ConnManager) {

	policy := new(LifePolicy).Init(k, cm)

	for true {
		msg := new(PolicyMessage)
		cm.Get(keyPairT.Public, msg)

		msgType, ok := policy.handlePolicyMessage(msg)

		// If a RequestInsuranceMessage, send an acceptance message and
		// then exit.
		if msgType == RequestInsurance && ok == nil {
			keyValue := msg.getRIM().PubKey.String() +
				msg.getRIM().Share.String()
			if storedMsg, ok := policy.insuredClients[keyValue]; !ok || !storedMsg.Equal(msg.getRIM()) {
				t.Error("Request message not stored.")
			}
			return
		}
	}
}

func TestTakeOutPolicy(t *testing.T) {

	// ERROR CHECKING

	// Invalid n
	_, ok1 := new(LifePolicy).Init(keyPairT, goConn).TakeOutPolicy(
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
	}

	// Success Cases

	// Start up the other insurers.
	for i := 0; i < numServers; i++ {
		go insurers(t, serverKeys[i], connectionManagers[i])
	}

	policy, ok := new(LifePolicy).Init(keyPairT, goConn).TakeOutPolicy(
		insurerList, nil, INSURE_GROUP, TSHARES, numServers)

	if !ok {
		t.Error("Policy failed to be created.")
	}

	if keyPairT != policy.GetKeyPair() {
		t.Error("The key for the policy not properly set.")
	}

	resultInsurerList := policy.GetInsurers()

	if len(resultInsurerList) != numServers {
		t.Error("The insurer list was not properly chosen.")
	}

	for i := 0; i < numServers; i++ {

		seen := false
		for j := 0; j < numServers; j++ {
			if insurerList[i].Equal(resultInsurerList[j]) {
				seen = true
				break
			}
		}

		if !seen {
			t.Error("A server was left out of the insurance list.")
			t.Error("Duplicates in server lis.")
		}
	}

	resultProofList := policy.GetPolicyProof()
	if resultProofList.Len() != numServers {
		t.Error("Insufficient number of proofs.")
	}

	seenList := make([]bool, len(insurerList))

	for nextElt := resultProofList.Front(); nextElt != nil; nextElt = nextElt.Next() {

		newMessage := nextElt.Value.(*PolicyApprovedMessage)
		for i := 0; i < numServers; i++ {
			if insurerList[i].Equal(newMessage.PubKey) {
				seenList[i] = true
				break
			}
		}
	}

	for i := 0; i < numServers; i++ {
		if !seenList[i] {
			t.Error("All servers not included in proof list.")
		}
	}
}
