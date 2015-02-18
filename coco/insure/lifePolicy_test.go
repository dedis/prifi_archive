package insure

import (
	"testing"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/config"
	"github.com/dedis/crypto/random"
	
	"github.com/dedis/prifi/coconet"
	"github.com/dedis/prifi/coco/connMan"
)

var goDir = coconet.NewGoDirectory()

var keyPairT  = produceKeyPairT()
var keyPair2T = produceKeyPairT()
var keyPair3T = produceKeyPairT()
var keyPair4T = produceKeyPairT()
var keyPair5T = produceKeyPairT()
var keyPair6T = produceKeyPairT()
var keyPair7T = produceKeyPairT()
var keyPair8T = produceKeyPairT()
var keyPair9T = produceKeyPairT()
var keyPair10T = produceKeyPairT()
var keyPair11T = produceKeyPairT()

var insurerList = []abstract.Point{keyPair2T.Public, keyPair3T.Public, keyPair4T.Public,
                   	keyPair5T.Public, keyPair6T.Public, keyPair7T.Public, 
		   	keyPair8T.Public, keyPair9T.Public, keyPair10T.Public,
		   	keyPair11T.Public}

var goConn  = produceGoConn(keyPairT)
var goConn2  = produceGoConn(keyPair2T)
var goConn3  = produceGoConn(keyPair3T)
var goConn4  = produceGoConn(keyPair4T)
var goConn5  = produceGoConn(keyPair5T)
var goConn6  = produceGoConn(keyPair6T)
var goConn7  = produceGoConn(keyPair7T)
var goConn8  = produceGoConn(keyPair8T)
var goConn9  = produceGoConn(keyPair9T)
var goConn10  = produceGoConn(keyPair10T)
var goConn11  = produceGoConn(keyPair11T)
var setupOkay = setupConn()

// Used to initialize the key pairs.
func produceKeyPairT() *config.KeyPair {
	keyPair := new(config.KeyPair)
	keyPair.Gen(KEY_SUITE, random.Stream)
	return keyPair
}

func produceGoConn(k *config.KeyPair) *connMan.GoConnManager {
	return new(connMan.GoConnManager).Init(k.Public, goDir)
}

func setupConn() bool {
	// Give #1 connections to everyone else.
	goConn.AddConn(keyPair2T.Public)
	goConn.AddConn(keyPair3T.Public)
	goConn.AddConn(keyPair4T.Public)
	goConn.AddConn(keyPair5T.Public)
	goConn.AddConn(keyPair6T.Public)
	goConn.AddConn(keyPair7T.Public)
	goConn.AddConn(keyPair8T.Public)
	goConn.AddConn(keyPair9T.Public)
	goConn.AddConn(keyPair10T.Public)
	goConn.AddConn(keyPair11T.Public)
	
	// Give everyone else connections to #1
	goConn2.AddConn(keyPairT.Public)
	goConn3.AddConn(keyPairT.Public)
	goConn4.AddConn(keyPairT.Public)
	goConn5.AddConn(keyPairT.Public)
	goConn6.AddConn(keyPairT.Public)
	goConn7.AddConn(keyPairT.Public)
	goConn8.AddConn(keyPairT.Public)
	goConn9.AddConn(keyPairT.Public)
	goConn10.AddConn(keyPairT.Public)
	goConn11.AddConn(keyPairT.Public)
	
	return true
}

func insurers(t *testing.T, k * config.KeyPair, cm connMan.ConnManager) {

	policy := new(LifePolicy).Init(k, cm) 

	for true {
		msg := new(PolicyMessage)
		cm.Get(keyPairT.Public, msg)
		
		msgType, ok := policy.handlePolicyMessage(msg)
			
		// If a RequestInsuranceMessage, send an acceptance message and then
		// exit.
		if msgType == RequestInsurance && ok {
		
			if storedMsg, ok := policy.insuredClients[keyPairT.Public.String()]; !ok ||
				!storedMsg.Equal(msg.getRIM()){			
				t.Error("Request message failed to be properly stored.")
			}
			return
		}
	}
}

func TestTakeOutPolicy(t *testing.T) {
	
	// ERROR CHECKING
	
	// Invalid n
	_, ok1 := new(LifePolicy).Init(keyPairT, goConn).TakeOutPolicy(insurerList, nil, 0)
			
	if ok1 {
		t.Fatal("Policy should fail if n < TSHARES.")
	}
	
	// Too small insurersList
	
	_, ok2 := new(LifePolicy).Init(keyPairT, goConn).TakeOutPolicy([]abstract.Point{keyPair2T.Public}, nil, 0)
			
	if ok2 {
		t.Fatal("Policy should fail not enough servers are given.")
	}
	
	// The function selection is bad
	
	badFunc := func(sl []abstract.Point, n int)([]abstract.Point, bool) {return []abstract.Point{keyPair2T.Public, keyPair3T.Public}, true}
	
	_, ok3 := new(LifePolicy).Init(keyPairT, goConn).TakeOutPolicy(insurerList, badFunc, 0)
			
	if ok3 {
		t.Fatal("Policy should fail not enough servers are given.")
	}
	
	
	// Start up the other insurers.
	go insurers(t, keyPair2T, goConn2)
	go insurers(t, keyPair3T, goConn3)
	go insurers(t, keyPair4T, goConn4)
	go insurers(t, keyPair5T, goConn5)
	go insurers(t, keyPair6T, goConn6)
	go insurers(t, keyPair7T, goConn7)
	go insurers(t, keyPair8T, goConn8)
	go insurers(t, keyPair9T, goConn9)
	go insurers(t, keyPair10T, goConn10)
	go insurers(t, keyPair11T, goConn11)
	
	n := 10

	policy, ok := new(LifePolicy).Init(keyPairT, goConn).TakeOutPolicy(insurerList, nil, n)
				
	if !ok {
		t.Error("Policy failed to be created.")
	}
	
	if keyPairT != policy.getKeyPair() {
		t.Error("The key for the policy not properly set.")
	}
	
	resultInsurerList := policy.GetInsurers()
	
	if len(resultInsurerList) != n {
		t.Error("The insurer list was not properly chosen.")
	}
	
	for i := 0; i < n; i++ {
	
		seen := false
		for j :=0; j < n; j++ {
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
	if resultProofList.Len() != n {
		t.Error("Insufficient number of proofs.")
	}
	
	seenList := make([]bool, len(insurerList))
	
	for nextElt := resultProofList.Front(); nextElt != nil; nextElt = nextElt.Next() {
	
		newMessage := nextElt.Value.(*PolicyApprovedMessage)
		for i :=0; i < n; i++ {
			if insurerList[i].Equal(newMessage.PubKey) {
				seenList[i] = true
				break
			}
		}
	}
	
	for i :=0; i < n; i++ {
		if !seenList[i] {
			t.Error("Proof list failed to include the proof from a server")
		}
	}
}

