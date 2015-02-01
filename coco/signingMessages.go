package coco

import (
	"bytes"
	"encoding/gob"
	"log"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/nist"
	"github.com/dedis/prifi/timestamp"
)

// All message structures defined in this package are used in the
// Collective Signing Protocol
// Over the network they are sent as byte slices, so each message
// has its own MarshlBinary and UnmarshalBinary method

const HASH_SIZE int = 32 // TODO: change the way this is known

type MessageType int

const (
	Error MessageType = iota
	Announcement
	Commitment
	Challenge
	Response
)

// Signing Messages are used for all comunications between servers
// It is imporant for encoding/ decoding for type to be kept as first field
type SigningMessage struct {
	Type MessageType
	am   *AnnouncementMessage
	com  *CommitmentMessage
	chm  *ChallengeMessage
	rm   *ResponseMessage
	err  *ErrorMessage
}

func (sm SigningMessage) MarshalBinary() ([]byte, error) {
	var b bytes.Buffer
	var sub []byte
	var err error
	b.WriteByte(byte(sm.Type)) // first field is 1-byte long type
	// marshal sub message based on its Type
	switch sm.Type {
	case Announcement:
		sub, err = sm.am.MarshalBinary()
	case Commitment:
		sub, err = sm.com.MarshalBinary()
	case Challenge:
		sub, err = sm.chm.MarshalBinary()
	case Response:
		sub, err = sm.rm.MarshalBinary()
	case Error:
		sub, err = sm.err.MarshalBinary()
	}
	if err == nil {
		b.Write(sub)
	}
	return b.Bytes(), err
}

func (sm *SigningMessage) UnmarshalBinary(data []byte) error {
	sm.Type = MessageType(data[0]) // first field is 1-byte long type
	msgBytes := data[1:]
	var err error
	switch sm.Type {
	case Announcement:
		sm.am = &AnnouncementMessage{}
		err = sm.am.UnmarshalBinary(msgBytes)
	case Commitment:
		sm.com = &CommitmentMessage{}
		err = sm.com.UnmarshalBinary(msgBytes)
	case Challenge:
		sm.chm = &ChallengeMessage{}
		err = sm.chm.UnmarshalBinary(msgBytes)
	case Response:
		sm.rm = &ResponseMessage{}
		err = sm.rm.UnmarshalBinary(msgBytes)
	case Error:
		sm.err = &ErrorMessage{}
		err = sm.err.UnmarshalBinary(msgBytes)
	}
	return err
}

// Broadcasted message initiated and signed by proposer
type AnnouncementMessage struct {
	LogTest []byte
}

type CommitmentMessage struct {
	V     abstract.Point // commitment Point
	V_hat abstract.Point // product of children's commitment points

	MTRoot timestamp.HashId // root of Merkle (sub)Tree
}

type ChallengeMessage struct {
	C abstract.Secret // challenge

	// Depth  byte
	MTRoot timestamp.HashId // the very root of the big Merkle Tree
	Proof  timestamp.Proof  // Merkle Path of Proofs from root to us
	// LevelProof timestamp.LevelProof // parent's LevelProof
}

type ResponseMessage struct {
	R_hat abstract.Secret // response
}

type ErrorMessage struct {
	Err error
}

type TestMessage struct {
	S     abstract.Secret
	Bytes []byte
}

// ANNOUCEMENT  ENCODE
func (am AnnouncementMessage) MarshalBinary() ([]byte, error) {
	var b bytes.Buffer
	enc := gob.NewEncoder(&b)
	err := enc.Encode(am.LogTest)
	return b.Bytes(), err
}

func (am *AnnouncementMessage) UnmarshalBinary(data []byte) error {
	b := bytes.NewBuffer(data)
	dec := gob.NewDecoder(b)
	err := dec.Decode(&am.LogTest)
	return err
}

// COMMIT ENCODE
func (cm CommitmentMessage) MarshalBinary() ([]byte, error) {
	// abstract.Write used to encode/ marshal crypto types
	b := bytes.Buffer{}
	abstract.Write(&b, &cm, nist.NewAES128SHA256P256())
	b.Write(cm.MTRoot)
	return b.Bytes(), nil
}

func (cm *CommitmentMessage) UnmarshalBinary(data []byte) error {
	// abstract.Write used to decode/ unmarshal crypto types
	b := bytes.NewBuffer(data)
	err := abstract.Read(b, cm, nist.NewAES128SHA256P256())
	cm.MTRoot = data[len(data)-HASH_SIZE:]
	return err
}

// CHALLENGE ENCODE
func (cm ChallengeMessage) MarshalBinary() ([]byte, error) {
	// abstract.Write used to encode/ marshal crypto types
	b := bytes.Buffer{}
	abstract.Write(&b, &cm.C, nist.NewAES128SHA256P256())

	// var err error
	b.Write(cm.MTRoot)
	for _, proof := range cm.Proof {
		b.Write(proof)
	}
	log.Println("Encodingchallenge with", len(b.Bytes()))
	return b.Bytes(), nil
}

func (cm *ChallengeMessage) UnmarshalBinary(data []byte) error {
	log.Println("Decoding challenge with", len(data))
	b := bytes.NewBuffer(data[:32])
	err := abstract.Read(b, cm, nist.NewAES128SHA256P256())
	rem := data[cm.C.Len():] // after secret

	if len(rem) < HASH_SIZE {
		return nil
	}
	cm.MTRoot = rem[:HASH_SIZE] // after mt root
	rem = rem[HASH_SIZE:]

	nHashIds := len(rem) / HASH_SIZE

	if len(rem)%HASH_SIZE != 0 {
		log.Println("BAD not div by Hash_size", len(rem)%HASH_SIZE)
	}

	log.Println("nhashIds", nHashIds)
	cm.Proof = cm.Proof[:0]
	for i := 0; i < nHashIds; i++ {
		if len(rem) < (i+1)*HASH_SIZE {
			return nil
		}
		cm.Proof = append(cm.Proof, rem[i*HASH_SIZE:(i+1)*HASH_SIZE])
	}

	return err
}

// RESPONE ENCODE
func (rm ResponseMessage) MarshalBinary() ([]byte, error) {
	b := bytes.Buffer{}
	abstract.Write(&b, &rm, nist.NewAES128SHA256P256())
	return b.Bytes(), nil
}

func (rm *ResponseMessage) UnmarshalBinary(data []byte) error {
	b := bytes.NewBuffer(data)
	err := abstract.Read(b, rm, nist.NewAES128SHA256P256())
	return err
}

// ERROR ENCODE
func (em ErrorMessage) MarshalBinary() ([]byte, error) {
	var b bytes.Buffer
	enc := gob.NewEncoder(&b)
	err := enc.Encode(em.Err)
	return b.Bytes(), err
}

func (em *ErrorMessage) UnmarshalBinary(data []byte) error {
	b := bytes.NewBuffer(data)
	dec := gob.NewDecoder(b)
	err := dec.Decode(&em.Err)
	return err
}

// Try challenge code
// log.Println("\n\n")
// log.Println(cm)
// log.Println()
// var messg coconet.BinaryUnmarshaler
// messg = &ChallengeMessage{}
// messg.UnmarshalBinary(b.Bytes())
// log.Println(messg)
// log.Println("\n\n")
