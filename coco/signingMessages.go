package coco

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/dedis/crypto/abstract"
)

// All message structures defined in this package are used in the
// Collective Signing Protocol
// Over the network they are sent as byte slices, so each message
// has its own MarshlBinary and UnmarshalBinary method

type MessageType int

const (
	Error MessageType = iota
	Announcement
	Commitment
	Challenge
	Response
)

type SigningMessage struct {
	Type MessageType
	am   *AnnouncementMessage
	com  *CommitmentMessage
	chm  *ChallengeMessage
	rm   *ResponseMessage
}

func (sm SigningMessage) MarshalBinary() ([]byte, error) {
	var b bytes.Buffer
	var sub []byte
	var err error
	fmt.Fprintf(&b, "%v ", sm.Type) // space needed after type
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
	}
	if err == nil {
		b.Write(sub)
	}
	fmt.Print(string(b.Bytes()))
	return b.Bytes(), err
}

func (sm *SigningMessage) UnmarshalBinary(data []byte) error {
	b := bytes.NewBuffer(data)
	n, err := fmt.Fscan(b, &sm.Type)
	if err != nil {
		return err
	}
	msgBytes := data[n:]
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
	}
	return err
}

// Broadcasted message initiated and signed by proposer
type AnnouncementMessage struct {
	logTest []byte
}

type CommitmentMessage struct {
	V     abstract.Point // commitment Point
	V_hat abstract.Point // product of children's commitment points
}

type ChallengeMessage struct {
	c abstract.Secret // challenge
}

type ResponseMessage struct {
	r_hat abstract.Secret // response
}

type TestMessage struct {
	S     abstract.Secret
	Bytes []byte
}

func (am AnnouncementMessage) MarshalBinary() ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	err := enc.Encode(am.logTest)
	return b.Bytes(), err
}

func (am *AnnouncementMessage) UnmarshalBinary(data []byte) error {
	b := bytes.NewBuffer(data)
	dec := json.NewDecoder(b)
	err := dec.Decode(&am.logTest)
	return err
}

func (cm CommitmentMessage) MarshalBinary() ([]byte, error) {
	var b bytes.Buffer
	fmt.Fprintln(&b, cm.V, cm.V_hat)
	return b.Bytes(), nil
}

func (cm *CommitmentMessage) UnmarshalBinary(data []byte) error {
	b := bytes.NewBuffer(data)
	_, err := fmt.Fscanln(b, &cm.V, &cm.V_hat)
	return err
}

func (cm ChallengeMessage) MarshalBinary() ([]byte, error) {
	var b bytes.Buffer
	fmt.Fprintln(&b, cm.c)
	return b.Bytes(), nil
}

func (cm *ChallengeMessage) UnmarshalBinary(data []byte) error {
	b := bytes.NewBuffer(data)
	_, err := fmt.Fscanln(b, &cm.c)
	return err
}

func (rm ResponseMessage) MarshalBinary() ([]byte, error) {
	var b bytes.Buffer
	fmt.Fprintln(&b, rm.r_hat)
	return b.Bytes(), nil
}

func (rm *ResponseMessage) UnmarshalBinary(data []byte) error {
	b := bytes.NewBuffer(data)
	_, err := fmt.Fscanln(b, &rm.r_hat)
	return err
}
