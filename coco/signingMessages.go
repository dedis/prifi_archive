package coco

import (
	"bytes"
	"fmt"

	"github.com/dedis/crypto/abstract"
)

// All message structures defined in this package are used in the
// Collective Signing Protocol
// Over the network they are sent as byte slices, so each message
// has its own MarshlBinary and UnmarshalBinary method

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
	fmt.Fprintln(&b, am.logTest)
	return b.Bytes(), nil
}

func (am *AnnouncementMessage) UnmarshalBinary(data []byte) error {
	b := bytes.NewBuffer(data)
	_, err := fmt.Fscanln(b, &am.logTest)
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
