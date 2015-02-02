package insure

import (
	"bytes"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/anon"
	"github.com/dedis/crypto/config"
	"github.com/dedis/crypto/nist"
	"github.com/dedis/crypto/poly"
	"github.com/dedis/crypto/random"
)

/* Modelled off coco/signingMessage.go, this file is responsible for encoding/
 * decoding messages sent as a part of the insurance policy protocol.
 */

type MessageType int

const (
	Error MessageType = iota
	RequestInsurance
	PolicyApproved
)

type PolicyMessage struct {
	Type MessageType
	rim  *RequestInsuranceMessage
	pam  *PolicyApprovedMessage
}

func (pm PolicyMessage) MarshalBinary() ([]byte, error) {
	var b bytes.Buffer
	var sub []byte
	var err error
	b.WriteByte(byte(pm.Type))
	// marshal sub message based on its Type
	switch pm.Type {
	case RequestInsurance:
		sub, err = pm.rim.MarshalBinary()
	case PolicyApproved:
		sub, err = pm.pam.MarshalBinary()
	}
	if err == nil {
		b.Write(sub)
	}
	return b.Bytes(), err
}

func (pm *PolicyMessage) UnmarshalBinary(data []byte) error {
	pm.Type = MessageType(data[0])
	msgBytes := data[1:]
	var err error
	switch pm.Type {
	case RequestInsurance:
		pm.rim = &RequestInsuranceMessage{}
		err = pm.rim.UnmarshalBinary(msgBytes)
	case PolicyApproved:
		pm.pam = &PolicyApprovedMessage{}
		err = pm.pam.UnmarshalBinary(msgBytes)
	}
	return err
}

type RequestInsuranceMessage struct {
	// The private share to give to the insurer
	share abstract.Secret

	// The public polynomial used to verify the share
	pubCommit poly.PubPoly
}

/* Creates a new insurance request message
 *
 * Arguments:
 *	s  = the shared secret to give to the insurer.
 *      pc = the public polynomial to check the share against.
 *
 * Returns:
 *	A new insurance request message.
 */
func (msg *RequestInsuranceMessage) createMessage(s abstract.Secret,
	pc poly.PubPoly) *RequestInsuranceMessage {
	msg.share = s
	msg.pubCommit = pc
	return msg
}

func (msg *RequestInsuranceMessage) MarshalBinary() ([]byte, error) {
	b := bytes.Buffer{}
	abstract.Write(&b, msg, nist.NewAES128SHA256P256())
	return b.Bytes(), nil
}

func (msg *RequestInsuranceMessage) UnmarshalBinary(data []byte) error {
	b := bytes.NewBuffer(data)
	err := abstract.Read(b, msg, nist.NewAES128SHA256P256())
	return err
}

type PolicyApprovedMessage struct {
	// The message stating that the insurer has approved of being an insurer
	message []byte

	// A certificate certifying that an insurer has indeed approved of
	// the policy and signed with their own key.
	signature []byte
}

/* Creates a new policy-approved message
 *
 * Arguments:
 *	kp       = the private/public key of the insuring server.
 *      theirKey = the public key of the server who requested the insurance
 *
 * Returns:
 *	A new policy approved message.
 *
 * NOTE:
 *	The approved certificate is a string of the form:
 *     		"My_Public_Key insures Their_Public_Key"
 *
 *	It will always be of this form for easy validation.
 */
func (msg *PolicyApprovedMessage) createMessage(kp config.KeyPair,
	theirKey abstract.Point) *PolicyApprovedMessage {

	set := anon.Set{kp.Public}
	approveMsg := kp.Public.String() + " insures " + theirKey.String()
	msg.message = []byte(approveMsg)
	msg.signature = anon.Sign(kp.Suite, random.Stream, msg.message,
		set, nil, 0, kp.Secret)
	return msg
}

// Encodes a policy message for sending over the Internet
func (msg *PolicyApprovedMessage) MarshalBinary() ([]byte, error) {
	b := bytes.Buffer{}
	abstract.Write(&b, msg, nist.NewAES128SHA256P256())
	return b.Bytes(), nil
}

// Decodes a policy message for sending over the Internet
func (msg *PolicyApprovedMessage) UnmarshalBinary(data []byte) error {
	b := bytes.NewBuffer(data)
	err := abstract.Read(b, msg, nist.NewAES128SHA256P256())
	return err
}

/* Verifies that a PolicyApproveMessage has been properly constructed.
 *
 * Arguments:
 *	su         = the suite that the insurer's public key was derived from.
 *      insuredKey = the public key of the insured or the client
 *      insurerKey = the public key of the insurer or "trustee"
 *
 * Returns:
 *	whether or not the message is valid.
 */

func (msg *PolicyApprovedMessage) verifyCertificate(su abstract.Suite,
	insuredKey, insurerKey abstract.Point) bool {

	set := anon.Set{insurerKey}
	_, err := anon.Verify(su, msg.message, set, nil, msg.signature)
	correctMsg := insurerKey.String() + " insures " + insuredKey.String()
	return err == nil && correctMsg == string(msg.message)
}
