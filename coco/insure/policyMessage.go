package insure

import (
	"bytes"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/anon"
	"github.com/dedis/crypto/config"
	"github.com/dedis/crypto/poly"
	"github.com/dedis/crypto/random"
	
	"github.com/dedis/protobuf"
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

/* Creates a new PolicyMessage
 *
 * Arguments:
 *	m = A RequestInsuranceMessage for sending over the network
 *
 * Returns:
 *	A new PolicyMessage responsible for sending an RequestInsuranceMessage
 */
func (pm *PolicyMessage) createRIMessage(m *RequestInsuranceMessage) *PolicyMessage {
	pm.Type = RequestInsurance
	pm.rim  = m
	return pm
}

/* Creates a new PolicyMessage
 *
 * Arguments:
 *	m = A PolicyApprovedMessage for sending over the network
 *
 * Returns:
 *	A new PolicyMessage responsible for sending an PolicyApprovedMessage
 */
func (pm *PolicyMessage) createPAMessage(m *PolicyApprovedMessage) *PolicyMessage {
	pm.Type = PolicyApproved
	pm.pam  = m
	return pm
}

// Returns the RequestInsuranceMessage of this PolicyMessage
func (pm *PolicyMessage) getRIM() *RequestInsuranceMessage {
	return pm.rim
}

// Returns the PolicyApprovedMessage of this PolicyMessage
func (pm *PolicyMessage) getPAM() *PolicyApprovedMessage {
	return pm.pam
}

// This code is responsible for mashalling the message for sending off.
func (pm *PolicyMessage) MarshalBinary() ([]byte, error) {
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

// This function is responsible for unmarshalling the data. It keeps track
// of which type the message is and decodes it properly.
func (pm *PolicyMessage) UnmarshalBinary(data []byte) error {
	pm.Type = MessageType(data[0])
	msgBytes := data[1:]
	var err error
	switch pm.Type {
	case RequestInsurance:
		pm.rim, err = new(RequestInsuranceMessage).UnmarshalBinary(msgBytes)
	case PolicyApproved:
		pm.pam, err = new(PolicyApprovedMessage).UnmarshalBinary(msgBytes)
	}
	return err
}


// These messages are used to send insurance requests. A node looking for an
// insurance policy will send these to other nodes to ask them to become
// insurers.
type RequestInsuranceMessage struct {
	// The public key of the insured.
	PubKey abstract.Point

	// The private share to give to the insurer
	Share abstract.Secret

	// The public polynomial used to verify the share
	PubCommit *poly.PubPoly
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
func (msg *RequestInsuranceMessage) createMessage(p abstract.Point, s abstract.Secret,
	pc *poly.PubPoly) *RequestInsuranceMessage {
	msg.PubKey = p
	msg.Share = s
	msg.PubCommit = pc
	return msg
}

// Encodes the message for sending.
func (msg *RequestInsuranceMessage) MarshalBinary() ([]byte, error) {
	b := bytes.Buffer{}
	abstract.Write(&b, msg, INSURE_GROUP)
	return b.Bytes(), nil
//	return protobuf.Encode(msg);
}

// Decodes a message received.
// NOTE: In order to be encoded properly, public polynomials need to be
// initialized with the right group and minimum number of shares.
func (msg *RequestInsuranceMessage) UnmarshalBinary(data []byte) (*RequestInsuranceMessage, error) {
	msg.PubCommit = new(poly.PubPoly)
	msg.PubCommit.Init(INSURE_GROUP, TSHARES, nil)
	msg.PubKey = KEY_SUITE.Point()
	b := bytes.NewBuffer(data)
	err := abstract.Read(b, msg, INSURE_GROUP)
	return msg, err
//	return 	msg, protobuf.Decode(data, msg)

}

type PolicyApprovedMessage struct {
	// The public key of the insurer.
	PubKey abstract.Point

	// The message stating that the insurer has approved of being an insurer
	Message []byte

	// A certificate certifying that an insurer has indeed approved of
	// the policy and signed with their own key.
	Signature []byte
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
func (msg *PolicyApprovedMessage) createMessage(kp *config.KeyPair,
	theirKey abstract.Point) *PolicyApprovedMessage {

	set := anon.Set{kp.Public}
	approveMsg := kp.Public.String() + " insures " + theirKey.String()
	msg.PubKey  = kp.Public
	msg.Message = []byte(approveMsg)
	msg.Signature = anon.Sign(kp.Suite, random.Stream, msg.Message,
		set, nil, 0, kp.Secret)
	return msg
}

// Encodes a policy message for sending over the Internet
func (msg *PolicyApprovedMessage) MarshalBinary() ([]byte, error) {
	return protobuf.Encode(msg);
}

// Decodes a policy message for sending over the Internet
func (msg *PolicyApprovedMessage) UnmarshalBinary(data []byte) (*PolicyApprovedMessage, error) {
	msg.PubKey = KEY_SUITE.Point()
	return msg, protobuf.Decode(data, msg);
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
	insuredKey abstract.Point) bool {

	set := anon.Set{msg.PubKey}
	_, err := anon.Verify(su, msg.Message, set, nil, msg.Signature)
	correctMsg := msg.PubKey.String() + " insures " + insuredKey.String()
	return err == nil && correctMsg == string(msg.Message)
}
