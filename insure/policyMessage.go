/* Modelled off coco/signingMessage.go, this file is responsible for encoding/
 * decoding messages sent as a part of the insurance policy protocol.
 */
package insure

import (
	"bytes"
	"encoding/binary"
	"io"
	"strconv"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/poly/promise"
)

// Used mostly in marshalling code, this is the size of a uint32
var uint32Size int = binary.Size(uint32(0))

type MessageType int

const (
	Error MessageType = iota
	PromiseResponse
	CertifyPromise
)

type PolicyMessage struct {
	Type MessageType
	cpm  *CertifyPromiseMessage
	prm  *PromiseResponseMessage
}

/* Creates a new PolicyMessage
 *
 * Arguments:
 *	m = A CertifyPromiseMessage for sending over the network
 *
 * Returns:
 *	A new PolicyMessage responsible for sending an CertifyPromiseMessage
 */
func (pm *PolicyMessage) createCPMessage(m *CertifyPromiseMessage) *PolicyMessage {
	pm.Type = CertifyPromise
	pm.cpm  = m
	return pm
}

/* Creates a new PolicyMessage
 *
 * Arguments:
 *	m = A PromiseResponseMessage for sending over the network
 *
 * Returns:
 *	A new PolicyMessage responsible for sending an PromiseResponseMessage
 */
func (pm *PolicyMessage) createPRMessage(m *PromiseResponseMessage) *PolicyMessage {
	pm.Type = PromiseResponse
	pm.prm  = m
	return pm
}

// Returns the CertifyPromiseMessage of this PolicyMessage
func (pm *PolicyMessage) getCPM() *CertifyPromiseMessage {
	return pm.cpm
}

// Returns the PromiseResponseMessage of this PolicyMessage
func (pm *PolicyMessage) getPRM() *PromiseResponseMessage {
	return pm.prm
}

// This code is responsible for mashalling the message for sending off.
func (pm *PolicyMessage) MarshalBinary() ([]byte, error) {
	var b bytes.Buffer
	var sub []byte
	var err error
	b.WriteByte(byte(pm.Type))
	// marshal sub message based on its Type
	switch pm.Type {
	case CertifyPromise:
		sub, err = pm.cpm.MarshalBinary()
	case PromiseResponse:
		sub, err = pm.prm.MarshalBinary()
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
	case CertifyPromise:
		pm.cpm = new(CertifyPromiseMessage)
		err = pm.cpm.UnmarshalBinary(msgBytes)
	case PromiseResponse:
		pm.prm = new(PromiseResponseMessage)
		err = pm.prm.UnmarshalBinary(msgBytes)
	}
	return err
}

// These messages are used to send insurance requests. A node looking for an
// insurance policy will send these to other nodes to ask them to become
// insurers.
type CertifyPromiseMessage struct {
	// The index of the share being sent.
	ShareIndex int

	// The promise to be insured
	Promise promise.Promise
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
func (msg *CertifyPromiseMessage) createMessage(shareIndex int,
	promise promise.Promise) *CertifyPromiseMessage {
	msg.ShareIndex = shareIndex
	msg.Promise    = promise
	return msg
}

/* Initializes a CertifyPromiseMessage for unmarshalling
 *
 * Arguments
 *    suite = the suite used within the Promise
 *
 * Returns
 *   An initialized Promise ready to be unmarshalled
 */
func (msg *CertifyPromiseMessage) UnmarshalInit(t,r,n int, suite abstract.Suite) *CertifyPromiseMessage {
	msg.Promise = promise.Promise{}
	msg.Promise.UnmarshalInit(t, r, n, suite)
	return msg
}

// Compares two messages to see if they are equal
func (msg *CertifyPromiseMessage) Equal(msg2 *CertifyPromiseMessage) bool {
	return msg.ShareIndex == msg2.ShareIndex &&
	       msg.Promise.Equal(&msg2.Promise)
}


/* Returns the number of bytes used by this struct when marshalled
 *
 * Returns
 *   The marshal size
 * Note
 *   This function can be used after UnmarshalInit
 */
func (msg *CertifyPromiseMessage) MarshalSize() int {
	return uint32Size + msg.Promise.MarshalSize()
}

/* Marshals a CertifyPromiseMessage struct into a byte array
 *
 * Returns
 *   A buffer of the marshalled struct
 *   The error status of the marshalling (nil if no error)
 *
 * Note
 *   The buffer is formatted as follows:
 *
 *      ||ShareIndex||Promise||
 *
 */
func (msg *CertifyPromiseMessage) MarshalBinary() ([]byte, error) {
	buf := make([]byte, msg.MarshalSize())

	binary.LittleEndian.PutUint32(buf, uint32(msg.ShareIndex))

	promiseBuf, err := msg.Promise.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(buf[uint32Size:], promiseBuf)
	return buf, nil
}

/* Unmarshals a CertifyPromiseMessage from a byte buffer
 *
 * Arguments
 *    buf = the buffer containing the Promise
 *
 * Returns
 *   The error status of the unmarshalling (nil if no error)
 */
func (msg *CertifyPromiseMessage) UnmarshalBinary(buf []byte) error {

	msg.ShareIndex = int(binary.LittleEndian.Uint32(buf))

	// Decode pubKey and pubPoly
	bufPos      := uint32Size
	promiseSize := msg.Promise.MarshalSize()
	if err := msg.Promise.UnmarshalBinary(buf[bufPos : bufPos+promiseSize]);
		err != nil {
		return err
	}
	return nil
}

/* Marshals a CertifyPromiseMessage struct using an io.Writer
 *
 * Arguments
 *    w = the writer to use for marshalling
 *
 * Returns
 *   The number of bytes written
 *   The error status of the write (nil if no errors)
 */
func (msg *CertifyPromiseMessage) MarshalTo(w io.Writer) (int, error) {
	buf, err := msg.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return w.Write(buf)
}

/* Unmarshals a Promise struct using an io.Reader
 *
 * Arguments
 *    r = the reader to use for unmarshalling
 *
 * Returns
 *   The number of bytes read
 *   The error status of the read (nil if no errors)
 */
func (msg *CertifyPromiseMessage) UnmarshalFrom(r io.Reader) (int, error) {
	// Retrieve promiseSize to find the entire length of the message
	buf := make([]byte, msg.MarshalSize())
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	return n , msg.UnmarshalBinary(buf)
}

/* Returns a string representation of the CertifyPromiseMessage for easy debugging
 *
 * Returns
 *   The CertifyPromiseMessage's string representation
 */
func (msg *CertifyPromiseMessage) String()  string {
	s := "{CertifyPromiseMessage:\n"
	s += "ShareIndex => " + strconv.Itoa(msg.ShareIndex) + ",\n"
	s += "Promise => " + msg.Promise.String() + "\n"
	s += "}\n"
	return s
}

type PromiseResponseMessage struct {

	// The index of teh share that this is a response to.
	ShareIndex int

	// The index of teh share that this is a response to.
	PromiserId string

	// The index of the share that this is a response to.
	Id string

	// The insurer's response denoting whether it approves or rejects the
	// promise.
	Response *promise.Response
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
func (msg *PromiseResponseMessage) createMessage(shareIndex int, promise promise.Promise,
	response *promise.Response) *PromiseResponseMessage {
	msg.Id         = promise.Id()
	msg.PromiserId = promise.PromiserId()
	msg.ShareIndex = shareIndex
	msg.Response   = response
	return msg
}

/* Initializes a CertifyPromiseMessage for unmarshalling
 *
 * Arguments
 *    suite = the suite used within the Promise
 *
 * Returns
 *   An initialized Promise ready to be unmarshalled
 */
func (msg *PromiseResponseMessage) UnmarshalInit(suite abstract.Suite) *PromiseResponseMessage {
	msg.Response = new(promise.Response).UnmarshalInit(suite)
	return msg
}

// Compares two messages to see if they are equal
func (msg *PromiseResponseMessage) Equal(msg2 *PromiseResponseMessage) bool {
	return msg.ShareIndex == msg2.ShareIndex &&
	       msg.PromiserId == msg2.PromiserId &&
	       msg.Id == msg2.Id &&
	       msg.Response.Equal(msg2.Response)
}


/* Returns the number of bytes used by this struct when marshalled
 *
 * Returns
 *   The marshal size
 * Note
 *   Since promise.Response can be variable (it can contain acceptance or
 *   rejection messages), this can not be used before UnMarshalling.
 */
func (msg *PromiseResponseMessage) MarshalSize() int {
	return 4*uint32Size + len(msg.Id) + len(msg.PromiserId) + msg.Response.MarshalSize()
}

/* Marshals a CertifyPromiseMessage struct into a byte array
 *
 * Returns
 *   A buffer of the marshalled struct
 *   The error status of the marshalling (nil if no error)
 *
 * Note
 *   The buffer is formatted as follows:
 *
 *      ||Response_Size||ShareIndex||Response||
 *
 */
func (msg *PromiseResponseMessage) MarshalBinary() ([]byte, error) {
	buf := make([]byte, msg.MarshalSize())
	idLen  := len(msg.Id)
	promiserIdLen := len(msg.PromiserId)

	binary.LittleEndian.PutUint32(buf, uint32(idLen))
	binary.LittleEndian.PutUint32(buf[uint32Size:], uint32(promiserIdLen))
	binary.LittleEndian.PutUint32(buf[2*uint32Size:], uint32(msg.Response.MarshalSize()))
	binary.LittleEndian.PutUint32(buf[3*uint32Size:], uint32(msg.ShareIndex))

	copy(buf[4*uint32Size:], []byte(msg.Id))
	copy(buf[4*uint32Size + idLen:], []byte(msg.PromiserId))

	responseBuf, err := msg.Response.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(buf[4*uint32Size + idLen + promiserIdLen:], responseBuf)
	return buf, nil
}

/* Unmarshals a PromiseResponseMessage from a byte buffer
 *
 * Arguments
 *    buf = the buffer containing the Promise
 *
 * Returns
 *   The error status of the unmarshalling (nil if no error)
 */
func (msg *PromiseResponseMessage) UnmarshalBinary(buf []byte) error {
  
	promiseSize    := int(binary.LittleEndian.Uint32(buf))
	idLen          := int(binary.LittleEndian.Uint32(buf[uint32Size:]))
	promiserIdLen  := int(binary.LittleEndian.Uint32(buf[2*uint32Size:]))
	msg.ShareIndex  = int(binary.LittleEndian.Uint32(buf[3*uint32Size:]))

	// Decode pubKey and pubPoly
	bufPos      := 4*uint32Size
	msg.Id = string(buf[bufPos:bufPos+idLen])
	bufPos += idLen
	
	msg.PromiserId = string(buf[bufPos:bufPos+promiserIdLen])
	bufPos += promiserIdLen

	if err := msg.Response.UnmarshalBinary(buf[bufPos : bufPos+promiseSize]);
		err != nil {
		return err
	}
	return nil
}

/* Marshals a CertifyPromiseMessage struct using an io.Writer
 *
 * Arguments
 *    w = the writer to use for marshalling
 *
 * Returns
 *   The number of bytes written
 *   The error status of the write (nil if no errors)
 */
func (msg *PromiseResponseMessage) MarshalTo(w io.Writer) (int, error) {
	buf, err := msg.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return w.Write(buf)
}

/* Unmarshals a Promise struct using an io.Reader
 *
 * Arguments
 *    r = the reader to use for unmarshalling
 *
 * Returns
 *   The number of bytes read
 *   The error status of the read (nil if no errors)
 */
func (msg *PromiseResponseMessage) UnmarshalFrom(r io.Reader) (int, error) {
	// Retrieve responseSize to find the entire length of the message
	buf := make([]byte, 3*uint32Size)
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	responseLen := int(binary.LittleEndian.Uint32(buf))
	idLen          := int(binary.LittleEndian.Uint32(buf[uint32Size:]))
	promiserIdLen  := int(binary.LittleEndian.Uint32(buf[2*uint32Size:]))

	// Calculate the final buffer, copy the old data to it, and fill it
	// for unmarshalling
	finalLen := 4*uint32Size + idLen + promiserIdLen + responseLen
	finalBuf := make([]byte, finalLen)
	copy(finalBuf, buf)
	m, err := io.ReadFull(r, finalBuf[n:])
	if err != nil {
		return n + m, err
	}
	return n + m, msg.UnmarshalBinary(finalBuf)
}

/* Returns a string representation of the CertifyPromiseMessage for easy debugging
 *
 * Returns
 *   The CertifyPromiseMessage's string representation
 */
func (msg *PromiseResponseMessage) String()  string {
	s := "{PromiseResponseMessage:\n"
	s += "ShareIndex => " + strconv.Itoa(msg.ShareIndex) + ",\n"
	s += "PromiserId => " + msg.PromiserId + ",\n"
	s += "Id => " + msg.Id + ",\n"
	s += "Response => " + msg.Response.String() + "\n"
	s += "}\n"
	return s
}

