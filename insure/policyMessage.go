/* Modelled off coco/sign/signingMessage.go, this file is defines messages
 * used in the insurance policy protocol.
 */
package insure

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strconv"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/poly/promise"
)

// PolicyMessageType lists the different types of messages that can be sent.
type PolicyMessageType int
const (
	Error PolicyMessageType = iota
	
	// Sent by servers to insurers to request that they certify a promise.
	CertifyPromise
	
	// The response an insurer sends for a CertifyPromise request. It can
	// either express approval or rejection of a promise.
	PromiseResponse
	
	// Servers use this message to send one of its promises to a client.
	PromiseToClient
	
	// Clients send this message to insurers to request that they reveal
	// their secret share for a promise.
	ShareRevealRequest
	
	// Insurers respond to a client's ShareRevealRequest with this message.
	ShareRevealResponse
	
	// Insurers send this "ping" message to servers to see if they are alive.
	ServerAliveRequest
	
	// Servers respond to an insurer's are-you-alive ping with this message.
	ServerAliveResponse
)

/* PolicyMessage is a union struct of the different types of messages used by
 * the life policy protocol. It provides a convenient way for sending and
 * receiving messages.
 *
 * To create a new message, simply set the Type field and assign the corresponding
 * message field. The name of the message to set corresponds nicely with the
 * message type.
 *
 * Note: Each PolicyMessage should only contain one type of message.
 */
type PolicyMessage struct {
	
	Type PolicyMessageType
	
	CertifyPromiseMsg      *CertifyPromiseMessage	
	PromiseResponseMsg     *PromiseResponseMessage
	
	// Simply include the promise itself. No additional info is needed.
	PromiseToClientMsg     *promise.Promise

	ShareRevealRequestMsg  *PromiseShareMessage
	ShareRevealResponseMsg *PromiseShareMessage
	
	// Since ServerAliveRequest and ServerAliveResponse messages are
	// merely pings, no unique messages needs to be set. Simply set
	// PolicyMessageType appropriately.
}

/* Initializes a PolicyMessage for unmarshalling.
 *
 * Arguments
 *   t, r, n = parameters for promises sent within messages. See crypto/poly/promise
 *             for more information.
 *   suite   = the suite of the keys used in the messages.
 *
 * Returns
 *   a PolicyMessage ready for unmarshalling.
 */
func (pm *PolicyMessage) UnmarshalInit(t,r,n int, suite abstract.Suite) *PolicyMessage{
	pm.CertifyPromiseMsg      = new(CertifyPromiseMessage).UnmarshalInit(t,r,n, suite)
	pm.PromiseResponseMsg     = new(PromiseResponseMessage).UnmarshalInit(suite)
	pm.PromiseToClientMsg     = new(promise.Promise).UnmarshalInit(t,r,n, suite)
	pm.ShareRevealRequestMsg  = new(PromiseShareMessage).UnmarshalInit(suite)
	pm.ShareRevealResponseMsg = new(PromiseShareMessage).UnmarshalInit(suite)
	return pm
}

// Marshalls a PolicyMessage for sending over the internet
func (pm *PolicyMessage) MarshalBinary() ([]byte, error) {
	var b bytes.Buffer
	var sub []byte
	var err error
	b.WriteByte(byte(pm.Type))
	switch pm.Type {
		case CertifyPromise:
			sub, err = pm.CertifyPromiseMsg.MarshalBinary()
		case PromiseResponse:
			sub, err = pm.PromiseResponseMsg.MarshalBinary()
		case PromiseToClient:
			sub, err = pm.PromiseToClientMsg.MarshalBinary()
		case ShareRevealRequest:
			sub, err = pm.ShareRevealRequestMsg.MarshalBinary()
		case ShareRevealResponse:
			sub, err = pm.ShareRevealResponseMsg.MarshalBinary()
		case ServerAliveRequest:
		case ServerAliveResponse:
		        sub = make([]byte, 0, 0)
		        err = nil
	}
	if err == nil {
		b.Write(sub)
	}
	return b.Bytes(), err
}

// Unmarshalls a PolicyMessage received.
func (pm *PolicyMessage) UnmarshalBinary(data []byte) error {
	pm.Type = PolicyMessageType(data[0])
	msgBytes := data[1:]
	var err error
	switch pm.Type {
		case CertifyPromise:
			err    = pm.CertifyPromiseMsg.UnmarshalBinary(msgBytes)
		case PromiseResponse:
			err    = pm.PromiseResponseMsg.UnmarshalBinary(msgBytes)
		case PromiseToClient:
			err    = pm.PromiseToClientMsg.UnmarshalBinary(msgBytes)
		case ShareRevealRequest:
			err    = pm.ShareRevealRequestMsg.UnmarshalBinary(msgBytes)
		case ShareRevealResponse:
			err    = pm.ShareRevealResponseMsg.UnmarshalBinary(msgBytes)
		case ServerAliveRequest:
		case ServerAliveResponse:
			err    = nil
	}
	return err
}

/*********************************** Messages *********************************/

// Used mostly in marshalling code, this is the size of a uint32
var uint32Size int = binary.Size(uint32(0))


/***************************** CertifyPromiseMessage ***************************/

/* CertifyPromiseMessage are sent by servers to insurers to request that they
 * certify a promise.
 */
type CertifyPromiseMessage struct {
	// The index of the share to certify.
	ShareIndex int

	// The promise to be insured.
	Promise promise.Promise
}

/* Initializes a CertifyPromiseMessage for unmarshalling.
 *
 * Arguments
 *   t, r, n = parameters for promises sent within messages. See crypto/poly/promise
 *             for more information.
 *   suite   = the suite of the keys used within the Promise.
 *
 * Returns
 *   An initialized Promise ready to be unmarshalled.
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


// Returns the number of bytes used by this struct when marshalled
func (msg *CertifyPromiseMessage) MarshalSize() int {
	return uint32Size + msg.Promise.MarshalSize()
}

/* Marshals a CertifyPromiseMessage struct into a byte array
 *
 * The buffer is formatted as follows:
 *
 *      ||ShareIndex||Promise||
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

// Unmarshals a CertifyPromiseMessage from a byte buffer
func (msg *CertifyPromiseMessage) UnmarshalBinary(buf []byte) error {

	if len(buf) < msg.MarshalSize() {
		return errors.New("Buffer size too small")
	}

	msg.ShareIndex = int(binary.LittleEndian.Uint32(buf))

	bufPos      := uint32Size
	promiseSize := msg.Promise.MarshalSize()
	err := msg.Promise.UnmarshalBinary(buf[bufPos : bufPos+promiseSize])
	if err != nil {
		return err
	}
	return nil
}

// Marshals a CertifyPromiseMessage struct using an io.Writer
func (msg *CertifyPromiseMessage) MarshalTo(w io.Writer) (int, error) {
	buf, err := msg.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return w.Write(buf)
}

// Unmarshals a Promise struct using an io.Reader
func (msg *CertifyPromiseMessage) UnmarshalFrom(r io.Reader) (int, error) {
	buf := make([]byte, msg.MarshalSize())
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	return n , msg.UnmarshalBinary(buf)
}

// Returns a string representation of the CertifyPromiseMessage for debugging
func (msg *CertifyPromiseMessage) String()  string {
	s := "{CertifyPromiseMessage:\n"
	s += "ShareIndex => " + strconv.Itoa(msg.ShareIndex) + ",\n"
	s += "Promise => " + msg.Promise.String() + "\n"
	s += "}\n"
	return s
}


/**************************** PromiseResponseMessage **************************/

/* PromiseResponseMessage are used by insurers to express approval or rejection
 * of a promise. 
 */
type PromiseResponseMessage struct {

	// The index of the share being approved or rejected
	ShareIndex int

	// The id of the server who created the promise
	// aka. promise.PromiserId()
	PromiserId string

	// The id of the promise itself
	// aka. promise.Id()
	Id string

	// The insurer's response
	Response *promise.Response
}

// Initializes a PromiseResponseMessage for unmarshalling
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
 * Note
 *   Since PromiseResponseMessage's contain variable length fields, this method
 *   can not be called before unmarshalling.
 */
func (msg *PromiseResponseMessage) MarshalSize() int {
	return 4*uint32Size + len(msg.Id) + len(msg.PromiserId) + msg.Response.MarshalSize()
}

/* Marshals a PromiseResponseMessage struct into a byte array
 *
 * The buffer is formatted as follows:
 *
 *   ||Id_len||PromiserId_len||Response_len||ShareIndex||Id||PromiserId||Response||
 *
 */
func (msg *PromiseResponseMessage) MarshalBinary() ([]byte, error) {
	buf := make([]byte, msg.MarshalSize())
	idLen         := len(msg.Id)
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

// Unmarshals a PromiseResponseMessage from a byte buffer
func (msg *PromiseResponseMessage) UnmarshalBinary(buf []byte) error {
  	if len(buf) < 4*uint32Size {
		return errors.New("Buffer size too small")
	}  
	idLen          := int(binary.LittleEndian.Uint32(buf))
	promiserIdLen  := int(binary.LittleEndian.Uint32(buf[uint32Size:]))
	responseSize   := int(binary.LittleEndian.Uint32(buf[2*uint32Size:]))
	msg.ShareIndex  = int(binary.LittleEndian.Uint32(buf[3*uint32Size:]))

 	if len(buf) < 4*uint32Size + idLen + promiserIdLen + responseSize {
		return errors.New("Buffer size too small")
	}

	bufPos      := 4*uint32Size
	msg.Id = string(buf[bufPos:bufPos+idLen])
	bufPos += idLen
	
	msg.PromiserId = string(buf[bufPos:bufPos+promiserIdLen])
	bufPos += promiserIdLen

	err := msg.Response.UnmarshalBinary(buf[bufPos : bufPos+responseSize])
	if err != nil {
		return err
	}
	return nil
}

// Marshals a PromiseResponseMessage struct using an io.Writer
func (msg *PromiseResponseMessage) MarshalTo(w io.Writer) (int, error) {
	buf, err := msg.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return w.Write(buf)
}

// Unmarshals a Promise struct using an io.Reader
func (msg *PromiseResponseMessage) UnmarshalFrom(r io.Reader) (int, error) {
	// Retrieve the length of the variable-length fields to calculate the
	// total buffer size
	buf := make([]byte, 3*uint32Size)
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	idLen          := int(binary.LittleEndian.Uint32(buf))
	promiserIdLen  := int(binary.LittleEndian.Uint32(buf[uint32Size:]))
	responseLen    := int(binary.LittleEndian.Uint32(buf[2*uint32Size:]))

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

// Returns a string representation of the PromiseResponseMessage for debugging
func (msg *PromiseResponseMessage) String()  string {
	s := "{PromiseResponseMessage:\n"
	s += "ShareIndex => " + strconv.Itoa(msg.ShareIndex) + ",\n"
	s += "PromiserId => " + msg.PromiserId + ",\n"
	s += "Id => " + msg.Id + ",\n"
	s += "Response => " + msg.Response.String() + "\n"
	s += "}\n"
	return s
}


/**************************** PromiseShareMessage **************************/

/* PromiseShareMessage's are used for both RevealShareRequests and 
 * RevealShareResponses. Clients can use this message to send requests to
 * insurers to reveal a share. Insurers can use this message to send back the
 * share.
 *
 * Since creating this struct is more complicated than with the others,
 * initialization methods are provided.
 *
 * Note: Whether the message is a request or response is determined by whether
 * the share is nil (nil for request, defined for response). Make sure that this
 * holds.
 */
type PromiseShareMessage struct {

	// The index of the share to be revealed
	ShareIndex int

	// A string of the long term public key of the promiser.
	PromiserId string

	// A string of the public key of the secret promised.
	Id string
	
	// The reason why the client is requesting the share. For more info,
	// see the documentation in lifePolicy.go for the verifyServerAlive
	// function.
	// This is nil for responses but defined for requests
	Reason string

	// The secret share of the insurer for responses, nil for requests.
	Share abstract.Secret
}

/* Creates a new PromiseShareMessage to be used for RevealShareRequests
 *
 * Arguments:
 *	shareIndex  = the index of the share to be revealed.
 *      reason      = the reason why the client is requesting the share to be
 *                    revealed.
 *      promise     = the promise holding the secret that is attempting to be
 *                    reconstructed.
 *
 * Returns:
 *	A new PromiseShareMessage
 */
func (msg *PromiseShareMessage) createRequestMessage(shareIndex int, reason string,
	promise promise.Promise) *PromiseShareMessage {
	msg.Id         = promise.Id()
	msg.PromiserId = promise.PromiserId()
	msg.ShareIndex = shareIndex
	msg.Reason     = reason
	msg.Share      = nil
	return msg
}

/* Creates a new PromiseShareMessage to be used for RevealShareResponses
 *
 * Arguments:
 *	shareIndex  = the index of the share to be revealed.
 *      promise     = the promise holding the secret that is attempting to be
 *                    reconstructed.
 *      share       = the revealed share
 *
 * Returns:
 *	A new PromiseShareMessage
 */
func (msg *PromiseShareMessage) createResponseMessage(shareIndex int,
	promise promise.Promise, share abstract.Secret) *PromiseShareMessage {
	msg.Id         = promise.Id()
	msg.PromiserId = promise.PromiserId()
	msg.ShareIndex = shareIndex
	msg.Share      = share
	return msg
}

// Initializes a PromiseShareMessage for unmarshalling
func (msg *PromiseShareMessage) UnmarshalInit(suite abstract.Suite) *PromiseShareMessage {
	msg.Share = suite.Secret()
	return msg
}

/* Compares two messages to see if they are equal
 *
 * Note: Requests should have msg.Share set to nil. Responses should have msg.Share
 * defined.
 */
func (msg *PromiseShareMessage) Equal(msg2 *PromiseShareMessage) bool {
	return msg.ShareIndex == msg2.ShareIndex &&
	       msg.PromiserId == msg2.PromiserId &&
	       msg.Id == msg2.Id &&
	       msg.Reason == msg2.Reason &&
	       (msg.Share == nil && msg2.Share == nil ||
	          (msg.Share != nil && msg2.Share != nil &&
	            msg.Share.Equal(msg2.Share)))
}


/* Returns the number of bytes used by this struct when marshalled
 *
 * Note
 *   Since PromiseShareMessage contains variable fields, this can't be used before
 *   unmarshalling.
 */
func (msg *PromiseShareMessage) MarshalSize() int {
	shareSize := 0
	if msg.Share != nil {
		shareSize = msg.Share.MarshalSize()
	}	
	return 5*uint32Size + len(msg.Id) + len(msg.PromiserId) + len(msg.Reason) + shareSize
}

/* Marshals a PromiseResponseMessage struct into a byte array
 *
 * Note
 *   The buffer is formatted as follows:
 *
 *   ||Id_len||PromiserId_len||Reason_len||Share_len||ShareIndex||Id||PromiserId||Reason||Share||
 *
 */
func (msg *PromiseShareMessage) MarshalBinary() ([]byte, error) {
	buf := make([]byte, msg.MarshalSize())
	idLen  := len(msg.Id)
	promiserIdLen := len(msg.PromiserId)
	reasonLen     := len(msg.Reason)
	shareSize := 0
	if msg.Share != nil {
		shareSize = msg.Share.MarshalSize()
	}

	binary.LittleEndian.PutUint32(buf, uint32(idLen))
	binary.LittleEndian.PutUint32(buf[uint32Size:], uint32(promiserIdLen))
	binary.LittleEndian.PutUint32(buf[2*uint32Size:], uint32(reasonLen))
	binary.LittleEndian.PutUint32(buf[3*uint32Size:], uint32(shareSize))
	binary.LittleEndian.PutUint32(buf[4*uint32Size:], uint32(msg.ShareIndex))

	copy(buf[5*uint32Size:], []byte(msg.Id))
	copy(buf[5*uint32Size + idLen:], []byte(msg.PromiserId))
	copy(buf[5*uint32Size + idLen + promiserIdLen:], []byte(msg.Reason))

	if msg.Share != nil {
		shareBuf, err := msg.Share.MarshalBinary()
		if err != nil {
			return nil, err
		}
		copy(buf[5*uint32Size + idLen + promiserIdLen + reasonLen:], shareBuf)
	}
	return buf, nil
}

// Unmarshals a PromiseResponseMessage from a byte buffer
func (msg *PromiseShareMessage) UnmarshalBinary(buf []byte) error {  
  	if len(buf) < 5*uint32Size {
		return errors.New("Buffer size too small")
	}
  
	idLen          := int(binary.LittleEndian.Uint32(buf))
	promiserIdLen  := int(binary.LittleEndian.Uint32(buf[uint32Size:]))
	reasonLen      := int(binary.LittleEndian.Uint32(buf[2*uint32Size:]))
	shareSize      := int(binary.LittleEndian.Uint32(buf[3*uint32Size:]))
	msg.ShareIndex  = int(binary.LittleEndian.Uint32(buf[4*uint32Size:]))

 	if len(buf) < 5*uint32Size + idLen + promiserIdLen + reasonLen + shareSize {
		return errors.New("Buffer size too small")
	}

	bufPos      := 5*uint32Size
	msg.Id = string(buf[bufPos:bufPos+idLen])
	bufPos += idLen
	
	msg.PromiserId = string(buf[bufPos:bufPos+promiserIdLen])
	bufPos += promiserIdLen

	msg.Reason = string(buf[bufPos:bufPos+reasonLen])
	bufPos += reasonLen

	if shareSize == 0 {
		msg.Share = nil
	} else if err := msg.Share.UnmarshalBinary(buf[bufPos : bufPos+shareSize]);
		err != nil {
		return err
	}
	return nil
}

// Marshals a CertifyPromiseMessage struct using an io.Writer
func (msg *PromiseShareMessage) MarshalTo(w io.Writer) (int, error) {
	buf, err := msg.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return w.Write(buf)
}

// Unmarshals a Promise struct using an io.Reader
func (msg *PromiseShareMessage) UnmarshalFrom(r io.Reader) (int, error) {
	// Retrieve size of variable length fields to calculate the total size
	buf := make([]byte, 4*uint32Size)
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	idLen          := int(binary.LittleEndian.Uint32(buf))
	promiserIdLen  := int(binary.LittleEndian.Uint32(buf[uint32Size:]))
	reasonLen      := int(binary.LittleEndian.Uint32(buf[2*uint32Size:]))
	shareSizeLen   := int(binary.LittleEndian.Uint32(buf[3*uint32Size:]))

	// Calculate the final buffer, copy the old data to it, and fill it
	// for unmarshalling
	finalLen := 5*uint32Size + idLen + promiserIdLen + reasonLen + shareSizeLen
	finalBuf := make([]byte, finalLen)
	copy(finalBuf, buf)
	m, err := io.ReadFull(r, finalBuf[n:])
	if err != nil {
		return n + m, err
	}
	return n + m, msg.UnmarshalBinary(finalBuf)
}

// Returns a string representation of the CertifyPromiseMessage for debugging
func (msg *PromiseShareMessage) String()  string {
	shareString := "None"
	if msg.Share != nil {
		shareString = msg.Share.String()
	}
	s := "{PromiseShareMessage:\n"
	s += "ShareIndex => " + strconv.Itoa(msg.ShareIndex) + ",\n"
	s += "PromiserId => " + msg.PromiserId + ",\n"
	s += "Id => " + msg.Id + ",\n"
	s += "Reason => " + msg.Reason + ",\n"
	s += "Share => " + shareString + "\n"
	s += "}\n"
	return s
}

