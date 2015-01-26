package dcnet

import (
	"crypto/cipher"
	"github.com/dedis/crypto/abstract"
)

type simpleCoder struct {
	suite abstract.Suite

	// Pseudorandom DC-nets streams shared with each peer.
	// On clients, there is one DC-nets stream per trustee.
	// On trustees, there ois one DC-nets stream per client.
	dcstreams []cipher.Stream

	xorbuf []byte
}

// Simple DC-net encoder providing no disruption or equivocation protection,
// for experimentation and baseline performance evaluations.
func SimpleCoderFactory() CellCoder {
	return new(simpleCoder)
}


///// Client methods /////

func (c *simpleCoder) ClientCellSize(payloadlen int) int {
	return payloadlen	// no expansion
}

func (c *simpleCoder) ClientSetup(suite abstract.Suite,
				peerstreams []cipher.Stream) {
	c.suite = suite

	// Use the provided master streams to seed
	// a pseudorandom DC-nets substream shared with each peer.
	npeers := len(peerstreams)
	c.dcstreams = make([]cipher.Stream, npeers)
	for j := range(peerstreams) {
		// next 3 lines copied from old SubStream code in d167467
		key := make([]byte, suite.Cipher(nil).KeySize())
		peerstreams[j].XORKeyStream(key, key)
		c.dcstreams[j] = suite.Cipher(key)
	}
}

func (c *simpleCoder) ClientEncode(payload []byte, payloadlen int,
				histoream cipher.Stream) []byte {

	if payload == nil {
		payload = make([]byte, payloadlen)
	}
	for i := range(c.dcstreams) {
		c.dcstreams[i].XORKeyStream(payload, payload)
	}
	return payload
}


///// Trustee methods /////

func (c *simpleCoder) TrusteeCellSize(payloadlen int) int {
	return payloadlen	// no expansion
}

func (c *simpleCoder) TrusteeSetup(suite abstract.Suite,
				peerstreams []cipher.Stream) []byte {
	c.ClientSetup(suite, peerstreams)	// no difference
	return nil
}

func (c *simpleCoder) TrusteeEncode(payloadlen int) []byte {
	return c.ClientEncode(nil, payloadlen, nil)	// no difference
}


///// Relay methods /////

func (c *simpleCoder) RelaySetup(suite abstract.Suite, trusteeinfo [][]byte) {
	// nothing to do
}

func (c *simpleCoder) DecodeStart(payloadlen int, histoream cipher.Stream) {

	c.xorbuf = make([]byte, payloadlen)
}

func (c *simpleCoder) DecodeClient(slice []byte) {

	for i := range slice {
		c.xorbuf[i] ^= slice[i]
	}
}

func (c *simpleCoder) DecodeTrustee(slice []byte) {

	c.DecodeClient(slice)	// same
}

func (c *simpleCoder) DecodeCell() []byte {

	return c.xorbuf
}

