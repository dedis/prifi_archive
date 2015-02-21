package net

import (
	"bytes"
	"testing"
)

func TestUnpack(t *testing.T) {
	m := Message{MessageType: 0, ConnNo: 1, Data: []byte{0, 1, 0, 2}}
	data, err := Pack(&m)
	if err != nil {
		t.Error("Unable to encode message, error ", err)
	}
	k, err := Unpack(data)
	if err != nil {
		t.Error("Unable to decode message, error ", err)
	}
	if m.MessageType != k.MessageType ||
		m.ConnNo != k.ConnNo ||
		!bytes.Equal(m.Data, k.Data) {
		t.Error("Decoded message incorrect")
	}
}
