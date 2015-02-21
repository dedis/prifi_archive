package net

/*
This file exports the Message type for multicast. It is based on python/net/message.py.
Native structs in Go mean we don't have to do the struct <==> dictionary transformation.
We can use a single protobuf to represent all messages and use Encode/Decode to send over the wire.
*/

import (
	"github.com/dedis/protobuf"
)

// Message types
type MType uint32

const (
	NIL MType = iota
	RELAY_DOWNSTREAM
	RELAY_TNEXT
	CLIENT_UPSTREAM
	CLIENT_ACK
	CLIENT_CONNECT
	TRUSTEE_CONNECT
	AP_CONNECT
	AP_DOWNSTREAM
	AP_PING
)

type Message struct {
	MessageType MType  // type of message
	ConnNo      int32  // connection number
	Next        uint32 // next slot
	MessageId   int32  // message id
	Node        int32  //node identification number
	AccessPt    int32  // access point index
	RelayMType  int32  // type of message being forwarded
	Data        []byte // variable length data
}

// Wrappers around Pack / Unpack
func Pack(m *Message) (data []byte, err error) {
	data, err = protobuf.Encode(m)
	return
}

func Unpack(data []byte) (m Message, err error) {
	err = protobuf.Decode(data, &m)
	return
}
