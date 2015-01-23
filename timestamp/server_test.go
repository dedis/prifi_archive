package time

import (
	"testing"
	"time"

	"github.com/dedis/prifi/coco"
)

//      server-node
//       /
//  client node
func TestStatic(t *testing.T) {
	// Crypto setup
	// suite := nist.NewAES128SHA256P256()
	// rand := suite.Cipher([]byte("example"))

	// create new directory for communication between peers
	dir := coco.NewGoDirectory()

	server := NewServer("server", dir)
	client := NewClient("client0", dir)

	ngc, err := coco.NewGoConn(dir, server.Name(), client.Name())
	if err != nil {
		panic(err)
	}
	server.clients[client.Name()] = ngc

	ngc, err = coco.NewGoConn(dir, client.Name(), server.Name())
	if err != nil {
		panic(err)
	}
	client.servers[server.Name()] = ngc

	go server.Listen()
	client.Put(server.Name(),
		&TimeStampMessage{
			Type: StampRequestType,
			sreq: &StampRequest{Val: []byte("hello world")}})

	time.Sleep(3 * time.Second)
}
