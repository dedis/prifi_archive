package time

import (
	"strconv"
	"testing"
	"time"

	"github.com/dedis/crypto/nist"
	"github.com/dedis/prifi/coco"
)

func TestStatic(t *testing.T) {
	// Crypto setup
	suite := nist.NewAES128SHA256P256()
	// rand := suite.Cipher([]byte("example"))

	// create new directory for communication between peers
	dir := coco.NewGoDirectory()

	// create server,client
	server := NewServer("server", dir, suite)
	client := NewClient("client0", dir)

	// intialize server
	ngc, err := coco.NewGoConn(dir, server.Name(), client.Name())
	if err != nil {
		panic(err)
	}
	server.clients[client.Name()] = ngc

	// intialize client
	ngc, err = coco.NewGoConn(dir, client.Name(), server.Name())
	if err != nil {
		panic(err)
	}
	client.servers[server.Name()] = ngc

	// start listening
	go server.Listen()
	go client.Listen()
	go client.showHistory()

	// have client send messages
	nMessages := 4
	nRounds := 2
	for r := 0; r < nRounds; r++ {
		for i := 0; i < nMessages; i++ {
			// TODO: messages should be sent hashed eventually
			messg := []byte("messg" + strconv.Itoa(r) + strconv.Itoa(i))
			go client.TimeStamp(messg, server.Name())

		}
		time.Sleep(3 * time.Second)
	}
	time.Sleep(15 * time.Second)
}
