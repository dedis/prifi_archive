package time

import (
	"strconv"
	"testing"
	"time"

	"github.com/dedis/crypto/nist"
	"github.com/dedis/prifi/coco"
)

func TestStaticMultipleClients(t *testing.T) {
	nClients := 10
	nMessages := 4 // per round
	nRounds := 5

	// Crypto setup
	suite := nist.NewAES128SHA256P256()
	// create new directory for communication between peers
	dir := coco.NewGoDirectory()

	// create server, clients
	server := NewServer("server", dir, suite)
	client := make([]*Client, 0, nClients)
	for i := 0; i < nClients; i++ {
		client = append(client, NewClient("client"+strconv.Itoa(i), dir))

		// intialize server conn to client
		ngc, err := coco.NewGoConn(dir, server.Name(), client[i].Name())
		if err != nil {
			panic(err)
		}
		server.clients[client[i].Name()] = ngc

		// intialize client connection to server
		ngc, err = coco.NewGoConn(dir, client[i].Name(), server.Name())
		if err != nil {
			panic(err)
		}
		client[i].servers[server.Name()] = ngc

		go client[i].Listen()
		go client[i].showHistory()
	}

	go server.Listen()

	// have client send messages
	for r := 0; r < nRounds; r++ {
		for _, client := range client {

			for i := 0; i < nMessages; i++ {
				// TODO: messages should be sent hashed eventually
				messg := []byte("messg" + strconv.Itoa(r) + strconv.Itoa(i))
				go client.TimeStamp(messg, server.Name())

			}
		}
		// wait between rounds
		time.Sleep(3 * time.Second)
	}
}
