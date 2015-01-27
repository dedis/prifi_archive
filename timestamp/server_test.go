package time

import (
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/dedis/prifi/coco"
)

// Create nClients for the TSServer, with first client associated with number fClient
func createClientsForTSServer(nClients int, TSServer *TSServer, dir *coco.GoDirectory, fClient int) []*Client {
	clients := make([]*Client, 0, nClients)
	for i := 0; i < nClients; i++ {
		clients = append(clients, NewClient("client"+strconv.Itoa(fClient+i), dir))

		// intialize TSServer conn to client
		ngc, err := coco.NewGoConn(dir, TSServer.Name(), clients[i].Name())
		if err != nil {
			panic(err)
		}
		TSServer.clients[clients[i].Name()] = ngc

		// intialize client connection to TSServer
		ngc, err = coco.NewGoConn(dir, clients[i].Name(), TSServer.Name())
		if err != nil {
			panic(err)
		}
		clients[i].TSServers[TSServer.Name()] = ngc

		go clients[i].Listen()
		go clients[i].showHistory()
	}

	return clients
}

func clientsTalk(clients []*Client, nRounds, nMessages int, TSServer *TSServer) {
	fmt.Println("clientsTalk to", TSServer.Name())
	// have client send messages
	for r := 0; r < nRounds; r++ {
		for _, client := range clients {
			fmt.Println(client.TSServers, client.name)

			for i := 0; i < nMessages; i++ {
				// TODO: messages should be sent hashed eventually
				messg := []byte("messg" + strconv.Itoa(r) + strconv.Itoa(i))
				go client.TimeStamp(messg, TSServer.Name())

			}
		}
		// wait between rounds
		time.Sleep(3 * time.Second)
	}
}

func TestStaticMultipleClients(t *testing.T) {
	// should not use this until fields of signing node
	// are exported
	return
	nClients := 2
	nMessages := 4 // per round
	nRounds := 2

	// Crypto setup
	// suite := nist.NewAES128SHA256P256()
	// create new directory for communication between peers
	dir := coco.NewGoDirectory()

	// create TSServer, clients
	TSServer := NewTSServer("TSServer")
	// TODO: add sn to TSServer with dir and suite, once sn exported
	clients := createClientsForTSServer(nClients, TSServer, dir, 0)

	go TSServer.Listen("test")
	clientsTalk(clients, nRounds, nMessages, TSServer)
}

// Configuration file data/exconf1.json
//       0
//      / \
//     1   2
func TestTreeFromStaticConfig(t *testing.T) {
	nMessages := 4 // per round
	nRounds := 1

	hostConfig, err := coco.LoadConfig("data/exconf1.json")
	if err != nil {
		t.Fatal(err)
	}
	err = hostConfig.Run()
	if err != nil {
		t.Fatal(err)
	}

	// create TSServers and clients
	nTSServers := len(hostConfig.SNodes)
	TSServers := make([]*TSServer, 0, nTSServers)
	for i, sn := range hostConfig.SNodes {
		TSServer := NewTSServer("TSServer" + strconv.Itoa(i))
		TSServer.sn = sn
		TSServers = append(TSServers, TSServer)
	}

	// Connect all TSServers to their clients, except for root TSServer
	ncps := 1 // # clients per TSServer
	for i := 1; i < nTSServers; i++ {
		TSServers[i].Listen("regular")

		clients := createClientsForTSServer(ncps, TSServers[i],
			TSServers[i].sn.Host.(*coco.GoHost).GetDirectory(), 0+i*ncps)

		clientsTalk(clients, nRounds, nMessages, TSServers[i])
	}

	TSServers[0].Listen("root")
	// Have root node initiate the signing protocol
	// via a simple annoucement
	// hostConfig.SNodes[0].LogTest = []byte("Hello World")
	// hostConfig.SNodes[0].Announce(&coco.AnnouncementMessage{hostConfig.SNodes[0].LogTest})
}
