package coco

import (
	"fmt"
	"log"
	"strconv"
	"sync"
	"testing"

	"github.com/dedis/prifi/coconet"
	"github.com/dedis/prifi/timestamp"
)

func TestStaticMultipleClients(t *testing.T) {
	// should not use this until fields of signing node
	// are exported
	// nClients := 2
	// nMessages := 4 // per round
	// nRounds := 2

	// Crypto setup
	// suite := nist.NewAES128SHA256P256()
	// create new directory for communication between peers
	// dir := coco.NewGoDirectory()

	// TODO: add sn with TSServer functionality inside
	// create TSServer, clients
	// TSServer := NewTSServer("TSServer")
	// clients := createClientsForTSServer(nClients, TSServer, dir, 0)

	// go TSServer.Listen("test")
	// clientsTalk(clients, nRounds, nMessages, TSServer)
}

// Configuration file data/exconf.json
//       0
//      / \
//     1   4
//    / \   \
//   2   3   5
func TestTSSIntegration(t *testing.T) {
	nMessages := 1 // per round
	nRounds := 2

	hostConfig, err := LoadConfig("data/exconf.json")
	if err != nil {
		t.Fatal(err)
	}
	err = hostConfig.Run()
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	// Connect all TSServers to their clients, except for root TSServer
	ncps := 1 // # clients per TSServer
	for i, sn := range hostConfig.SNodes[1:] {
		go sn.ListenToClients("regular", nRounds)

		clients := createClientsForTSServer(ncps, sn,
			sn.Host.(*coconet.GoHost).GetDirectory(), 0+i*ncps)

		for _, client := range clients {
			go client.Listen()
			go client.ShowHistory()
		}

		wg.Add(1)
		go func(clients []*timestamp.Client, nRounds int, nMessages int, sn *SigningNode) {
			defer wg.Done()
			log.Println("clients Talk")
			clientsTalk(clients, nRounds, nMessages, sn)
			log.Println("Clients done Talking")
		}(clients, nRounds, nMessages, sn)

	}
	log.Println("listening to clients")
	go hostConfig.SNodes[0].ListenToClients("root", nRounds)
	log.Println("waiting for clients to be done")
	wg.Wait()
}

// Create nClients for the TSServer, with first client associated with number fClient
func createClientsForTSServer(nClients int, sn *SigningNode, dir *coconet.GoDirectory, fClient int) []*timestamp.Client {
	clients := make([]*timestamp.Client, 0, nClients)
	for i := 0; i < nClients; i++ {
		clients = append(clients, timestamp.NewClient("client"+strconv.Itoa(fClient+i), dir))

		// intialize TSServer conn to client
		ngc, err := coconet.NewGoConn(dir, sn.Name(), clients[i].Name())
		if err != nil {
			panic(err)
		}
		sn.clients[clients[i].Name()] = ngc

		// intialize client connection to sn
		ngc, err = coconet.NewGoConn(dir, clients[i].Name(), sn.Name())
		if err != nil {
			panic(err)
		}
		clients[i].Sns[sn.Name()] = ngc
	}

	return clients
}

func clientsTalk(clients []*timestamp.Client, nRounds, nMessages int, sn *SigningNode) {
	fmt.Println("clientsTalk to", sn.Name())
	// have client send messages
	for r := 0; r < nRounds; r++ {
		var wg sync.WaitGroup
		for _, client := range clients {
			fmt.Println("Here", client.Sns, client.Name())
			for i := 0; i < nMessages; i++ {
				// TODO: messages should be sent hashed eventually
				// TODO: add wait group around go time stamps
				messg := []byte("messg" + strconv.Itoa(r) + strconv.Itoa(i))
				wg.Add(1)
				go func(messg []byte, sn *SigningNode, i int) {
					defer wg.Done()
					log.Println("time stamping round: ", i)
					client.TimeStamp(messg, sn.Name())
					log.Println("returned from timestamp")
				}(messg, sn, r)
			}
		}
		// wait between rounds
		wg.Wait()
		log.Println("done with round: ", r)
	}
}
