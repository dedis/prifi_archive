package coco

import (
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/dedis/prifi/coconet"
	"github.com/dedis/prifi/timestamp"
)

// Configuration file data/exconf.json
//       0
//      / \
//     1   4
//    / \   \
//   2   3   5
func TestTSSIntegration(t *testing.T) {
	nMessages := 4 // per round
	nRounds := 3

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
	ncps := 3 // # clients per TSServer
	clientsLists := make([][]*timestamp.Client, len(hostConfig.SNodes[1:]))
	for i, sn := range hostConfig.SNodes[1:] {
		clientsLists[i] = createClientsForTSServer(ncps, sn,
			sn.Host.(*coconet.GoHost).GetDirectory(), 0+i+ncps)
	}
	for i, sn := range hostConfig.SNodes[1:] {
		go sn.ListenToClients("regular", nRounds)

		// clients := createClientsForTSServer(ncps, sn,
		// 	sn.Host.(*coconet.GoHost).GetDirectory(), 0+i*ncps)

		for _, client := range clientsLists[i] {
			go client.Listen()
			go client.ShowHistory()
		}
		wg.Add(1)
		go func(clients []*timestamp.Client, nRounds int, nMessages int, sn *SigningNode) {
			defer wg.Done()
			// log.Println("clients Talk")
			clientsTalk(clients, nRounds, nMessages, sn)
			// log.Println("Clients done Talking")
		}(clientsLists[i], nRounds, nMessages, sn)

	}
	go hostConfig.SNodes[0].ListenToClients("root", nRounds)
	wg.Wait()

	// After clients receive messages back we need a better way
	// of waiting to make sure servers check ElGamal sigs
	time.Sleep(1 * time.Second)
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
	// have client send messages
	for r := 0; r < nRounds; r++ {
		var wg sync.WaitGroup
		for _, client := range clients {
			for i := 0; i < nMessages; i++ {
				// TODO: messages should be sent hashed eventually
				messg := []byte("messg" + strconv.Itoa(r) + strconv.Itoa(i))
				wg.Add(1)
				go func(client *timestamp.Client, messg []byte, sn *SigningNode, i int) {
					defer wg.Done()
					client.TimeStamp(messg, sn.Name())
				}(client, messg, sn, r)
			}
		}
		// wait between rounds
		wg.Wait()
		// time.Sleep(1 * time.Second)
	}
}
