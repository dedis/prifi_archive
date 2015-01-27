package time

import (
	"strconv"
	"testing"
	"time"

	"github.com/dedis/crypto/nist"
	"github.com/dedis/prifi/coco"
)

// Create nClients for the server, with first client associated with number fClient
func createClientsForServer(nClients int, server *Server, dir *coco.GoDirectory, fClient int) []*Client {
	clients := make([]*Client, 0, nClients)
	for i := 0; i < nClients; i++ {
		clients = append(clients, NewClient("client"+strconv.Itoa(fClient+i), dir))

		// intialize server conn to client
		ngc, err := coco.NewGoConn(dir, server.Name(), clients[i].Name())
		if err != nil {
			panic(err)
		}
		server.clients[clients[i].Name()] = ngc

		// intialize client connection to server
		ngc, err = coco.NewGoConn(dir, clients[i].Name(), server.Name())
		if err != nil {
			panic(err)
		}
		clients[i].servers[server.Name()] = ngc

		go clients[i].Listen()
		go clients[i].showHistory()
	}

	return clients
}

func TestStaticMultipleClients(t *testing.T) {
	nClients := 2
	nMessages := 4 // per round
	nRounds := 2

	// Crypto setup
	suite := nist.NewAES128SHA256P256()
	// create new directory for communication between peers
	dir := coco.NewGoDirectory()

	// create server, clients
	server := NewServer("server", dir, suite)
	clients := createClientsForServer(nClients, server, dir, 0)

	isRoot := true
	go server.Listen(isRoot)

	// have client send messages
	for r := 0; r < nRounds; r++ {
		for _, client := range clients {

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

// Configuration file data/exconf.json
//       0
//      / \
//     1   4
//    / \   \
//   2   3   5
func TestTreeFromStaticConfig(t *testing.T) {
	return
	hostConfig, err := coco.LoadConfig("data/exconf.json")
	if err != nil {
		t.Fatal(err)
	}
	err = hostConfig.Run()
	if err != nil {
		t.Fatal(err)
	}

	// create servers
	nServers := len(hostConfig.SNodes)
	servers := make([]*Server, 0, nServers)
	for i, sn := range hostConfig.SNodes {
		server := &Server{name: "server" + strconv.Itoa(i)}
		server.SigningNode = *sn
		servers = append(servers, server)

	}
	// Have root node initiate the signing protocol
	// via a simple annoucement
	hostConfig.SNodes[0].LogTest = []byte("Hello World")
	hostConfig.SNodes[0].Announce(&coco.AnnouncementMessage{hostConfig.SNodes[0].LogTest})
}
