package stamp_test

import (
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	log "github.com/Sirupsen/logrus"

	_ "github.com/dedis/prifi/coco"
	"github.com/dedis/prifi/coco/coconet"
	"github.com/dedis/prifi/coco/sign"
	"github.com/dedis/prifi/coco/stamp"
	"github.com/dedis/prifi/coco/test/oldconfig"
)

// func init() {
// 	log.SetFlags(log.Lshortfile)
// 	//log.SetOutput(ioutil.Discard)
// }

// Configuration file data/exconf.json
//       0
//      / \
//     1   4
//    / \   \
//   2   3   5
func TestTSSIntegration(t *testing.T) {
	nMessages := 4 // per round
	nRounds := 3

	hostConfig, err := oldconfig.LoadConfig("../test/data/exconf.json")
	if err != nil {
		t.Fatal(err)
	}
	err = hostConfig.Run(sign.MerkleTree)
	if err != nil {
		t.Fatal(err)
	}

	// Connect all TSServers to their clients, except for root TSServer
	ncps := 3 // # clients per TSServer
	stampers := make([]*stamp.Server, len(hostConfig.SNodes))
	for i := range stampers {
		stampers[i] = stamp.NewServer(hostConfig.SNodes[i])
	}

	clientsLists := make([][]*stamp.Client, len(hostConfig.SNodes[1:]))
	for i, s := range stampers[1:] {
		clientsLists[i] = createClientsForTSServer(ncps, s, hostConfig.Dir, 0+i+ncps)
	}

	var wg sync.WaitGroup
	for i, s := range stampers[1:] {
		go s.Run("regular", nRounds+2)
		go s.ListenToClients()

		// clients := createClientsForTSServer(ncps, sn,
		// 	sn.Host.(*coconet.GoHost).GetDirectory(), 0+i*ncps)

		//for _, client := range clientsLists[i] {
		//go client.Listen()
		//go client.ShowHistory()
		//}
		wg.Add(1)
		go func(clients []*stamp.Client, nRounds int, nMessages int, s *stamp.Server) {
			defer wg.Done()
			log.Println("clients Talk")
			clientsTalk(clients, nRounds, nMessages, s)
			log.Println("Clients done Talking")
		}(clientsLists[i], nRounds, nMessages, s)

	}
	go stampers[0].Run("root", nRounds)
	wg.Wait()

	// After clients receive messages back we need a better way
	// of waiting to make sure servers check ElGamal sigs
	time.Sleep(1 * time.Second)
}

func TestGoConnTimestampFromConfig(t *testing.T) {
	oldconfig.StartConfigPort += 2010
	nMessages := 1
	nClients := 1
	nRounds := 1

	hc, err := oldconfig.LoadConfig("../test/data/exconf.json")
	if err != nil {
		t.Fatal(err)
	}
	err = hc.Run(sign.MerkleTree)
	if err != nil {
		t.Fatal(err)
	}

	stampers, clients, err := hc.RunTimestamper(nClients)
	if err != nil {
		log.Fatal(err)
	}

	// for _, c := range clients {
	// 	// go c.Listen()
	// 	// go c.ShowHistory()
	// 	// go c.Connect()
	// }
	for _, s := range stampers[1:] {
		go s.Run("regular", nRounds)
		go s.ListenToClients()
	}
	go stampers[0].Run("root", nRounds)
	go stampers[0].ListenToClients()
	log.Println("About to start sending client messages")
	// time.Sleep(1 * time.Second)
	for r := 0; r < nRounds; r++ {
		var wg sync.WaitGroup
		for _, c := range clients {
			for i := 0; i < nMessages; i++ {
				// TODO: messages should be sent hashed eventually
				messg := []byte("messg:" + strconv.Itoa(r) + "." + strconv.Itoa(i))
				wg.Add(1)
				go func(c *stamp.Client, messg []byte, i int) {
					defer wg.Done()
					server := "NO VALID SERVER"
					for k := range c.Servers {
						server = k
						break
					}
					c.TimeStamp(messg, server)
				}(c, messg, r)
			}
		}
		// wait between rounds
		wg.Wait()
		fmt.Println("done with round:", r, nRounds)
	}
	for _, h := range hc.SNodes {
		h.Close()
	}
	for _, c := range clients {
		c.Close()
	}
}

func TestTCPTimestampFromConfig(t *testing.T) {
	oldconfig.StartConfigPort += 2010
	nMessages := 1
	nClients := 1
	nRounds := 2

	hc, err := oldconfig.LoadConfig("../test/data/extcpconf.json", oldconfig.ConfigOptions{ConnType: "tcp", GenHosts: true})
	if err != nil {
		t.Fatal(err)
	}
	err = hc.Run(sign.MerkleTree)
	if err != nil {
		t.Fatal(err)
	}

	stampers, clients, err := hc.RunTimestamper(nClients)
	if err != nil {
		log.Fatal(err)
	}

	// for _, c := range clients {
	// 	// go c.Listen()
	// 	// go c.ShowHistory()
	// 	// go c.Connect()
	// }
	for _, s := range stampers[1:] {
		go s.Run("regular", nRounds)
	}
	go stampers[0].Run("root", nRounds)
	log.Println("About to start sending client messages")
	// time.Sleep(1 * time.Second)
	for r := 0; r < nRounds; r++ {
		var wg sync.WaitGroup
		for _, c := range clients {
			for i := 0; i < nMessages; i++ {
				// TODO: messages should be sent hashed eventually
				messg := []byte("messg:" + strconv.Itoa(r) + "." + strconv.Itoa(i))
				wg.Add(1)
				go func(c *stamp.Client, messg []byte, i int) {
					defer wg.Done()
					server := "NO VALID SERVER"
				retry:
					for k := range c.Servers {
						server = k
						break
					}
					log.Infoln("timestamping")
					err := c.TimeStamp(messg, server)
					if err != nil {
						time.Sleep(1 * time.Second)
						goto retry
					}
					log.Infoln("timestamped")
				}(c, messg, r)
			}
		}
		// wait between rounds
		wg.Wait()
		log.Println("done with round:", r, nRounds)
	}
	for _, h := range hc.SNodes {
		h.Close()
	}
	for _, c := range clients {
		c.Close()
	}
}

// Create nClients for the TSServer, with first client associated with number fClient
func createClientsForTSServer(nClients int, s *stamp.Server, dir *coconet.GoDirectory, fClient int) []*stamp.Client {
	clients := make([]*stamp.Client, 0, nClients)
	for i := 0; i < nClients; i++ {
		clients = append(clients, stamp.NewClient("client"+strconv.Itoa(fClient+i)))

		// intialize TSServer conn to client
		ngc, err := coconet.NewGoConn(dir, s.Name(), clients[i].Name())
		if err != nil {
			panic(err)
		}
		s.Clients[clients[i].Name()] = ngc

		// intialize client connection to sn
		ngc, err = coconet.NewGoConn(dir, clients[i].Name(), s.Name())
		if err != nil {
			panic(err)
		}
		clients[i].AddServer(s.Name(), ngc)
	}

	return clients
}

func clientsTalk(clients []*stamp.Client, nRounds, nMessages int, s *stamp.Server) {
	// have client send messages
	for r := 0; r < nRounds; r++ {
		var wg sync.WaitGroup
		for _, client := range clients {
			for i := 0; i < nMessages; i++ {
				// TODO: messages should be sent hashed eventually
				messg := []byte("messg" + strconv.Itoa(r) + strconv.Itoa(i))
				wg.Add(1)
				go func(client *stamp.Client, messg []byte, s *stamp.Server, i int) {
					defer wg.Done()
					client.TimeStamp(messg, s.Name())
					// log.Println("timestamped")
				}(client, messg, s, r)
			}
		}
		// wait between rounds
		wg.Wait()
		// time.Sleep(1 * time.Second)
	}
}
