// deployment configuration
//
// many hosts (physical machines)
// multiple nodes per host (at a given port p)
//   node runs signing node on port p
//             timestamper on port p+1
//             pprof server on port p+2
// deterlab defines a
package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net"
	"sync"
	"time"

	"github.com/dedis/prifi/coco/test/cliutils"
	"github.com/dedis/prifi/coco/test/graphs"
)

func main() {
	fs := []string{"exec", "timeclient", "logserver", "cfg.json", "hosts.txt"}
	hosts := cliutils.ReadLines("hosts.txt")

	// get the files to where they need to go
	var wg sync.WaitGroup
	for _, f := range fs {
		for h := range hosts {
			wg.Add(1)
			go func(h string, f string) {
				defer wg.Done()
				cliutils.Scp("", h, f, d)
			}(h, f)
		}
	}

	// now read in the config file
	file, e := ioutil.ReadFile("cfg.json")
	if e != nil {
		log.Fatal("Error Reading Configuration File: %v\n", e)
	}

	var tree graphs.Tree
	json.Unmarshal(file, &tree)

	wg.Wait()

	// the final host runs the logging server
	logger := hosts[len(hosts)-1] + ":10000"
	go cliutils.SshRun("", hosts[len(hosts)-1], "./logserver -addr="+logger)
	time.Sleep(1 * time.Second)
	// loop through all hosts but last one to launch clients (1 per host colocated)
	for i := 0; i < len(hosts)-1; i++ {
		go cliutils.SshRun("", hosts[i], "./timeclient -rate=100 -addr=client@"+hosts[i])
	}
	time.Sleep(1 * time.Second)
	// now start up servers
	tree.TraverseTree(func(t *Tree) {
		h, p, err := net.SplitHostPort(t.Name)
		if err != nil {
			log.Fatal("improperly formatted host. must be host:port")
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			cliutils.SshRun("", h, "./exec -hostname="+h+" -logger="+logger)
		}()
	})
	// wait for the servers to finish before stopping
	wg.Wait()
}
