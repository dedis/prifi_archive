// deploy2deter is responsible for kicking off the deployment process
// for deterlab. Given a list of hostnames, it will create an overlay
// tree topology, using all but the last node. It will create multiple
// nodes per server and run timestamping processes. The last node is
// reserved for the logging server, which is forwarded to localhost:8080
//
// options are "bf" which specifies the branching factor
//
// 	and "hpn" which specifies the replicaiton factor: hosts per node
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"sync"

	"github.com/dedis/prifi/coco/test/cliutils"
	"github.com/dedis/prifi/coco/test/graphs"
)

// bf is the branching factor of the tree that we want to build
var bf int

// hpn is the replication factor of hosts per node: how many hosts do we want per node
var hpn int

func init() {
	flag.IntVar(&bf, "bf", 2, "branching factor: default binary")
	flag.IntVar(&hpn, "hpn", 1, "hosts per node: default 1")
}

func main() {
	flag.Parse()
	var wg sync.WaitGroup
	// start building the necessary packages
	packages := []string{"../logserver", "../timeclient", "../exec", "../deter"}
	for _, p := range packages {
		wg.Add(1)
		if p == "../deter" {
			go func(p string) {
				defer wg.Done()
				// the users node has a 386 FreeBSD architecture
				cliutils.Build(p, "386", "freebsd")
			}(p)
			continue
		}
		go func(p string) {
			defer wg.Done()
			// deter has an amd64, linux architecture
			cliutils.Build(p, "amd64", "linux")
		}(p)
	}
	// killssh processes on users
	cliutils.SshRunStdout("dvisher", "users.isi.deterlab.net", "killall ssh; killall scp")
	// read in the hosts config and create the graph topology that we will be using
	// reserve the final host for the logging package
	phys, err := cliutils.ReadLines("phys.txt")
	if err != nil {
		log.Fatal("error reading physical hosts file:", err)
	}
	virt, err := cliutils.ReadLines("virt.txt")
	if err != nil {
		log.Fatal("error reading virtual hosts file:", err)
	}

	logger := phys[len(phys)-1]
	virt = virt[:len(virt)-1]
	phys = phys[:len(phys)-1]
	t, _, err := graphs.TreeFromList(virt, hpn, bf)

	// after constructing the tree generate a configuration file
	// for deployment on each of the nodes
	b, err := json.Marshal(t)
	if err != nil {
		log.Fatal("unable to generate tree from list")
	}
	err = ioutil.WriteFile("cfg.json", b, 0660)
	if err != nil {
		log.Fatal("unable to write configuration file")
	}

	// at this point we need all of our builds to be complete
	wg.Wait()
	// move the logserver into the other directory
	err = os.Rename("logserver", "../logserver/logserver")
	if err != nil {
		log.Fatal("failed to copy logserver")
	}
	// scp the files that we need over to the boss node
	files := []string{"timeclient", "exec", "deter", "cfg.json", "phys.txt", "virt.txt"}
	cliutils.Scp("dvisher", "users.isi.deterlab.net", "../logserver", "")
	for _, f := range files {
		wg.Add(1)
		go func(f string) {
			defer wg.Done()
			cliutils.Scp("dvisher", "users.isi.deterlab.net", f, f)
		}(f)
	}
	wg.Wait()

	// setup port forwarding for viewing log server
	// ssh -L 8080:pcXXX:80 username@users.isi.deterlab.net
	// ssh username@users.deterlab.net -L 8118:somenode.experiment.YourClass.isi.deterlab.net:80
	fmt.Println("setup port forwarding for logger: ", logger)
	cmd := exec.Command(
		"ssh",
		"-t",
		"-t",
		"dvisher@users.isi.deterlab.net",
		"-L",
		"8080:"+logger+":10000")
	cmd.Start()
	if err != nil {
		log.Fatal("failed to setup portforwarding for logging server")
	}
	// run the deter lab boss nodes process
	// it will be responsible for forwarding the files and running the individual
	// timestamping servers
	log.Fatal(cliutils.SshRunStdout("dvisher", "users.isi.deterlab.net", "./deter"))
}
