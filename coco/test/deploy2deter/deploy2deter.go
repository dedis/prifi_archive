// logging server can be seen at localhost:8080
package main

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"os/exec"
	"sync"

	"github.com/dedis/prifi/coco/test/cliutils"
	"github.com/dedis/prifi/coco/test/graphs"
)

var bf int
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
		go func(p string) {
			defer wg.Done()
			// deter has an amd64, linux architecture
			cliutils.Build(p, "amd64", "linux")
		}(p)
	}

	// read in the hosts config and create the graph topology that we will be using
	hosts := cliutils.ReadLines("hosts.txt")
	logger := hosts[len(hosts)-1]
	hosts = hosts[:len(hosts)-1]
	var t graphs.Tree = graph.TreeFromList(hosts, bf)
	b, err := json.Marshal(t)
	if err != nil {
		log.Fatal("unable to generate tree from list")
	}
	err = ioutil.WriteFile("cfg.json", b, 0660)
	if err != nil {
		log.Fatal("unable to write configuration file")
	}
	//hosts per node, branching factor, start machine[]
	wg.Wait()
	files := []string{"logserver", "timeclient", "exec", "deter", "cfg.json", "hosts.txt"}
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

	err = exec.Command("ssh", "-L", "8080:"+logger+":10000", "dvisher@users.isi.deterlab.ne").Start()
	if err != nil {
		log.Errorln("failed to setup portforwarding for logging server")
	}

	log.Fatal(cliutils.SshRun("dvisher", "users.isi.deterlab.net", "./deter"))
}
