// deter is the deterlab process that should run on the boss node
//
// It spawns multiple timestampers and clients, while constructing
// the topology defined on cfg.json. It assumes that hosts.txt has
// the entire list of hosts to run timestampers on and that the final
// host is the designated logging server.
//
// The overall topology that is created is defined by cfg.json.
// The port layout for each node, however, is specified here.
// cfg.json will assign each node a port p. This is the port
// that each singing node is listening on. The timestamp server
// to which clients connect is listneing on port p+1. And the
// pprof server for each node is listening on port p+2. This
// means that in order to debug each client, you can forward
// the p+2 port of each node to your localhost.
//
// In the future the loggingserver will be connecting to the
// servers on the pprof port in order to gather extra data.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dedis/prifi/coco/test/cliutils"
	"github.com/dedis/prifi/coco/test/config"
	"github.com/dedis/prifi/coco/test/graphs"
)

func GenExecCmd(phys string, names []string, loggerport, rootwait string) string {
	total := ""
	for _, n := range names {
		total += "(sudo ./exec -rootwait=" + rootwait +
			" -physaddr=" + phys +
			" -hostname=" + n +
			" -logger=" + loggerport +
			" -debug=" + debug +
			" </dev/null 2>/dev/null 1>/dev/null &); "
	}
	return total
}

var nmsgs string
var hpn string
var bf string
var debug string

func init() {
	flag.StringVar(&nmsgs, "nmsgs", "100", "the number of messages per round")
	flag.StringVar(&hpn, "hpn", "", "number of hosts per node")
	flag.StringVar(&bf, "bf", "", "branching factor")
	flag.StringVar(&debug, "debug", "false", "set debug mode")
}

func main() {
	flag.Parse()
	fmt.Println("running deter with nmsgs:", nmsgs)
	// fs defines the list of files that are needed to run the timestampers.
	fs := []string{"exec", "timeclient", "cfg.json", "virt.txt", "phys.txt"}

	// read in the hosts file.
	virt, err := cliutils.ReadLines("virt.txt")
	if err != nil {
		log.Fatal(err)
	}
	phys, err := cliutils.ReadLines("phys.txt")
	if err != nil {
		log.Fatal(err)
	}
	vpmap := make(map[string]string)
	for i := range virt {
		vpmap[virt[i]] = phys[i]
	}
	// kill old processes
	var wg sync.WaitGroup
	for _, h := range phys {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			cliutils.SshRun("", h, "sudo killall exec logserver timeclient scp ssh 2>/dev/null >/dev/null")
		}(h)
	}
	wg.Wait()
	masterLogger := phys[0]
	slaveLogger1 := phys[1]
	slaveLogger2 := phys[2]
	loggers := []string{masterLogger, slaveLogger1, slaveLogger2}

	phys = phys[3:]
	virt = virt[3:]

	// Read in and parse the configuration file
	file, e := ioutil.ReadFile("cfg.json")
	if e != nil {
		log.Fatal("deter.go: error reading configuration file: %v\n", e)
	}

	for _, logger := range loggers {
		cliutils.Scp("", logger, "cfg.json", "logserver/cfg.json")
	}

	var tree graphs.Tree
	json.Unmarshal(file, &tree)

	hostnames := make([]string, 0, len(virt))
	tree.TraverseTree(func(t *graphs.Tree) {
		hostnames = append(hostnames, t.Name)
	})

	depth := graphs.Depth(&tree)

	log.Println("depth of tree:", depth)
	cf := config.ConfigFromTree(&tree, hostnames)
	cfb, err := json.Marshal(cf)
	if err != nil {
		log.Fatal(err)
	}

	// write out a true configuration file
	log.Println(string(cfb))
	err = ioutil.WriteFile("cfg.json", cfb, 0666)
	if err != nil {
		log.Fatal(err)
	}

	// mapping from physical node name to the timestamp servers that are running there
	// essentially a reverse mapping of vpmap except ports are also used
	physToServer := make(map[string][]string)
	for _, virt := range hostnames {
		v, _, _ := net.SplitHostPort(virt)
		p := vpmap[v]
		ss := physToServer[p]
		ss = append(ss, virt)
		physToServer[p] = ss
	}

	fmt.Println("copying over files")
	for _, logger := range loggers {
		cliutils.Scp("", logger, "logserver", "")
	}
	// copy the files over to all the host machines.
	for _, f := range fs {
		for _, h := range phys {
			wg.Add(1)
			go func(h string, f string) {
				defer wg.Done()
				cliutils.Scp("", h, f, f)
			}(h, f)
		}
		// cfg.json on logger should be in tree format
		if f != "cfg.json" {
			for _, logger := range loggers {
				cliutils.Scp("", logger, f, "logserver/"+f)
			}
		}
	}
	wg.Wait()

	// start up the logging server on the final host at port 10000
	fmt.Println("starting up logserver")
	// start up the master logger
	loggerports := make([]string, len(loggers))
	for i, logger := range loggers {
		loggerport := logger + ":10000"
		loggerports[i] = loggerport
		// redirect to the master logger
		master := masterLogger + ":10000"
		// if this is the master logger than don't set the master to anything
		if loggerport == masterLogger+":10000" {
			master = ""
		}

		go cliutils.SshRunStdout("", logger, "cd logserver; sudo ./logserver -addr="+loggerport+
			" -hosts="+strconv.Itoa(len(hostnames))+
			" -depth="+strconv.Itoa(depth)+
			" -bf="+bf+
			" -hpn="+hpn+
			" -nmsgs="+nmsgs+
			" -master="+master)
	}

	// wait a little bit for the logserver to start up
	time.Sleep(5 * time.Second)
	fmt.Println("starting time clients")

	// start up one timeclient per physical machine
	// it requests timestamps from all the servers on that machine
	i := 0
	for p, ss := range physToServer {
		if len(ss) == 0 {
			continue
		}
		servers := strings.Join(ss, ",")
		go cliutils.SshRunBackground("", p, "sudo ./timeclient -nmsgs="+nmsgs+
			" -name=client@"+p+
			" -server="+servers+
			" -logger="+loggerports[i]+
			" -debug="+debug)
		i = (i + 1) % len(loggerports)
	}

	rootwait := strconv.Itoa(30)
	for phys, virts := range physToServer {
		if len(virts) == 0 {
			continue
		}
		cmd := GenExecCmd(phys, virts, loggerports[i], rootwait)
		i = (i + 1) % len(loggerports)
		wg.Add(1)
		//time.Sleep(500 * time.Millisecond)
		go func(phys, cmd string) {
			// log.Println("running on ", phys, cmd)
			err := cliutils.SshRunBackground("", phys, cmd)
			if err != nil {
				log.Fatal("ERROR STARTING TIMESTAMPER:", err)
			}
		}(phys, cmd)
	}
	// wait for the servers to finish before stopping
	wg.Wait()
	time.Sleep(10 * time.Minute)
}
