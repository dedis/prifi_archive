package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"

	"github.com/dedis/crypto/nist"
	"github.com/dedis/prifi/coco/test/config"
	"github.com/dedis/prifi/coco/test/graphs"
)

var hostfile string
var depth int
var port string
var app string
var cps int
var clientfile string
var nrounds int
var zoo bool
var uname string
var nmsgs int
var kill bool
var logger string

func init() {
	flag.StringVar(&hostfile, "hostfile", "hosts.txt", "file with hostnames space separated")
	flag.StringVar(&clientfile, "clientfile", "hosts.txt", "file with clientnames space separated")
	flag.IntVar(&depth, "depth", 2, "the depth of the tree to build")
	flag.StringVar(&port, "port", "9025", "the port for the signing nodes to run at")
	flag.StringVar(&app, "app", "sign", "the application to run [sign|time")
	flag.IntVar(&nrounds, "nrounds", 300000, "number of rounds to run")
	flag.IntVar(&nmsgs, "nmsgs", 10, "number of messages per round")
	flag.IntVar(&cps, "cps", 10, "clients per server")
	flag.BoolVar(&zoo, "zoo", false, "flag to indicate that there is a shared ")
	flag.StringVar(&uname, "u", "yale_dissent", "the username to use when logging in")
	flag.BoolVar(&kill, "kill", false, "kill services running on given nodes")
	flag.StringVar(&logger, "logger", "hippo.zoo.cs.yale.edu:9123", "the address that the logger will be running at")
}

func setupLogger() {
	h, _, err := net.SplitHostPort(logger)
	if err != nil {
		log.Info(err)
		h = logger
	}
	// build the logserver for the logger's environment
	err = build("../logserver", "386", "linux")
	if err != nil {
		log.Fatal("failed to build logserver:", err)
	}
	// move the build to the logserver directory
	err = os.Rename("logserver", "../logserver/logserver")
	if err != nil {
		log.Fatal("failed to rename logserver:", err)
	}
	// scp the logserver to the environment it will run on
	err = scp(uname, h, "../logserver", "~/")
	if err != nil {
		log.Fatal("failed to scp logserver:", err)
	}
	// startup the logserver
	go func() {
		sshRunStdout(uname, h, "cd logserver; ./logserver -addr="+logger)
		if err != nil {
			log.Fatal("failed to run logserver:", err)
		}
	}()
}

// takes in list of unique hosts
func scpTestFiles(hostnames []string) map[string]bool {
	var wg sync.WaitGroup
	failed := make(map[string]bool)
	var mu sync.Mutex
	for _, host := range hostnames {
		wg.Add(1)
		log.Println("scp test files:", host, hostnames)

		go func(host string) {
			defer wg.Done()
			err := timeoutRun(10*time.Second,
				func() error { return scp(uname, host, "latency_test", "latency_test") })
			if err != nil {
				log.Println("Failed:", host, err)
				mu.Lock()
				failed[host] = true
				mu.Unlock()
				return
			}

			err = timeoutRun(10*time.Second,
				func() error { return scp(uname, host, hostfile, "hosts.txt") })
			if err != nil {
				log.Println("Failed:", host, err)
				mu.Lock()
				failed[host] = true
				mu.Unlock()
				return
			}
		}(host)
	}
	wg.Wait()
	return failed
}

func testNodes(hostnames []string, failed map[string]bool) ([]string, []byte) {
	var mu sync.Mutex
	var edgelist []byte
	var wg sync.WaitGroup
	for _, host := range hostnames {
		log.Println("latency test:", host)
		if _, ok := failed[host]; ok {
			continue
		}
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			starttime := time.Now()
			// kill latent processes
			err := timeoutRun(10*time.Second,
				func() error {
					return sshRunStdout(uname, host, "killall logserver; killall timeclient; killall latency_test; killall cocoexec; rm -rf cocoexec")
				})
			if err != nil {
				log.Println("Failed:", host, err)
				mu.Lock()
				failed[host] = true
				mu.Unlock()
				return
			}

			// run the latency test
			log.Println("running latency_test:", host)
			output, err := sshRun(uname, host, "./latency_test -hostfile=hosts.txt -hostname="+host)
			if err != nil {
				log.Println("Failed:", host, err)
				mu.Lock()
				failed[host] = true
				mu.Unlock()
				return
			}

			// if this took to long say that this has failed
			if time.Since(starttime) > (20 * time.Minute) {
				log.Println("Failed:", host, err)
				mu.Lock()
				failed[host] = true
				mu.Unlock()
				return
			}
			fmt.Println("output:", string(output))
			mu.Lock()
			edgelist = append(edgelist, output...)
			mu.Unlock()
			return
		}(host)
	}
	wg.Wait()
	log.Println("latency test done")
	goodhosts := make([]string, 0, len(hostnames)-len(failed))
	for _, h := range hostnames {
		if !failed[h] {
			goodhosts = append(goodhosts, h)
		}
	}
	return goodhosts, edgelist
}

func scpClientFiles(clients []string) {
	var wg sync.WaitGroup
	log.Println("sending client files:", clients)
	for _, c := range clients {
		wg.Add(1)
		go func(client string) {
			defer wg.Done()
			if err := scp(uname, client, "timeclient", "timeclient"); err != nil {
				log.Println(client, err)
			}
		}(c)
	}
	wg.Wait()
}

func deployClient(client string, host string) {
	time.Sleep(1 * time.Second)
	// log.Println("running client")
	// timestamp server runs a port one higher than the signingnode port
	h, p, err := net.SplitHostPort(host)
	if err != nil {
		log.Fatal(err)
	}
	pn, _ := strconv.Atoi(p)
	pn += 1
	hp := net.JoinHostPort(h, strconv.Itoa(pn))
	if err := sshRunStdout(uname, client, "./timeclient -name="+client+" -server="+hp+" -nmsgs="+strconv.Itoa(nrounds)+" -logger="+logger); err != nil {
		log.Fatal(host, err)
	}
}

func runClients(clientnames, hostnames []string, cps int) {
	if app != "time" {
		return
	}
	t := 0
	for _, host := range hostnames {
		for i := 0; i < cps; i++ {
			go deployClient(clientnames[t%len(clientnames)], host)
			t++
		}
	}
}

func scpServerFiles(hostnames []string) {
	var wg sync.WaitGroup
	for _, host := range hostnames {
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			if err := scp(uname, host, "cfg.json", "cfg.json"); err != nil {
				log.Fatal(host, err)
			}
			if err := scp(uname, host, "exec", "cocoexec"); err != nil {
				log.Println(host, err)
			}
		}(host)
	}
	wg.Wait()
}

func deployServers(hostnames []string) {
	var wg sync.WaitGroup
	for _, hostport := range hostnames {
		wg.Add(1)
		go func(hostport string) {
			defer wg.Done()
			host, _, err := net.SplitHostPort(hostport)
			if err != nil {
				log.Fatal(err)
			}
			// log.Println("running signing node")
			if err := sshRunStdout(uname, host, "./cocoexec -hostname="+hostport+" -app="+app+" -nrounds="+strconv.Itoa(nrounds)+" -config=cfg.json -logger="+logger); err != nil {
				log.Fatal(host, err)
			}
		}(hostport)
	}
	wg.Wait()
}

func getUniqueHosts(hostnames []string) []string {
	seen := make(map[string]bool)
	unique := make([]string, 0, len(hostnames))
	log.Println("all:", hostnames)
	for _, hp := range hostnames {
		h, _, err := net.SplitHostPort(hp)
		if err != nil {
			h = hp
		}
		if _, ok := seen[h]; !ok {
			unique = append(unique, h)
			seen[h] = true
		}
		// if there is a shared file system then we only need
		// to send the files to one host. the first host
		if zoo == true {
			break
		}
	}
	log.Println("unique:", unique)
	return unique
}

func main() {
	flag.Parse()
	content, err := ioutil.ReadFile(hostfile)
	if err != nil {
		log.Fatal(hostfile, ": ", err)
	}
	// get the specified hostnames from the file
	hostnames := strings.Fields(string(content))
	log.Println("hostnames: ", hostnames)
	content, err = ioutil.ReadFile(clientfile)
	if err != nil {
		log.Fatal(err)
	}
	// get the specified hostnames from the file
	clientnames := strings.Fields(string(content))
	log.Println("clientnames: ", clientnames)

	if err := build("../latency_test", "386", "linux"); err != nil {
		log.Fatal(err)
	}
	if err := build("../exec", "386", "linux"); err != nil {
		log.Fatal(err)
	}
	if app == "time" {
		if err := build("../timeclient", "386", "linux"); err != nil {
			log.Fatal(err)
		}
	}

	// test the latency between nodes and remove bad ones
	uniquehosts := getUniqueHosts(hostnames)
	uniqueclients := getUniqueHosts(clientnames)

	if kill {
		var wg sync.WaitGroup
		for _, h := range hostnames {
			wg.Add(1)
			go func(h string) {
				defer wg.Done()
				sshRun(uname, h, "killall logserver; killall timeclient; killall latency_test; killall cocoexec; rm -rf cocoexec; rm -rf latency_test; rm -rf timeclient")
			}(h)
		}
		for _, h := range clientnames {
			wg.Add(1)
			go func(h string) {
				defer wg.Done()
				sshRun(uname, h, "killall logserver; killall timeclient; killall latency_test; killall cocoexec; rm -rf cocoexec; rm -rf latency_test; rm -rf timeclient")
			}(h)
		}
		wg.Wait()
		return
	}
	log.Println("uniquehosts: ", uniquehosts)
	failed := scpTestFiles(uniquehosts)
	goodhosts, edgelist := testNodes(hostnames, failed)
	hostnames = goodhosts

	// create a new graph with just these good nodes
	g := graphs.NewGraph(goodhosts)
	g.LoadEdgeList(edgelist)

	// this network into a tree with the given depth
	log.Println("CONSTRUCTING TREE OF DEPTH:", depth)
	t := g.Tree(depth)

	// generate the public and private keys for each node in this tree
	suite := nist.NewAES128SHA256P256()
	t.GenKeys(nist.NewAES128SHA256P256(), suite.Cipher([]byte("example")))
	log.Println("tree:", t)

	// turn this config into a config file for deployment
	cf := config.ConfigFromTree(t, goodhosts)

	// give each host in the file the specified port
	cf.AddPorts(port)

	log.Println("config file contents:", cf)
	b, err := json.Marshal(cf)
	if err != nil {
		log.Fatal(err)
	}

	// write this file out to disk for scp
	log.Println("config file:", string(b))
	err = ioutil.WriteFile("cfg.json", b, 0644)
	if err != nil {
		log.Fatal(err)
	}
	log.Infoln("setting up logger")
	setupLogger()
	log.Infoln("set up logger")
	uniqueclients = getUniqueHosts(clientnames)
	uniquehosts = getUniqueHosts(cf.Hosts)
	log.Infoln("running clients and servers")
	scpClientFiles(uniqueclients)
	scpServerFiles(uniquehosts)
	runClients(clientnames, cf.Hosts, cps)
	deployServers(cf.Hosts)
}
