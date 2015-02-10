package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/dedis/crypto/nist"
	"github.com/dedis/prifi/coco/test/config"
	"github.com/dedis/prifi/coco/test/graphs"
)

var hostfile string
var depth int
var port string

func init() {
	log.SetFlags(log.Lshortfile)
	flag.StringVar(&hostfile, "hostfile", "hosts.txt", "file with hostnames space separated")
	flag.IntVar(&depth, "depth", 2, "the depth of the tree to build")
	flag.StringVar(&port, "port", "9015", "the port for the signing nodes to run at")
}

func scp(username, host, file, dest string) error {
	cmd := exec.Command("scp", "-o", "StrictHostKeyChecking=no", "-C", file, username+"@"+host+":"+dest)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func sshRun(username, host, command string) ([]byte, error) {
	cmd := exec.Command("ssh", "-o", "StrictHostKeyChecking=no", username+"@"+host,
		"eval '"+command+"'")
	//log.Println(cmd)
	cmd.Stderr = os.Stderr
	return cmd.Output()
}

func sshRunStdout(username, host, command string) error {
	cmd := exec.Command("ssh", "-o", "StrictHostKeyChecking=no", username+"@"+host,
		"eval '"+command+"'")
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	return cmd.Run()
}

func build(path, goarch, goos string) error {
	cmd := exec.Command("go", "build", "-v", path)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append([]string{"GOOS=" + goos, "GOARCH=" + goarch}, os.Environ()...)
	return cmd.Run()
}

func timeoutRun(d time.Duration, f func() error) error {
	echan := make(chan error)
	go func() {
		echan <- f()
	}()
	var e error
	select {
	case e = <-echan:
	case <-time.After(d):
		e = errors.New("function timed out")
	}
	return e
}

func main() {
	flag.Parse()
	content, err := ioutil.ReadFile(hostfile)
	if err != nil {
		log.Fatal(err)
	}
	// get the specified hostnames from the file
	hostnames := strings.Fields(string(content))

	if err := build("../latency_test", "386", "linux"); err != nil {
		log.Fatal(err)
	}
	if err := build("../exec", "386", "linux"); err != nil {
		log.Fatal(err)
	}
	var mu sync.Mutex
	failed := make(map[string]bool)
	var edgelist []byte
	var wg sync.WaitGroup
	for _, host := range hostnames {
		wg.Add(1)
		log.Println("latency test:", host)

		go func(host string) {
			starttime := time.Now()
			defer wg.Done()
			err := timeoutRun(10*time.Second,
				func() error { return scp("yale_dissent", host, "latency_test", "latency_test") })
			if err != nil {
				log.Println("Failed:", host, err)
				mu.Lock()
				failed[host] = true
				mu.Unlock()
				return
			}
			err = timeoutRun(10*time.Second,
				func() error { return sshRunStdout("yale_dissent", host, "killall cocoexec; rm -rf cocoexec") })
			if err != nil {
				log.Println("Failed:", host, err)
				mu.Lock()
				failed[host] = true
				mu.Unlock()
				return
			}
			err = timeoutRun(10*time.Second,
				func() error { return scp("yale_dissent", host, hostfile, "hosts.txt") })
			if err != nil {
				log.Println("Failed:", host, err)
				mu.Lock()
				failed[host] = true
				mu.Unlock()
				return
			}
			log.Println("running latency_test:", host)
			output, err := sshRun("yale_dissent", host, "./latency_test -hostfile hosts.txt -hostname "+host)
			if err != nil {
				log.Println("Failed:", host, err)
				mu.Lock()
				failed[host] = true
				mu.Unlock()
				return
			}
			if time.Since(starttime) > (20 * time.Minute) {
				log.Println("Failed took too long:", host, err)
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

	hostnames = goodhosts
	// create a new graph
	g := graphs.NewGraph(goodhosts)
	g.LoadEdgeList(edgelist)
	log.Printf("%#v\n", g)
	// convert it into a tree with public and private keys
	t := g.Tree(depth)
	suite := nist.NewAES128SHA256P256()
	t.GenKeys(nist.NewAES128SHA256P256(), suite.Cipher([]byte("example")))
	log.Println("tree:", t)
	// turn it into a config file
	cf := config.ConfigFromTree(t, goodhosts)
	b, err := json.Marshal(cf)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("prior to adding ports:", string(b))

	cf.AddPorts(port)
	log.Println("config file contents:", cf)
	b, err = json.Marshal(cf)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("config file:", string(b))
	err = ioutil.WriteFile("cfg.json", b, 0644)
	if err != nil {
		log.Fatal(err)
	}

	for _, host := range hostnames {
		log.Println("sending over cfg")
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			if err = scp("yale_dissent", host, "cfg.json", "cfg.json"); err != nil {
				log.Fatal(host, err)
			}
			if err = scp("yale_dissent", host, "exec", "cocoexec"); err != nil {
				log.Println(host, err)
			}
			time.Sleep(1 * time.Second)
			log.Println("running signing node")
			if err = sshRunStdout("yale_dissent", host, "./cocoexec -hostname "+host+":"+port+" -config cfg.json"); err != nil {
				log.Fatal(host, err)
			}
		}(host)
	}
	wg.Wait()
}
