package main

import (
	"flag"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/dedis/prifi/coco/test/graphs"
)

var hostfile string

func init() {
	log.SetFlags(log.Lshortfile)
	flag.StringVar(&hostfile, "hostfile", "hosts.txt", "file with hostnames space separated")
}

func scp(username, host, file, dest string) error {
	cmd := exec.Command("scp", "-C", file, username+"@"+host+":"+dest)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func sshRun(username, host, command string) ([]byte, error) {
	cmd := exec.Command("ssh", username+"@"+host,
		"eval '"+command+"'")
	cmd.Stderr = os.Stderr
	return cmd.Output()
}

func build(path, goarch, goos string) error {
	cmd := exec.Command("go", "build", "-v", path)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append([]string{"GOOS=" + goos, "GOARCH=" + goarch}, os.Environ()...)
	return cmd.Run()
}

func main() {
	content, err := ioutil.ReadFile(hostfile)
	if err != nil {
		log.Fatal(err)
	}
	// get the specified hostnames from the file
	hostnames := strings.Fields(string(content))

	// create a new graph
	g := graphs.NewGraph(hostnames)
	if err := build("github.com/dedis/prifi/test/latency_test", "386", "linux"); err != nil {
		log.Fatal(err)
	}
	var mu sync.Mutex
	var failed []string
	var edgelist []byte
	for _, host := range hostnames {
		if scp("yale_dissent", host, "latency_test", "latency_test") != nil {
			log.Println("Failed:", host, err)
			mu.Lock()
			failed = append(failed, host)
			mu.Unlock()
		}
		if scp("yale_dissent", host, hostfile, "hosts.txt") != nil {
			log.Println("Failed:", host, err)
			mu.Lock()
			failed = append(failed, host)
			mu.Unlock()
		}
		output, err := sshRun("yale_dissent", host, "latency_test -hostfile hosts.txt")
		if err != nil {
			log.Println("Failed:", host, err)
			mu.Lock()
			failed = append(failed, host)
			mu.Unlock()
		}
		mu.Lock()
		edgelist = append(edgelist, output...)
		mu.Unlock()
	}
	g.LoadEdgeList(edgelist)
}
