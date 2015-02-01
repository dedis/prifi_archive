// pings servers in the hostfile that are not this hostname
//
// host peer1 avgtime1
// host peer2 avgtime2
// ...

package main

import (
	"bytes"
	"flag"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"sync"
)

var fname string
var hostname string
var threshold int

func init() {
	log.SetFlags(log.Lshortfile)
	flag.StringVar(&hostname, "hostname", "", "the hostname of this machine")
	flag.StringVar(&fname, "hostfile", "hosts.txt", "a file of hostnames. one per line.")
	flag.IntVar(&threshold, "threshold", 90, "the threshold")
}

var pingLoss *regexp.Regexp = regexp.MustCompile(`^[0-9]+ packets transmitted, [0-9]+ packets received, ([0-9]*\.?[0-9]*)% packet loss$`)
var pingStats *regexp.Regexp = regexp.MustCompile(`round-trip min/avg/max/stddev = ([0-9]*\.?[0-9]*)/([0-9]*\.?[0-9]*)/([0-9]*\.?[0-9]*)/([0-9]*\.?[0-9]*) ms`)

func main() {
	bs, err := ioutil.ReadFile(fname)
	if err != nil {
		os.Exit(1)
	}
	lines := bytes.Split(bs, []byte{'\n'})
	var wg sync.WaitGroup
	for _, bhostport := range lines {
		wg.Add(1)
		go func(bhostport []byte) {
			hostport := string(bhostport)
			if hostport == hostname {
				return
			}

			host, _, err := net.SplitHostPort(hostport)

			if err != nil {
				// if there was an error assume that it is that a hostname was given rather than host:port
				hostname = hostport
			}

			if host == hostport {
				return
			}
			output, err := exec.Command("ping", host, "-c", "20").Output()
			if err != nil {
				return
			}
			//output := string(boutput)
			smatch := pingLoss.FindSubmatch(output)
			if smatch == nil {
				return
			}

			success, err := strconv.ParseFloat(string(smatch[0]), 64)
			if err != nil {
				return
			}

			if success < float64(threshold) {
				// if a host has less than a 90% success rate don't use it
				return
			}

			matches := pingStats.FindSubmatch(output)
			if matches == nil {
				log.Println("FAILED:", host)
			}
			//min, _ := strconv.Atoi(string(matches[0]))
			avg, _ := strconv.Atoi(string(matches[1]))
			//max, _ := strconv.Atoi(string(matches[2]))
			//stddev, _ := strconv.Atoi(string(matches[3]))
			log.Println(hostname, host, avg)

		}(bhostport)
	}
	wg.Wait()
}
