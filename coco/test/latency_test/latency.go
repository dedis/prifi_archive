// pings servers in the hostfile that are not this hostname
//
// host peer1 avgtime1
// host peer2 avgtime2
// ...

package main

import (
	"bytes"
	"flag"
	"fmt"
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
	log.SetOutput(os.Stderr)
	flag.StringVar(&hostname, "hostname", "", "the hostname of this machine")
	flag.StringVar(&fname, "hostfile", "hosts.txt", "a file of hostnames. one per line.")
	flag.IntVar(&threshold, "threshold", 90, "the threshold")
}

var pingLoss *regexp.Regexp = regexp.MustCompile(`[0-9]+ packets transmitted, [0-9]+ received, ([0-9]*\.?[0-9]*)% packet loss`)
var pingStats *regexp.Regexp = regexp.MustCompile(`min/avg/max/mdev = ([0-9]*\.?[0-9]*)/([0-9]*\.?[0-9]*)/([0-9]*\.?[0-9]*)/([0-9]*\.?[0-9]*) ms`)

func main() {
	flag.Parse()
	bs, err := ioutil.ReadFile(fname)
	if err != nil {
		log.Fatal("FAILED TO READ FILE!")
		os.Exit(1)
	}
	lines := bytes.Split(bs, []byte{'\n'})
	var wg sync.WaitGroup
	for _, bhostport := range lines {
		wg.Add(1)
		go func(bhostport []byte) {
			defer wg.Done()
			hostport := string(bhostport)
			if hostport == hostname {
				return
			}

			host, _, err := net.SplitHostPort(hostport)

			if err != nil {
				// if there was an error assume that it is that a hostname was given rather than host:port
				host = hostport
			}

			if host == hostname {
				return
			}
			output, err := exec.Command("ping", host, "-c", "20").Output()
			if err != nil {
				log.Println("error pinging")
				return
			}
			//output := string(boutput)
			//log.Println(string(output))
			smatch := pingLoss.FindSubmatch(output)
			if smatch == nil {
				log.Println("no ping loss")
				return
			}

			success, err := strconv.ParseFloat(string(smatch[1]), 64)
			if err != nil {
				log.Println("smatch err:", err, smatch[1], smatch[0])
				return
			}

			if success > 100-float64(threshold) {
				log.Println("below thresh")
				// if a host has less than a 90% success rate don't use it
				return
			}

			matches := pingStats.FindSubmatch(output)
			if matches == nil {
				log.Println("FAILED:", host)
			}
			//log.Println(matches)
			//log.Println(string(matches[2]))
			//min, _ := strconv.Atoi(string(matches[1]))
			avg, _ := strconv.ParseFloat(string(matches[2]), 64)
			//max, _ := strconv.Atoi(string(matches[3]))
			//stddev, _ := strconv.Atoi(string(matches[4]))
			log.Println(hostname, host, avg)
			fmt.Println(hostname, host, avg)

		}(bhostport)
	}
	wg.Wait()
}
