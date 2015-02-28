// usage exec:
//
// exec -name "hostname" -config "cfg.json"
//
// -name indicates the name of the node in the cfg.json
//
// -config points to the file that holds the configuration.
//     This configuration must be in terms of the final hostnames.
//
// pprof runs on the physical address space [if there is a virtual and physical network layer]
// and if one is specified.

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	_ "net/http/pprof"
	"strconv"
	"time"

	_ "expvar"

	log "github.com/Sirupsen/logrus"

	"github.com/dedis/prifi/coco"
	"github.com/dedis/prifi/coco/sign"
	"github.com/dedis/prifi/coco/test/logutils"
	"github.com/dedis/prifi/coco/test/oldconfig"
)

var hostname string
var configFile string
var logger string
var app string
var nrounds int
var pprofaddr string
var physaddr string
var rootwait int
var debug bool

// TODO: add debug flag for more debugging information (memprofilerate...)
func init() {
	flag.StringVar(&hostname, "hostname", "", "the hostname of this node")
	flag.StringVar(&configFile, "config", "cfg.json", "the json configuration file")
	flag.StringVar(&logger, "logger", "", "remote logger")
	flag.StringVar(&app, "app", "time", "application to run [sign|time]")
	flag.IntVar(&nrounds, "nrounds", 100, "number of rounds to run")
	flag.StringVar(&pprofaddr, "pprof", ":10000", "the address to run the pprof server at")
	flag.StringVar(&physaddr, "physaddr", "", "the physical address of the noded [for deterlab]")
	flag.IntVar(&rootwait, "rootwait", 30, "the amount of time the root should wait")
	flag.BoolVar(&debug, "debug", false, "set debugging")
}

func main() {
	flag.Parse()
	if debug {
		coco.DEBUG = true
	}
	defer func() {
		log.Errorln("TERMINATING HOST")
	}()

	// connect with the logging server
	if logger != "" && coco.DEBUG {
		// blocks until we can connect to the logger
		lh, err := logutils.NewLoggerHook(logger, hostname, app)
		if err != nil {
			log.WithFields(log.Fields{
				"file": logutils.File(),
			}).Fatalln("ERROR SETTING UP LOGGING SERVER:", err)
		}
		log.AddHook(lh)
		log.SetOutput(ioutil.Discard)
		//log.Println("Log Test")
		//fmt.Println("exiting logger block")
	}

	if physaddr == "" {
		h, _, err := net.SplitHostPort(hostname)
		if err != nil {
			log.Fatal("improperly formatted hostname")
		}
		physaddr = h
	}

	// run an http server to serve the cpu and memory profiles
	go func() {
		_, port, err := net.SplitHostPort(hostname)
		if err != nil {
			log.Fatal("improperly formatted hostname: should be host:port")
		}
		p, _ := strconv.Atoi(port)
		// uncomment if more fine grained memory debuggin is needed
		//runtime.MemProfileRate = 1
		log.Println(http.ListenAndServe(net.JoinHostPort(physaddr, strconv.Itoa(p+2)), nil))
	}()
	//log.SetPrefix(hostname + ":")
	//log.SetFlags(log.Lshortfile)
	fmt.Println("EXEC TIMESTAMPER: "+hostname, " logger: ", logger)
	if hostname == "" {
		fmt.Println("hostname is empty")
		log.Fatal("no hostname given")
	}

	// load the configuration
	//log.Println("loading configuration")
	hc, err := oldconfig.LoadConfig(configFile, oldconfig.ConfigOptions{ConnType: "tcp", Host: hostname})
	if err != nil {
		fmt.Println(err)
		log.Fatal(err)
	}

	// run this specific host
	//log.Println("RUNNING HOST CONFIG")
	err = hc.Run(sign.MerkleTree, hostname)
	if err != nil {
		log.Fatal(err)
	}

	defer func(sn *sign.Node) {
		log.Errorln("program has terminated")
		sn.Close()
	}(hc.SNodes[0])

	if app == "sign" {
		//log.Println("RUNNING Node")
		// if I am root do the announcement message
		if hc.SNodes[0].IsRoot() {
			time.Sleep(3 * time.Second)
			start := time.Now()
			iters := 10

			for i := 0; i < iters; i++ {
				start = time.Now()
				//fmt.Println("ANNOUNCING")
				hc.SNodes[0].LogTest = []byte("Hello World")
				err = hc.SNodes[0].Announce(
					&sign.AnnouncementMessage{
						LogTest: hc.SNodes[0].LogTest,
						Round:   i})
				if err != nil {
					log.Println(err)
				}
				elapsed := time.Since(start)
				log.WithFields(log.Fields{
					"file":  logutils.File(),
					"type":  "root_announce",
					"round": i,
					"time":  elapsed,
				}).Info("")
			}

		} else {
			// otherwise wait a little bit (hopefully it finishes by the end of this)
			time.Sleep(30 * time.Second)
		}
	} else if app == "time" {
		//log.Println("RUNNING TIMESTAMPER")
		stampers, _, err := hc.RunTimestamper(0, hostname)
		// get rid of the hc information so it can be GC'ed
		hc = nil
		if err != nil {
			log.Fatal(err)
		}
		for _, s := range stampers {
			// only listen if this is the hostname specified
			if s.Name() == hostname {
				if s.IsRoot() {
					log.Println("RUNNING ROOT SERVER AT:", hostname)
					log.Printf("Waiting: %d s\n", rootwait)
					// wait for the other nodes to get set up
					time.Sleep(time.Duration(rootwait) * time.Second)
					log.Println("STARTING ROOT ROUND")
					s.Run("root", nrounds)
					fmt.Println("\n\nROOT DONE\n\n")

				} else {
					s.Run("regular", nrounds)
					fmt.Println("\n\nREGULAR DONE\n\n")
				}
			}
		}
	}

}
