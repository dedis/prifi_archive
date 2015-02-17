// usage exec:
//
// exec -name "hostname" -config "cfg.json"
//
// -name indicates the name of the node in the cfg.json
//
// -config points to the file that holds the configuration.
//     This configuration must be in terms of the final hostnames.

package main

import (
	"flag"
	"fmt"
	"math"
	"net"
	"net/http"
	_ "net/http/pprof"
	"strconv"
	"time"

	log "github.com/Sirupsen/logrus"

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

func init() {
	flag.StringVar(&hostname, "hostname", "", "the hostname of this node")
	flag.StringVar(&configFile, "config", "cfg.json", "the json configuration file")
	flag.StringVar(&logger, "logger", "", "remote logger")
	flag.StringVar(&app, "app", "time", "application to run [sign|time]")
	flag.IntVar(&nrounds, "nrounds", math.MaxInt32, "number of rounds to run")
	flag.StringVar(&pprofaddr, "pprof", ":10000", "the address to run the pprof server at")
}

func main() {
	flag.Parse()
	go func() {
		_, port, err := net.SplitHostPort(hostname)
		if err != nil {
			log.Fatal("improperly formatted hostname: should be host:port")
		}
		p, _ := strconv.Atoi(port)
		//runtime.MemProfileRate = 1
		log.Println(http.ListenAndServe(strconv.Itoa(p+2), nil))
	}()
	//log.SetPrefix(hostname + ":")
	//log.SetFlags(log.Lshortfile)
	fmt.Println("Execing")
	if hostname == "" {
		fmt.Println("hostname is empty")
		log.Fatal("no hostname given")
	}
	// connect with the logging server
	if logger != "" {
		// blocks until we can connect to the logger
		lh, err := logutils.NewLoggerHook(logger, hostname, app)
		if err != nil {
			log.Fatal(err)
		}
		log.AddHook(lh)
		log.Println("Log Test")
		fmt.Println("exiting logger block")
	}

	// load the configuration
	log.Println("loading configuration")
	hc, err := oldconfig.LoadConfig(configFile, oldconfig.ConfigOptions{ConnType: "tcp", Host: hostname})
	if err != nil {
		fmt.Println(err)
		log.Fatal(err)
	}

	// run this specific host
	log.Println("RUNNING HOST CONFIG")
	err = hc.Run(sign.MerkleTree, hostname)
	if err != nil {
		log.Fatal(err)
	}

	defer hc.SNodes[0].Close()

	if app == "sign" {
		log.Println("RUNNING SIGNINGNODE")
		// if I am root do the announcement message
		if hc.SNodes[0].IsRoot() {
			time.Sleep(3 * time.Second)
			start := time.Now()
			iters := 10

			for i := 0; i < iters; i++ {
				start = time.Now()
				fmt.Println("ANNOUNCING")
				hc.SNodes[0].LogTest = []byte("Hello World")
				err = hc.SNodes[0].Announce(&sign.AnnouncementMessage{LogTest: hc.SNodes[0].LogTest, Round: i})
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
			time.Sleep(480 * time.Second)
		}
	} else if app == "time" {
		log.Println("RUNNING TIMESTAMPER")
		stampers, _, err := hc.RunTimestamper(0, hostname)
		// get rid of the hc information so it can be GC
		hc = nil
		if err != nil {
			log.Fatal(err)
		}
		for _, s := range stampers {
			// only listen if this is the hostname specified
			if s.Name() == hostname {
				if s.IsRoot() {
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
