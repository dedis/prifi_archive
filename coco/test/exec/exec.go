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
	"io"
	"log"
	"net"
	"os"
	"time"

	"github.com/dedis/prifi/coco/sign"
	"github.com/dedis/prifi/coco/test/oldconfig"
)

var hostname string
var configFile string
var logger string

func init() {
	flag.StringVar(&hostname, "hostname", "", "the hostname of this node")
	flag.StringVar(&configFile, "config", "cfg.json", "the json configuration file")
	flag.StringVar(&logger, "logger", "", "remote logging interface")
}

func main() {
	flag.Parse()
	log.SetPrefix(hostname + ":")
	fmt.Println("Execing")
	// open connection with remote logging interface if there is one
	if false && logger != "" {
		conn, err := net.Dial("tcp", logger)
		if err != nil {
			fmt.Println("ERROR ESTABLISHING LOG CONNECTION")
			os.Exit(1)
			log.Fatal("ERROR: error establishing logging connection: ", err)
		}
		defer conn.Close()
		log.Println("Log Test")
		fmt.Println("Connected to logger successfully")
		log.SetOutput(io.MultiWriter(os.Stdout, conn))
		log.SetPrefix(hostname + ":")
		log.Println("Log Test")
		fmt.Println("exiting logger block")
	}
	if hostname == "" {
		fmt.Println("hostname is empty")
		log.Fatal("no hostname given")
	}

	// load the configuration
	fmt.Println("loading configuration")
	hc, err := oldconfig.LoadConfig(configFile, oldconfig.ConfigOptions{ConnType: "tcp", Host: hostname})
	if err != nil {
		fmt.Println(err)
		log.Fatal(err)
	}

	// run this specific host
	fmt.Println("STARTING TO RUN")
	err = hc.Run(hostname)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("RUNNING")
	defer hc.SNodes[0].Close()

	// if I am root do the announcement message
	if hc.SNodes[0].IsRoot() {
		time.Sleep(3 * time.Second)
		start := time.Now()
		iters := 1

		for i := 0; i < iters; i++ {
			fmt.Println("ANNOUNCING")
			hc.SNodes[0].LogTest = []byte("Hello World")
			err = hc.SNodes[0].Announce(&sign.AnnouncementMessage{hc.SNodes[0].LogTest})
			if err != nil {
				log.Println(err)
			}
		}

		elapsed := time.Since(start)
		log.Printf("took %d ns/op\n", elapsed.Nanoseconds()/int64(iters))
	} else {
		// otherwise wait a little bit (hopefully it finishes by the end of this)
		time.Sleep(20 * time.Second)
	}
	fmt.Println("DONE")
}
