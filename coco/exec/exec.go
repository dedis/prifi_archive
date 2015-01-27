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
	"log"
	"net"
	"time"

	"github.com/dedis/prifi/coco"
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
	// open connection with remote logging interface if there is one
	if logger != "" {
		conn, err := net.Dial("tcp", logger)
		if err != nil {
			log.Println("ERROR: error establishing logging connection: ", err)
		} else {
			log.SetOutput(conn)
		}
	}
	flag.Parse()
	if hostname == "" {
		log.Fatal("no hostname given")
	}
	// open the testfile
	hc, err := coco.LoadConfig(configFile, coco.ConfigOptions{ConnType: "tcp", Host: hostname})
	if err != nil {
		log.Fatal(err)
	}
	err = hc.Run(hostname)
	if err != nil {
		log.Fatal(err)
	}
	if hc.SNodes[0].IsRoot() {
		hc.SNodes[0].LogTest = []byte("Hello World")
		err = hc.SNodes[0].Announce(&coco.AnnouncementMessage{hc.SNodes[0].LogTest})
		if err != nil {
			log.Fatal(err)
		}
	} else {
		time.Sleep(5 * time.Second)
	}
}
