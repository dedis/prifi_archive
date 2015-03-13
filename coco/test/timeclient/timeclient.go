package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"

	"github.com/dedis/prifi/coco/coconet"
	"github.com/dedis/prifi/coco/hashid"
	"github.com/dedis/prifi/coco/stamp"
	"github.com/dedis/prifi/coco/test/logutils"
	"github.com/dedis/prifi/coco/test/oldconfig"
)

var server string
var nmsgs int
var name string
var logger string
var rate int

func init() {
	addr, _ := oldconfig.GetAddress()
	flag.StringVar(&server, "server", "", "the timestamping server to contact")
	flag.IntVar(&nmsgs, "nmsgs", 100, "messages per round")
	flag.StringVar(&name, "name", addr, "name for the client")
	flag.StringVar(&logger, "logger", "", "remote logger")
	flag.IntVar(&rate, "rate", -1, "milliseconds between timestamp requests")

	//log.SetFormatter(&log.JSONFormatter{})
}

func genRandomMessages(n int) [][]byte {
	msgs := make([][]byte, n)
	for i := range msgs {
		msgs[i] = make([]byte, hashid.Size)
		_, err := rand.Read(msgs[i])
		if err != nil {
			log.Fatal("failed to generate random commit:", err)
		}
	}
	return msgs
}

func main() {
	flag.Parse()
	if logger != "" {
		// blocks until we can connect to the logger
		lh, err := logutils.NewLoggerHook(logger, name, "timeclient")
		if err != nil {
			log.Fatal(err)
		}
		log.AddHook(lh)
		log.Println("Log Test")
		fmt.Println("exiting logger block")
	}
	//log.SetFlags(log.Lshortfile)
	//log.SetPrefix(name + ":")
	log.Println("TIMESTAMP CLIENT")
	c := stamp.NewClient(name)
	log.Println("SERVER: ", server)
	conn := coconet.NewTCPConn(server)
	c.AddServer(server, conn)
	msgs := genRandomMessages(nmsgs)

	// if the rate has been specified then send out one message every
	// rate milliseconds
	if rate != -1 {
		ticker := time.Tick(time.Duration(rate) * time.Millisecond)
		for {
			go func() {
				e := c.TimeStamp(msgs[0], server)
				if e != nil {
					/*log.WithFields(log.Fields{
						"clientname": name,
						"server":     server,
					}).Errorln("error timesamping:", e)*/
				}
			}()
			<-ticker
		}
		return
	}

	// rounds based messaging
	r := 0
	for {
		start := time.Now()
		var wg sync.WaitGroup
		var m sync.Mutex
		var err error
		for i := 0; i < nmsgs; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				//log.Println("timestamping")
				e := c.TimeStamp(msgs[i], server)
				//log.Println("timestamped")
				if e != nil {
					m.Lock()
					err = e
					m.Unlock()
					return
				}
			}(i)
		}
		wg.Wait()
		if err != nil {
			log.Errorln("client error detected returning:", err)
			time.Sleep(3 * time.Second)
			continue
		}
		elapsed := time.Since(start)
		// log.Println("client done with round: ", time.Since(start).Nanoseconds())
		log.WithFields(log.Fields{
			"file":  logutils.File(),
			"type":  "client_round",
			"round": r,
			"time":  elapsed,
		}).Info("client round")
		r++
	}
}
