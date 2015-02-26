package main

import (
	"crypto/rand"
	"flag"
	"io"
	"net"
	"runtime"
	"strconv"
	"strings"
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
	// TODO: change to take in list of servers: comma separated no spaces
	//   -server=s1,s2,s3,...
	flag.StringVar(&server, "server", "", "the timestamping servers to contact")
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
	runtime.GOMAXPROCS(runtime.NumCPU())
	if logger != "" {
		// blocks until we can connect to the logger
		lh, err := logutils.NewLoggerHook(logger, name, "timeclient")
		if err != nil {
			log.Fatal(err)
		}
		log.AddHook(lh)
		// log.Println("Log Test")
		// fmt.Println("exiting logger block")
	}
	//log.SetFlags(log.Lshortfile)
	//log.SetPrefix(name + ":")
	// log.Println("TIMESTAMP CLIENT")
	c := stamp.NewClient(name)
	// log.Println("SERVER: ", server)
	msgs := genRandomMessages(nmsgs)

	servers := strings.Split(server, ",")
	// log.Println("connecting to servers:", servers)
	for _, s := range servers {
		h, p, err := net.SplitHostPort(s)
		if err != nil {
			log.Fatal("improperly formatted host")
		}
		pn, _ := strconv.Atoi(p)
		c.AddServer(s, coconet.NewTCPConn(net.JoinHostPort(h, strconv.Itoa(pn+1))))
	}
	// if the rate has been specified then send out one message every
	// rate milliseconds
	if rate != -1 {
		ticker := time.Tick(time.Duration(rate) * time.Millisecond)
		i := 0
		for _ = range ticker {
			// every tick send a time stamp request to every server specified
			msg := genRandomMessages(1)[0]
			s := servers[i]
			err := c.TimeStamp(msg, s)
			if err == io.EOF {
				log.Errorln("EOF: termininating time client")
				return
			}
			i += 1
		}
		return
	}

	// rounds based messaging
	r := 0
	s := 0

	// log.Println("timeclient using rounds")
	for {
		//start := time.Now()
		var wg sync.WaitGroup
		var m sync.Mutex
		var err error
		for i := 0; i < nmsgs; i++ {
			wg.Add(1)
			go func(i, s int) {
				defer wg.Done()
				e := c.TimeStamp(msgs[i], servers[s])
				if e != nil {
					m.Lock()
					err = e
					m.Unlock()
					return
				}
			}(i, s)
			s = (s + 1) % len(servers)
		}
		wg.Wait()
		if err == io.EOF {
			log.Errorln("EOF: terminating time client")
			return
		}
		if err != nil {
			//log.Errorln("client error detected returning:", err)
			time.Sleep(1 * time.Second)
			continue
		}
		//elapsed := time.Since(start)
		// log.Println("client done with round: ", time.Since(start).Nanoseconds())
		//log.WithFields(log.Fields{
		//"file":  logutils.File(),
		//"type":  "client_round",
		//"round": r,
		//"time":  elapsed,
		//}).Info("client round")
		r++
	}
}
