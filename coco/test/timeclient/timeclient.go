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
	"sync/atomic"
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
var debug bool

func init() {
	addr, _ := oldconfig.GetAddress()
	// TODO: change to take in list of servers: comma separated no spaces
	//   -server=s1,s2,s3,...
	flag.StringVar(&server, "server", "", "the timestamping servers to contact")
	flag.IntVar(&nmsgs, "nmsgs", 100, "messages per round")
	flag.StringVar(&name, "name", addr, "name for the client")
	flag.StringVar(&logger, "logger", "", "remote logger")
	flag.IntVar(&rate, "rate", -1, "milliseconds between timestamp requests")
	flag.BoolVar(&debug, "debug", false, "set debug mode")
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

func streamMessgs(c *stamp.Client, servers []string) {
	log.Println("STREAMING: GIVEN RATE")
	// buck[i] = # of timestamp responses received in second i
	buck := make([]int64, MAX_N_SECONDS)
	// roundsAfter[i] = # of timestamp requests that were processed i rounds late
	roundsAfter := make([]int64, MAX_N_ROUNDS)
	ticker := time.Tick(time.Duration(rate) * time.Millisecond)
	msg := genRandomMessages(1)[0]
	i := 0
	nServers := len(servers)
	firstReceived := false
	var tFirst time.Time

	// every tick send a time stamp request to every server specified
	for _ = range ticker {
		go func(msg []byte, s string) {
			t0 := time.Now()
			err := c.TimeStamp(msg, s)
			t := time.Since(t0)

			if err == io.EOF {
				log.WithFields(log.Fields{
					"file":        logutils.File(),
					"type":        "client_msg_stats",
					"buck":        buck,
					"roundsAfter": roundsAfter,
				}).Info("")

				log.Fatal("EOF: termininating time client")
			} else if err != nil {
				// ignore errors
				return
			}
			log.Println("successfully timestamped item")
			if !firstReceived {
				firstReceived = true
				tFirst = time.Now()
			}

			// TODO: we might want to subtract a buffer from secToTimeStamp
			// to account for computation time
			secToTimeStamp := t.Seconds()
			secSinceFirst := time.Since(tFirst).Seconds()
			atomic.AddInt64(&buck[int(secSinceFirst)], 1)
			index := int(secToTimeStamp) / int(stamp.ROUND_TIME/time.Second)
			atomic.AddInt64(&roundsAfter[index], 1)

		}(msg, servers[i])

		i = (i + 1) % nServers
	}

}

var MAX_N_SECONDS int = 1 * 60 * 60 // 1 hours' worth of seconds
var MAX_N_ROUNDS int = MAX_N_SECONDS / int(stamp.ROUND_TIME/time.Second)

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
	}
	c := stamp.NewClient(name)
	msgs := genRandomMessages(nmsgs + 20)
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

	// if rate specified send out one message every rate milliseconds
	if rate > 0 {
		// Stream time stamp requests
		streamMessgs(c, servers)
		return
	}

	// rounds based messaging
	r := 0
	s := 0

	// log.Println("timeclient using rounds")
	log.Fatal("ROUNDS BASED RATE LIMITING DEPRECATED")
	for {
		//start := time.Now()
		var wg sync.WaitGroup
		for i := 0; i < nmsgs; i++ {
			wg.Add(1)
			go func(i, s int) {
				defer wg.Done()
				err := c.TimeStamp(msgs[i], servers[s])
				if err == io.EOF {
					log.WithFields(log.Fields{
						"file":        logutils.File(),
						"type":        "client_msg_stats",
						"buck":        make([]int64, 0),
						"roundsAfter": make([]int64, 0),
					}).Info("")

					log.Fatal("EOF: terminating time client")
				}
			}(i, s)
			s = (s + 1) % len(servers)
		}
		wg.Wait()
		//elapsed := time.Since(start)
		log.Println("client done with round")
		//log.WithFields(log.Fields{
		//"file":  logutils.File(),
		//"type":  "client_round",
		//"round": r,
		//"time":  elapsed,
		//}).Info("client round")
		r++
	}
}
