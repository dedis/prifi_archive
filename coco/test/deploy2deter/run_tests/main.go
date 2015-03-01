// NOTE: SHOULD BE RUN FROM run_tests directory
// note: deploy2deter must be run from within it's directory
//
// Outputting data: output to csv files (for loading into excel)
//   make a datastructure per test output file
//   all output should be in the test_data subdirectory
//
// connect with logging server (receive json until "EOF" seen or "terminating")
//   connect to websocket ws://localhost:8080/log
//   receive each message as bytes
//		 if bytes contains "EOF" or contains "terminating"
//       wrap up the round, output to test_data directory, kill deploy2deter
//
// for memstats check localhost:8080/d/server-0-0/debug/vars
//   parse out the memstats zones that we are concerned with
//
// different graphs needed rounds:
//   load on the x-axis: increase messages per round holding everything else constant
//			hpn=40 bf=10, bf=50
//
// run time command with the deploy2deter exec.go (timestamper) instance associated with the root
//    and a random set of servers
//
// latency on y-axis, timestamp servers on x-axis push timestampers as higher as possible
//
//
// RunTest(hpn, bf), Monitor() -> RunStats() -> csv -> Excel
//
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/browser"
	"golang.org/x/net/websocket"
)

type RunStats struct {
	NHosts int
	Depth  int

	MinTime float64
	MaxTime float64
	AvgTime float64
	StdDev  float64

	SysTime  float64
	UserTime float64

	Rate float64
}

func (s RunStats) CSVHeader() []byte {
	var buf bytes.Buffer
	buf.WriteString("hosts, depth, min, max, avg, stddev, systime, usertime, rate\n")
	return buf.Bytes()
}
func (s RunStats) CSV() []byte {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%d, %d, %f, %f, %f, %f, %f, %f, %f\n",
		s.NHosts,
		s.Depth,
		s.MinTime,
		s.MaxTime,
		s.AvgTime,
		s.StdDev,
		s.SysTime,
		s.UserTime,
		s.Rate)
	return buf.Bytes()
}

/*
{
	"eapp":"time",
	"ehost":"10.255.0.13:2000",
	"elevel":"info",
	"emsg":"root round",
	"etime":"2015-02-27T09:50:45-08:00",
	"file":"server.go:195",
	"round":59,
	"time":893709029,
	"type":"root_round"
}
*/
var view bool
var debug string = "-debug=false"

func SetDebug(b bool) {
	if b {
		debug = "-debug=true"
	} else {
		debug = "-debug=false"
	}
}

type StatsEntry struct {
	App     string  `json:"eapp"`
	Host    string  `json:"ehost"`
	Level   string  `json:"elevel"`
	Msg     string  `json:"emsg"`
	MsgTime string  `json:"etime"`
	File    string  `json:"file"`
	Round   int     `json:"round"`
	Time    float64 `json:"time"`
	Type    string  `json:"type"`
}

type SysStats struct {
	File     string  `json:"file"`
	Type     string  `json:"type"`
	SysTime  float64 `json:"systime"`
	UserTime float64 `json:"usertime"`
}

type ClientMsgStats struct {
	File        string    `json:"file"`
	Type        string    `json:"type"`
	Buckets     []float64 `json:"buck"`
	RoundsAfter []float64 `json:"roundsAfter"`
}

type ExpVar struct {
	Cmdline  []string         `json:"cmdline"`
	Memstats runtime.MemStats `json:"memstats"`
}

func Memstats(server string) (*ExpVar, error) {
	url := "localhost:8080/d/" + server + "/debug/vars"
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	b, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}
	var evar ExpVar
	err = json.Unmarshal(b, &evar)
	if err != nil {
		log.Println("failed to unmarshal expvar:", string(b))
		return nil, err
	}
	return &evar, nil
}

func MonitorMemStats(server string, poll int, done chan struct{}, stats *[]*ExpVar) {
	go func() {
		ticker := time.NewTicker(time.Duration(poll) * time.Millisecond)
		for {
			select {
			case <-ticker.C:
				evar, err := Memstats(server)
				if err != nil {
					continue
				}
				*stats = append(*stats, evar)
			case <-done:
				return
			}
		}
	}()
}

// Monitor: monitors log aggregates results into RunStats
func Monitor() RunStats {
	log.Println("MONITORING")
	defer fmt.Println("DONE MONITORING")
retry_dial:
	ws, err := websocket.Dial("ws://localhost:8080/log", "", "http://localhost/")
	if err != nil {
		time.Sleep(1 * time.Second)
		goto retry_dial
	}
retry:
	// Get HTML of webpage for data (NHosts, Depth, ...)
	doc, err := goquery.NewDocument("http://localhost:8080/")
	if err != nil {
		log.Println("unable to get log data: retrying:", err)
		goto retry
	}
	if view {
		browser.OpenURL("http://localhost:8080/")
	}
	nhosts := doc.Find("#numhosts").First().Text()
	log.Println("hosts:", nhosts)
	depth := doc.Find("#depth").First().Text()
	log.Println("depth:", depth)
	nh, err := strconv.Atoi(nhosts)
	if err != nil {
		log.Fatal("unable to convert hosts to be a number:", nhosts)
	}
	d, err := strconv.Atoi(depth)
	if err != nil {
		log.Fatal("unable to convert depth to be a number:", depth)
	}

	var rs RunStats
	rs.NHosts = nh
	rs.Depth = d

	var M, S float64
	k := float64(1)
	first := true
	for {
		var data []byte
		err := websocket.Message.Receive(ws, &data)
		if err != nil {
			// if it is an eof error than stop reading
			if err == io.EOF {
				log.Println("websocket terminated before emitting EOF or terminating string")
				break
			}
			continue
		}
		if bytes.Contains(data, []byte("EOF")) || bytes.Contains(data, []byte("terminating")) {
			log.Println("EOF/terminating Detected: need forkexec to report")
		}
		if bytes.Contains(data, []byte("root_round")) {
			var entry StatsEntry
			err := json.Unmarshal(data, &entry)
			if err != nil {
				log.Fatal("json unmarshalled improperly:", err)
			}
			log.Println("root_round:", entry)
			if first {
				first = false
				rs.MinTime = entry.Time
				rs.MaxTime = entry.Time
			}
			if entry.Time < rs.MinTime {
				rs.MinTime = entry.Time
			} else if entry.Time > rs.MaxTime {
				rs.MaxTime = entry.Time
			}

			rs.AvgTime = ((rs.AvgTime * (k - 1)) + entry.Time) / k

			var tM = M
			M += (entry.Time - tM) / k
			S += (entry.Time - tM) * (entry.Time - M)
			k++
			rs.StdDev = math.Sqrt(S / (k - 1))
		} else if bytes.Contains(data, []byte("forkexec")) {
			var ss SysStats
			err := json.Unmarshal(data, &ss)
			if err != nil {
				log.Fatal("unable to unmarshal forkexec:", ss)
			}
			rs.SysTime = ss.SysTime
			rs.UserTime = ss.UserTime
			log.Println("FORKEXEC:", ss)
			break
		} else if bytes.Contains(data, []byte("client_msg_stats")) {
			var cms ClientMsgStats
			err := json.Unmarshal(data, &cms)
			if err != nil {
				log.Fatal("unable to unmarshal client_msg_stats:", string(data))
			}
			// what do I want to keep out of the Client Message States
			// cms.Buckets stores how many were processed at time T
			// cms.RoundsAfter stores how many rounds delayed it was
			//
			// get the average delay (roundsAfter), max and min
			// get the total number of messages timestamped
			// get the average number of messages timestamped per second?
			avg, _, _, _ := ArrStats(cms.Buckets)
			// get the observed rate of processed messages
			// avg is how many messages per second, we want how many milliseconds between messages
			observed := avg / 1000 // set avg to messages per milliseconds
			observed = 1 / observed
			rs.Rate = observed
		}
	}
	return rs
}

func ArrStats(stream []float64) (avg float64, min float64, max float64, stddev float64) {
	// truncate trailing 0s
	i := len(stream) - 1
	for ; i >= 0; i-- {
		if math.Abs(stream[i]) > 0.01 {
			break
		}
	}
	stream = stream[:i+1]

	k := float64(1)
	first := true
	var M, S float64
	for _, e := range stream {
		if first {
			first = false
			min = e
			max = e
		}
		if e < min {
			min = e
		} else if max < e {
			max = e
		}
		avg = ((avg * (k - 1)) + e) / k
		var tM = M
		M += (e - tM) / k
		S += (e - tM) * (e - M)
		k++
		stddev = math.Sqrt(S / (k - 1))
	}
	return avg, min, max, stddev
}

type T struct {
	hpn   int
	bf    int
	nmsgs int
	rate  int
}

// hpn, bf, nmsgsG
func RunTest(t T) RunStats {
	hpn := fmt.Sprintf("-hpn=%d", t.hpn)
	bf := fmt.Sprintf("-bf=%d", t.bf)
	nmsgs := fmt.Sprintf("-nmsgs=%d", t.nmsgs)
	rate := fmt.Sprintf("-rate=%d", t.rate)
	cmd := exec.Command("./deploy2deter", hpn, bf, nmsgs, rate, debug)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Start()
	if err != nil {
		log.Fatal(err)
	}
	// give it a while to start up
	time.Sleep(3 * time.Minute)
	rs := Monitor()
	cmd.Process.Kill()
	fmt.Println("TEST COMPLETE:", rs)
	return rs
}

func MkTestDir() {
	err := os.MkdirAll("test_data/", 0777)
	if err != nil {
		log.Fatal("failed to make test directory")
	}
}

func TestFile(name string) string {
	return "test_data/" + name
}

// RunTests runs the given tests and puts the output into the
// given file name. It outputs RunStats in a CSV format.
func RunTests(name string, ts []T) {
	rs := make([]RunStats, len(ts))
	for i, t := range ts {
		rs[i] = RunTest(t)
	}
	output := rs[0].CSVHeader()
	for _, s := range rs {
		output = append(output, s.CSV()...)
	}
	err := ioutil.WriteFile(TestFile(name), output, 0660)
	if err != nil {
		log.Fatal("failed to write out test file:", name)
	}
}

// hpn=1 bf=2 nmsgs=700
var TestT = []T{
	{1, 2, 700, -1},
	{1, 2, -1, 1},
}

func LoadTest(hpn, bf, low, high, step int) []T {
	n := (high - low) / step
	ts := make([]T, 0, n)
	for nmsgs := low; nmsgs <= high; nmsgs += step {
		ts = append(ts, T{hpn, bf, nmsgs, -1})
	}
	return ts
}

// high and low specify how many milliseconds between messages
func RateLoadTest(hpn, bf int) []T {
	return []T{
		{hpn, bf, -1, 50000000}, // never send a message
		{hpn, bf, -1, 5000},     // one per round
		{hpn, bf, -1, 500},      // 10 per round
		{hpn, bf, -1, 50},       // 100 per round
		{hpn, bf, -1, 5},        // 1000 per round
		{hpn, bf, -1, 1},        // 5000 per round
	}
}

func DepthTest(hpn, low, high, step int) []T {
	ts := make([]T, 0)
	for bf := low; bf <= high; bf += step {
		ts = append(ts, T{hpn, bf, 7000, -1})
	}
	return ts
}

func main() {
	view = true
	os.Chdir("..")
	MkTestDir()
	err := exec.Command("go", "build", "-v").Run()
	if err != nil {
		log.Println(err)
	}
	// test the testing framework
	t := TestT
	RunTests("test", t)

	t = RateLoadTest(40, 10)
	RunTests("load_rate_test_bf10", t)
	t = RateLoadTest(40, 50)
	RunTests("load_rate_test_bf50", t)

	t = LoadTest(40, 10, 0, 10000, 1000)
	RunTests("load_test_bf10", t)
	t = LoadTest(40, 50, 0, 10000, 1000)
	RunTests("load_test_bf50", t)

	t = DepthTest(40, 10, 50, 10)
	RunTests("depth_test", t)
}
