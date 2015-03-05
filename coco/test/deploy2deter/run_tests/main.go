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
	"errors"
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

	BF int

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
	buf.WriteString("hosts, depth, bf, min, max, avg, stddev, systime, usertime, rate\n")
	return buf.Bytes()
}
func (s RunStats) CSV() []byte {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%d, %d, %d, %f, %f, %f, %f, %f, %f, %f\n",
		s.NHosts,
		s.Depth,
		s.BF,
		s.MinTime,
		s.MaxTime,
		s.AvgTime,
		s.StdDev,
		s.SysTime,
		s.UserTime,
		s.Rate)
	return buf.Bytes()
}

func RunStatsAvg(rs []RunStats) RunStats {
	if len(rs) == 0 {
		return RunStats{}
	}
	r := RunStats{}
	r.NHosts = rs[0].NHosts
	r.Depth = rs[0].Depth
	r.BF = rs[0].BF

	for _, a := range rs {
		r.MinTime += a.MinTime
		r.MaxTime += a.MaxTime
		r.AvgTime += a.AvgTime
		r.StdDev += a.StdDev
		r.SysTime += a.SysTime
		r.UserTime += a.UserTime
		r.Rate += a.Rate
	}
	l := float64(len(rs))
	r.MinTime /= l
	r.MaxTime /= l
	r.AvgTime /= l
	r.StdDev /= l
	r.SysTime /= l
	r.UserTime /= l
	r.Rate /= l
	return r
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
	Buckets     []float64 `json:"buck,omitempty"`
	RoundsAfter []float64 `json:"roundsAfter,omitempty"`
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
func Monitor(bf int) RunStats {
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
	client_done := false
	root_done := false
	var rs RunStats
	rs.NHosts = nh
	rs.Depth = d
	rs.BF = bf

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
			log.Printf(
				"EOF/terminating Detected: need forkexec to report and clients: %b %b",
				root_done, client_done)
		}
		if bytes.Contains(data, []byte("root_round")) {
			if client_done || root_done {
				// ignore after we have received our first EOF
				continue
			}
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
			if root_done {
				continue
			}
			var ss SysStats
			err := json.Unmarshal(data, &ss)
			if err != nil {
				log.Fatal("unable to unmarshal forkexec:", ss)
			}
			rs.SysTime = ss.SysTime
			rs.UserTime = ss.UserTime
			log.Println("FORKEXEC:", ss)
			if client_done {
				break
			}
			root_done = true
		} else if bytes.Contains(data, []byte("client_msg_stats")) {
			if client_done {
				continue
			}
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
			if root_done {
				break
			}
			client_done = true
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
	hpn      int
	bf       int
	rate     int
	rounds   int
	failures int
}

func isZero(f float64) bool {
	return math.Abs(f) < 0.0000001
}

// hpn, bf, nmsgsG
func RunTest(t T) (RunStats, error) {
	// add timeout for 10 minutes?
	done := make(chan struct{})
	var rs RunStats
	hpn := fmt.Sprintf("-hpn=%d", t.hpn)
	nmsgs := fmt.Sprintf("-nmsgs=%d", -1)
	bf := fmt.Sprintf("-bf=%d", t.bf)
	rate := fmt.Sprintf("-rate=%d", t.rate)
	rounds := fmt.Sprintf("-rounds=%d", t.rounds)
	failures := fmt.Sprintf("-failures=%d", t.failures)
	cmd := exec.Command("./deploy2deter", hpn, nmsgs, bf, rate, rounds, debug, failures)
	log.Println("RUNNING TEST:", cmd.Args)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Start()
	if err != nil {
		log.Fatal(err)
	}
	// give it a while to start up
	time.Sleep(30 * time.Second)

	go func() {
		rs = Monitor(t.bf)
		cmd.Process.Kill()
		fmt.Println("TEST COMPLETE:", rs)
		done <- struct{}{}
	}()

	// timeout the command if it takes too long
	select {
	case <-done:
		if isZero(rs.MinTime) || isZero(rs.MaxTime) || isZero(rs.AvgTime) || math.IsNaN(rs.Rate) || math.IsInf(rs.Rate, 0) {
			return rs, errors.New("unable to get good data")
		}
		return rs, nil
	case <-time.After(10 * time.Minute):
		return rs, errors.New("timed out")
	}

	return rs, nil
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
	f, err := os.OpenFile(TestFile(name), os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0660)
	if err != nil {
		log.Fatal("error opening test file:", err)
	}
	_, err = f.Write(rs[0].CSVHeader())
	if err != nil {
		log.Fatal("error writing test file header:", err)
	}
	err = f.Sync()
	if err != nil {
		log.Fatal("error syncing test file:", err)
	}

	for i, t := range ts {
		// try three times
		// take the average of all successfull runs
		var runs []RunStats
		for r := 0; r < 3; r++ {
			run, err := RunTest(t)
			if err == nil {
				runs = append(runs, run)
			} else {
				log.Println("error running test:", err)
			}
		}
		if len(runs) == 0 {
			log.Println("unable to get any data for test:", t)
			continue
		}
		rs[i] = RunStatsAvg(runs)
		_, err := f.Write(rs[i].CSV())
		if err != nil {
			log.Fatal("error writing data to test file:", err)
		}
		err = f.Sync()
		if err != nil {
			log.Fatal("error syncing data to test file:", err)
		}
	}
}

// hpn=1, bf=2, rate=5000, failures=20
var TestT = []T{
	{1, 2, 5000, 5, 0},
	{1, 2, 5000, 10, 50},
	{10, 2, 5000, 10, 10},
}

// high and low specify how many milliseconds between messages
func RateLoadTest(hpn, bf int) []T {
	return []T{
		{hpn, bf, 5000, DefaultRounds, 0}, // never send a message
		{hpn, bf, 5000, DefaultRounds, 0}, // one per round
		{hpn, bf, 500, DefaultRounds, 0},  // 10 per round
		{hpn, bf, 50, DefaultRounds, 0},   // 100 per round
		{hpn, bf, 30, DefaultRounds, 0},   // 1000 per round
	}
}

func DepthTest(hpn, low, high, step int) []T {
	ts := make([]T, 0)
	for bf := low; bf <= high; bf += step {
		ts = append(ts, T{hpn, bf, 10, DefaultRounds, 0})
	}
	return ts
}

var DefaultRounds int = 100

func main() {
	// view = true
	os.Chdir("..")
	SetDebug(true)
	DefaultRounds = 10

	MkTestDir()

	err := exec.Command("go", "build", "-v").Run()
	if err != nil {
		log.Fatalln("error building deploy2deter:", err)
	}
	// test the testing framework

	t := TestT
	RunTests("test", t)
	// how does the branching factor effect speed
	t = DepthTest(100, 2, 100, 1)
	RunTests("depth_test.csv", t)

	// load test the client
	t = RateLoadTest(40, 10)
	RunTests("load_rate_test_bf10.csv", t)
	t = RateLoadTest(40, 50)
	RunTests("load_rate_test_bf50.csv", t)

}
