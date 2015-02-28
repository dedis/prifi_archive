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
	"golang.org/x/net/websocket"
)

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

type RunStats struct {
	NHosts int
	Depth  int

	MinTime float64
	MaxTime float64
	AvgTime float64
	StdDev  float64

	SysTime  float64
	UserTime float64
}

func (s RunStats) CSVHeader() []byte {
	var buf bytes.Buffer
	buf.WriteString("hosts, depth, min, max, avg, stddev, systime, usertime\n")
	return buf.Bytes()
}
func (s RunStats) CSV() []byte {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%d, %d, %f, %f, %f, %f, %f, %f\n",
		s.NHosts,
		s.Depth,
		s.MinTime,
		s.MaxTime,
		s.AvgTime,
		s.StdDev,
		s.SysTime,
		s.UserTime)
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

type SysStats struct {
	File     string  `json:"file"`
	Type     string  `json:"type"`
	SysTime  float64 `json:"systime"`
	UserTime float64 `json:"usertime"`
}

// Monitor: monitors log aggregates results into RunStats
func Monitor() RunStats {
	log.Println("MONITORING")
	defer fmt.Println("DONE MONITORING")
retry:
	ws, err := websocket.Dial("ws://localhost:8080/log", "", "http://localhost/")
	if err != nil {
		time.Sleep(1 * time.Second)
		goto retry
	}
	// Get HTML of webpage for data (NHosts, Depth, ...)
	doc, err := goquery.NewDocument("http://localhost:8080/")
	if err != nil {
		log.Println("unable to get log data: retrying:", err)
		goto retry
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
		}
	}
	return rs
}

type T struct {
	hpn   int
	bf    int
	nmsgs int
}

// hpn, bf, nmsgsG
func RunTest(t T) RunStats {
	hpn := fmt.Sprintf("-hpn=%d", t.hpn)
	bf := fmt.Sprintf("-bf=%d", t.bf)
	nmsgs := fmt.Sprintf("-nmsgs=%d", t.nmsgs)
	cmd := exec.Command("./deploy2deter", hpn, bf, nmsgs, "-debug=true")
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
	{1, 2, 700},
}

func LoadTest(hpn, bf, low, high, step int) []T {
	n := (high - low) / step
	ts := make([]T, 0, n)
	for nmsgs := low; nmsgs <= high; nmsgs += step {
		ts = append(ts, T{hpn, bf, nmsgs})
	}
	return ts
}

func DepthTest(hpn, low, high, step int) []T {
	ts := make([]T, 0)
	for bf := low; bf <= high; bf += step {
		ts = append(ts, T{hpn, bf, 7000})
	}
	return ts
}

func main() {
	os.Chdir("..")
	MkTestDir()
	err := exec.Command("go", "build", "-v").Run()
	if err != nil {
		log.Println(err)
	}
	//t := TestT
	//RunTests("test", t)
	t := LoadTest(40, 10, 0, 10000, 1000)
	RunTests("load_test_bf10", t)
	t = LoadTest(40, 50, 0, 10000, 1000)
	RunTests("load_test_bf50", t)
	t = DepthTest(40, 10, 50, 10)
	RunTests("depth_test", t)
}
