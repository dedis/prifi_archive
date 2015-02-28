package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"math"
	"os/exec"
	"strconv"
	"time"

	"github.com/PuerkitoBio/goquery"
	"golang.org/x/net/websocket"
)

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

func (s RunStats) CSVHeader() []byte {
	var buf bytes.Buffer
	buf.WriteString("hosts, depth, min, max, avg, stddev\n")
}
func (s RunStats) CSV() []byte {
	var buf bytes.Buffer
	fmt.FPrintf(&buf, "%d, %d, %f, %f, %f, %f\n",
		s.NHosts,
		s.Depth,
		s.MinTime,
		s.MaxTime,
		s.AvgTime,
		s.StdDev)
}

// Monitor: monitors log aggregates results into RunStats
func Monitor() RunStats {
retry:
	ws, err := websocket.Dial("ws://localhost:8080/log", "", "http://localhost/")
	if err != nil {
		time.Sleep(1 * time.Second)
		goto retry
	}
	// Get HTML of webpage for data (NHosts, Depth, ...)
	doc, err := goquery.NewDocument("http://localhost:8080/")
	if err != nil {
		log.Fatal("unable to get log data")
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
	rs.NHost = nh
	rs.Depth = d

	var M, S float64
	k := float64(1)
	first := true
	for {
		var entry StatsEntry
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
			break
		}
		if bytes.Contains(data, []byte("root_round")) {
			err := json.Unmarshal(data, entry)
			if err != nil {
				log.Fatal("json unmarshalled improperly")
			}
			if first {
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
		}
	}
	return rs
}

func RunTest(hpn, bf, nmsgs int) RunStats {
	cmdstr := fmt.Sprintf("./deploy2deter -hpn=%d -bf=%d -nmsgs=%d", hpn, bf, msgs)
	cmd := exec.Command("bash -c \"" + cmdstr + "\"")
	err := cmd.Start()
	if err != nil {
		log.Fatal(err)
	}
	rs := Monitor()
	cmd.Process.Kill()
	return rs
}
