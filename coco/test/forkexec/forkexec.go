package main

import (
	"flag"
	"io/ioutil"
	"os/exec"
	"strconv"

	log "github.com/Sirupsen/logrus"
	"github.com/dedis/prifi/coco/test/logutils"
)

// Wrapper around exec.go to enable measuring of cpu time

var hostname string
var configFile string
var logger string
var app string
var nrounds int
var pprofaddr string
var physaddr string
var rootwait int
var debug bool

// TODO: add debug flag for more debugging information (memprofilerate...)
func init() {
	flag.StringVar(&hostname, "hostname", "", "the hostname of this node")
	flag.StringVar(&configFile, "config", "cfg.json", "the json configuration file")
	flag.StringVar(&logger, "logger", "", "remote logger")
	flag.StringVar(&app, "app", "time", "application to run [sign|time]")
	flag.IntVar(&nrounds, "nrounds", 100, "number of rounds to run")
	flag.StringVar(&pprofaddr, "pprof", ":10000", "the address to run the pprof server at")
	flag.StringVar(&physaddr, "physaddr", "", "the physical address of the noded [for deterlab]")
	flag.IntVar(&rootwait, "rootwait", 30, "the amount of time the root should wait")
	flag.BoolVar(&debug, "debug", false, "set debugging")
}

func main() {
	flag.Parse()

	// connect with the logging server
	if logger != "" {
		// blocks until we can connect to the logger
		lh, err := logutils.NewLoggerHook(logger, hostname, app)
		if err != nil {
			log.WithFields(log.Fields{
				"file": logutils.File(),
			}).Fatalln("ERROR SETTING UP LOGGING SERVER:", err)
		}
		log.AddHook(lh)
		log.SetOutput(ioutil.Discard)
		//log.Println("Log Test")
		//fmt.Println("exiting logger block")
	}

	// recombine the flags for exec to use
	nargs := 9
	args := make([]string, nargs)
	args[0] = "-hostname=" + hostname
	args[1] = "-configFile=" + configFile
	args[2] = "-logger=" + logger
	args[3] = "-app=" + app
	args[4] = "-nrounds=" + strconv.Itoa(nrounds)
	args[5] = "-pprofaddr=" + pprofaddr
	args[6] = "-physaddr=" + physaddr
	args[7] = "-rootwait=" + strconv.Itoa(rootwait)
	args[8] = "-debug=" + strconv.FormatBool(debug)

	onearg := ""
	for i := 0; i < nargs; i++ {
		onearg = onearg + args[i]
	}

	cmd := exec.Command("exec", onearg)
	err := cmd.Run()
	if err != nil {
		log.Errorln("cmd run:" + err.Error())
	}

	// get CPU usage stats
	st := cmd.ProcessState.SystemTime()
	ut := cmd.ProcessState.UserTime()
	log.WithFields(log.Fields{
		"file":     logutils.File(),
		"type":     "forkexec",
		"systime":  st,
		"usertime": ut,
	}).Info("")

}
