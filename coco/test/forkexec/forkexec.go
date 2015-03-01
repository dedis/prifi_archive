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
	// log.Println("IN FORK EXEC")
	// recombine the flags for exec to use
	args := []string{
		"-hostname=" + hostname,
		"-config=" + configFile,
		"-logger=" + logger,
		"-app=" + app,
		"-nrounds=" + strconv.Itoa(nrounds),
		"-pprof=" + pprofaddr,
		"-physaddr=" + physaddr,
		"-rootwait=" + strconv.Itoa(rootwait),
		"-debug=" + strconv.FormatBool(debug),
	}
	//infos, _ := ioutil.ReadDir(".")*/
	//for _, i := range infos {
	//if i.Name() == "exec" {
	//log.Println("exec file exists")
	//}
	//}
	cmd := exec.Command("./exec", args...)
	//cmd.Stdout = log.StandardLogger().Writer()
	//cmd.Stderr = log.StandardLogger().Writer()
	//log.Println("running command:", cmd)
	err := cmd.Run()
	if err != nil {
		log.Errorln("cmd run:", err)
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
