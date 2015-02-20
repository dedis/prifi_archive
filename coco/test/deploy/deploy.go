package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"

	"github.com/dedis/prifi/coco/test/oldconfig"
)

// deploy usage:
//
//   deploy -mode "planetlab"|"zoo" -hosts "host1,host2" -config "cfg.json"
//
// example: go run deploy.go -mode zoo -config ../data/zoo.json -u name
//          go run deploy.go -mode pl -arch 386 -u yale_dissent -config ../data/zoo.json -hosts h1,h2,h3,h4,h5,h6

var configFile string
var mode string
var hostList string
var logFile string
var portRewrite string
var username string
var rarch string
var ros string
var clean string

var LogWriter io.Writer

func init() {
	flag.StringVar(&configFile, "config", "cfg.json", "the json configuration file")
	flag.StringVar(&mode, "mode", "zoo", "the deployment system")
	flag.StringVar(&hostList, "hosts", "", "list of hostnames to replace in the config")
	flag.StringVar(&logFile, "log", "", "log file to write to")
	flag.StringVar(&portRewrite, "p", "", "rewrite rule for hosts, what their port should be")
	flag.StringVar(&username, "u", "", "the username that should be used when logging into hosts")
	flag.StringVar(&rarch, "arch", "amd64", "the architecture of the hostmachines")
	flag.StringVar(&ros, "os", "linux", "the operating system of the hostmachines")
	flag.StringVar(&clean, "clean", "false", "clean config files off of host")
}

var WG sync.WaitGroup

// handles a log request from one of the remote connections
func handleLogRequest(conn net.Conn) {
	buf := make([]byte, 0, 4096)
	for {
		n, err := conn.Read(buf)
		if err == io.EOF {
			// log.Println("EOF")
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if err != nil {
			log.Println("READ ERROR:", err)
			break
		}
		fmt.Println("RECEIVED LOG REQUEST:")
		log.Print(string(buf[:n])) // duplex to file
	}
	// main waits on done to return from all
	WG.Done()
}

func StartLoggingServer(port string) {
	ln, err := net.Listen("tcp", ":9000")
	if err != nil {
		fmt.Println(err)
		log.Fatal(err)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println("ERROR: error accepting connection: ", err)
			continue
			// handle error
		}
		WG.Add(1)
		log.Println("accepted connection")
		go handleLogRequest(conn)

	}
}

func SetupLogs() {
	var err error
	var logf *os.File
	if logFile == "" {
		logf, err = ioutil.TempFile("", "log")
	} else {
		logf, err = os.OpenFile(logFile, os.O_WRONLY|os.O_CREATE, 0640)
	}
	if err != nil {
		log.Fatal(err)
	}
	LogWriter = io.MultiWriter(logf, os.Stdout)
	log.SetOutput(LogWriter)
}

func BuildExec() chan bool {
	ch := make(chan bool)
	go func(ch chan bool) {
		log.Println("starting build process")
		// build the coco/exec for the target architectures
		cmd := exec.Command("go", "build", "-v", "../exec")
		cmd.Stdout = LogWriter
		cmd.Stderr = LogWriter
		cmd.Env = append([]string{"GOOS=" + ros, "GOARCH=" + rarch}, os.Environ()...)
		log.Println("about to run build")
		err := cmd.Run()
		if err != nil {
			log.Println(err)
		}
		log.Println("sending to done:", ch)
		ch <- true
	}(ch)
	return ch
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	flag.Parse()
	zoo := true
	if mode == "pl" || mode == "planetlab" {
		zoo = false
	}
	SetupLogs()
	Done := BuildExec()
	// establish logging server to listen to remote connections
	go StartLoggingServer(":9000")
	log.Println("started logging server")
	addr, err := oldconfig.GetAddress()
	if err != nil {
		addr = ""
	}

	log.Println("parsing hosts")
	logserver := addr + ":9000"
	if addr != "" {
		logserver = ""
	}
	log.Print(logserver)

	// parse out the hostnames
	var hostnames []string
	if hostList != "" {
		temp := strings.Split(hostList, ",")
		for i := range temp {
			temp[i] = strings.TrimSpace(temp[i])
			if temp[i] != "" {
				hostnames = append(hostnames, temp[i])
			}
		}
	}
	log.Println("hosts: ", hostnames)

	// update the config to represent a tcp configuration with the given hostnames
	b, err := ioutil.ReadFile(configFile)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("REWRITING PORT:", portRewrite)
	hc, err := oldconfig.LoadJSON(b, oldconfig.ConfigOptions{ConnType: "tcp", Hostnames: hostnames, Port: portRewrite})
	if err != nil {
		log.Fatal("bad config file:", err)
	}
	f, err := ioutil.TempFile("./", "config")
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile(f.Name(), []byte(hc.String()), 0666)
	if err != nil {
		log.Fatal(err)
	}

	// get the definative list of hostnames
	hostnames = make([]string, 0, len(hc.Hosts))
	for h := range hc.Hosts {
		hostnames = append(hostnames, h)
	}

	log.Println("final hostnames: ", hostnames)

	log.Println("sending configuration file")
	// send this file to the hosts (using proper authentication)
	var wg sync.WaitGroup
	// if clean == "true" {
	// 	for _, host := range hostnames {
	// 		wg.Add(1)
	// 		go func(host string) {
	// 			defer wg.Done()
	// 			h := strings.Split(host, ":")[0]
	// 			if username != "" {
	// 				h = username + "@" + h
	// 			}
	// 			cmd := exec.Command("ssh", h,
	// 				"rm config*")
	// 			log.Println(cmd.Args)
	// 			cmd.Stdout = LogWriter
	// 			cmd.Stderr = LogWriter
	// 			err := cmd.Run()
	// 			if err != nil {
	// 				log.Println(h, err)
	// 			}
	// 		}(host)
	// 	}
	// 	wg.Wait()
	// }
	log.Println("waiting for done: ", Done)
	<-Done
	log.Println("done")
	for _, host := range hostnames {
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			h := strings.Split(host, ":")[0]
			if username != "" {
				h = username + "@" + h
			}
			log.Println("starting scp: ", h)
			cmd := exec.Command("scp", "-C", "-B", f.Name(), h+":"+f.Name())
			cmd.Stdout = LogWriter
			cmd.Stderr = LogWriter
			err := cmd.Run()
			if err != nil {
				log.Fatal("scp failed on: ", h, err)
			}
		}(host)
		// only need to send one file to the zoo
		if zoo {
			break
		}
	}
	wg.Wait()
	log.Println("waiting for build to finish")
	// <-buildDone
	log.Println("sending executable")

	// scp that file to the hosts
	// send this file to the hosts (using proper authentication)
	for _, host := range hostnames {
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			h := strings.Split(host, ":")[0]
			if username != "" {
				h = username + "@" + h
			}
			cmd := exec.Command("scp", "-C", "exec", h+":"+"cocoexec")
			cmd.Stdout = LogWriter
			cmd.Stderr = LogWriter
			log.Println("scp binary to ", h)
			err := cmd.Run()
			if err != nil {
				log.Fatal(h, ": scp:", err)
			}
			err = exec.Command("ssh", h,
				"eval 'chmod +x cocoexec'").Run()
			if err != nil {
				log.Print(h, ": chmod:", err)
			}
		}(host)
		if zoo {
			break
		}
	}
	wg.Wait()

	// ssh run the file on each of the hosts
	for _, host := range hostnames {
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			h := strings.Split(host, ":")[0]
			if username != "" {
				h = username + "@" + h
			}
			cmd := exec.Command("ssh", h,
				"eval './cocoexec -hostname "+host+" -config "+f.Name()+" -logger "+logserver+"'")
			log.Println(cmd.Args)
			cmd.Stdout = LogWriter
			cmd.Stderr = LogWriter
			err := cmd.Run()
			if err != nil {
				log.Println(h, err)
			}
		}(host)
	}
	wg.Wait()
	fmt.Println("All children have completed")
}
