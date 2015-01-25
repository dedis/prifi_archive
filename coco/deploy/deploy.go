package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/dedis/prifi/coco"
)

// deploy usage:
//
//   deploy -mode "planetlab"|"zoo" -hosts "host1,host2" -config "cfg.json"
//
// hosts is a list of hostnames
// import "github.com/kolo/xmlrpc"

var configFile string
var mode string
var hostList string
var logFile string

var LogWriter io.Writer

func init() {
	flag.StringVar(&configFile, "config", "cfg.json", "the json configuration file")
	flag.StringVar(&mode, "mode", "zoo", "the deployment system")
	flag.StringVar(&hostList, "hosts", "", "list of hostnames to replace in the config")
	flag.StringVar(&logFile, "log", "", "log file to write to")
}

func LaunchZoo() {

}

func handleLogRequest(conn net.Conn) {
	buf := make([]byte, 0, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			fmt.Println("read error:", err)
			break
		}
		log.Print(string(buf[:n])) // duplex to file
	}
}

func StartLoggingServer(port string) {
	ln, err := net.Listen("tcp", ":9000")
	if err != nil {
		// handle error
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			// handle error
		}
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

func main() {
	zoo := true
	flag.Parse()
	SetupLogs()
	// establish logging server to listen to remote connections
	go StartLoggingServer(":9000")
	log.Println("started logging server")
	addr, err := coco.GetAddress()
	if err != nil {
		log.Fatal(err)
	}

	log.Println("parsing hosts")
	logserver := addr + ":9000"
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
	hc, err := coco.LoadJSON(b, coco.ConfigOptions{ConnType: "tcp", Hostnames: hostnames})
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
	for _, host := range hostnames {
		h := strings.Split(host, ":")[0]
		if zoo {
			h = "dmv29@" + h
		}
		log.Println("starting scp: ", h)
		cmd := exec.Command("scp", "-C", "-B", f.Name(), h+":"+f.Name())
		cmd.Stdout = LogWriter
		cmd.Stderr = LogWriter
		err := cmd.Run()
		if err != nil {
			log.Fatal("scp failed on: ", h, err)
		}
		// only need to send one file to the zoo
		if zoo {
			break
		}
	}

	log.Println("starting build process")
	// build the coco/exec for the target architectures
	cmd := exec.Command("go", "build", "-v", "github.com/dedis/prifi/coco/exec")
	cmd.Stdout = LogWriter
	cmd.Stderr = LogWriter
	cmd.Env = append([]string{"GOOS=linux"}, os.Environ()...)
	cmd.Run()

	log.Println("sending executable")
	// scp that file to the hosts
	// send this file to the hosts (using proper authentication)
	for _, host := range hostnames {
		h := strings.Split(host, ":")[0]
		if zoo {
			h = "dmv29@" + h
		}
		cmd := exec.Command("scp", "-C", "-B", "exec", h+":"+"cocoexec")
		cmd.Stdout = LogWriter
		cmd.Stderr = LogWriter
		err := cmd.Run()
		if err != nil {
			log.Fatal(err)
		}
		if zoo {
			break
		}
	}

	// ssh run the file on each of the hosts
	for _, host := range hostnames {
		h := strings.Split(host, ":")[0]
		if zoo {
			h = "dmv29@" + h
		}
		cmd := exec.Command("ssh", "-o", "BatchMode", h,
			"'./cocoexec -hostname "+host+" -config "+f.Name()+" -logger "+logserver+"'")
		cmd.Stdout = LogWriter
		cmd.Stderr = LogWriter
		err := cmd.Run()
		if err != nil {
			log.Fatal(err)
		}
	}

}
