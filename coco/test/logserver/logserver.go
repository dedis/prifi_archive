package main

import (
	"flag"
	"html/template"
	"math/rand"
	"net/http"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"

	"golang.org/x/net/websocket"
)

var addr string
var homePage *template.Template

type Home struct {
	LogServer string
}

func init() {
	flag.StringVar(&addr, "addr", "", "the address of the logging server")
}

var Log Logger

func init() {
	Log = Logger{
		Slock: sync.RWMutex{},
		Sox:   make(map[*websocket.Conn]bool),
		Mlock: sync.RWMutex{},
		Msgs:  make([][]byte, 0, 100000),
	}
	rand.Seed(42)
}

type Logger struct {
	Slock sync.RWMutex
	Sox   map[*websocket.Conn]bool

	Mlock sync.RWMutex
	Msgs  [][]byte
	End   int
}

// keep a list of websockets that people are listening on

// keep a log of messages received

func logEntryHandler(ws *websocket.Conn) {
	var data []byte
	err := websocket.Message.Receive(ws, &data)
	for err == nil {
		log.Println("RECEIVED LOG ENTRY")
		Log.Mlock.Lock()
		Log.Msgs = append(Log.Msgs, data)
		Log.End += 1
		Log.Mlock.Unlock()
		err = websocket.Message.Receive(ws, &data)
	}
	log.Println("log server client error")
}

func logHandler(ws *websocket.Conn) {
	log.Println("LOG HANDLER")
	i := 0
	for {
		Log.Mlock.RLock()
		end := Log.End
		Log.Mlock.RUnlock()
		if i >= end {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		Log.Mlock.RLock()
		msg := Log.Msgs[i]
		Log.Mlock.RUnlock()
		_, err := ws.Write(msg)
		if err != nil {
			log.Println("unable to write to log websocket")
			return
		}

		i++
	}
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("HOME HANDLER: ", r.URL)
	err := homePage.Execute(w, Home{"ws://" + addr + "/log"})
	if err != nil {
		panic(err)
		log.Fatal(err)
	}
}

func main() {
	// read in from flags the port I should be listening on
	flag.Parse()
	var err error
	homePage, err = template.ParseFiles("home.html")
	if err != nil {
		log.Fatal("unable to parse home.html")
	}
	//("./home.html")
	if err != nil {
		log.Fatal("failed to read homepage")
	}
	log.Println("LOG SERVER RUNNING AT:", addr)
	// /bower_components/Chart.js/Chart.min.js
	http.HandleFunc("/", homeHandler)
	fs := http.FileServer(http.Dir("bower_components/"))
	http.Handle("/bower_components/", http.StripPrefix("/bower_components/", fs))
	http.Handle("/_log", websocket.Handler(logEntryHandler))
	http.Handle("/log", websocket.Handler(logHandler))
	log.Fatalln("ERROR: ", http.ListenAndServe(addr, nil))
	// now combine that port
}
