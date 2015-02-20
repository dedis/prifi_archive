package logutils

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/Sirupsen/logrus"
	"golang.org/x/net/websocket"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

type LoggerHook struct {
	HostPort string
	Conn     *websocket.Conn
	f        logrus.Formatter
}

func File() string {
	_, file, line, ok := runtime.Caller(1)
	if !ok {
		file = "???"
		line = 0
	}
	short := file
	for i := len(file) - 1; i > 0; i-- {
		if file[i] == '/' {
			short = file[i+1:]
			break
		}
	}
	file = short
	return file + ":" + strconv.Itoa(line)
}

// host is my host: what machine I am running on
// hostport is the address of the logging server
// host
func NewLoggerHook(hostport, host, app string) (*LoggerHook, error) {
retry:
	addr := "ws://" + hostport + "/_log"
	ws, err := websocket.Dial(addr, "", "http://localhost/")
	if err != nil {
		log.Println("failed to connect to logger:", addr)
		time.Sleep(time.Second)
		goto retry
	}
	return &LoggerHook{hostport, ws, &JSONFormatter{host, app}}, err
}

// Fire is called when a log event is fired.
func (hook *LoggerHook) Fire(entry *logrus.Entry) error {
	// fmt.Println("running log hook")
	serialized, err := hook.f.Format(entry)
	if err != nil {
		return fmt.Errorf("Failed to  fields to format, %v", err)
	}
	// only report some subset of the client rounds
	if k, ok := entry.Data["type"]; ok && k.(string) == "client_round" {
		if rand.Intn(512) > 1 {
			return nil
		}
	}
	bytesWritten, err := hook.Conn.Write(serialized)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to send log line to Logger via TCP. Wrote %d bytes before error: %v", bytesWritten, err)
		return err
	}

	return nil
}

// Levels returns the available logging levels.
func (hook *LoggerHook) Levels() []logrus.Level {
	return []logrus.Level{
		logrus.PanicLevel,
		logrus.FatalLevel,
		logrus.ErrorLevel,
		logrus.WarnLevel,
		logrus.InfoLevel,
		logrus.DebugLevel,
	}
}

func (hook *LoggerHook) Close() {
	hook.Conn.Close()
}

type JSONFormatter struct {
	Host string
	App  string
}

func (f *JSONFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	data := make(logrus.Fields, len(entry.Data)+5)
	for k, v := range entry.Data {
		data[k] = v
	}
	data["entry.host"] = f.Host // the host that this is running on
	data["entry.app"] = f.App   // what app we are running (timeclient, timestamper, signer)
	data["entry.time"] = entry.Time.Format(time.RFC3339)
	data["entry.msg"] = entry.Message
	data["entry.level"] = entry.Level.String()

	serialized, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("Failed to marshal fields to JSON, %v", err)
	}
	return append(serialized, '\n'), nil
}
