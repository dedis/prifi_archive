package time

import (
	"fmt"
	"sync"
	"time"

	"github.com/dedis/prifi/coco"
)

var ROUND_TIME time.Duration = 5 * time.Second

// File defines the server side of the interaction between
// Servers and Clients with the purpose of timestampting client messages
// Server will probably be intergrated with the SigningNodes eventually

func (s *Server) Listen() {
	var mux sync.Mutex
	READING := 0
	PROCESSING := 1
	Queue := make([][]TimeStampMessage, 2)
	Queue[READING] = make([]TimeStampMessage, 0)
	Queue[PROCESSING] = make([]TimeStampMessage, 0)
	for _, c := range s.clients {
		go func(c coco.Conn) {
			for {
				tsm := TimeStampMessage{}
				c.Get(&tsm)
				mux.Lock()
				Queue[READING] = append(Queue[READING], tsm)
				mux.Unlock()
			}
		}(c)
	}

	ticker := time.NewTicker(ROUND_TIME)
	for _ = range ticker.C {
		mux.Lock()
		READING, PROCESSING = PROCESSING, READING
		Queue[READING] = Queue[READING][:0]
		mux.Unlock()
		// aggregate messages from this round
		for msg := range Queue[PROCESSING] {
			// aggregate message
			fmt.Println(msg)
		}
	}
}

type Server struct {
	clients map[string]coco.Conn
}

type Client struct {
	name string
}
