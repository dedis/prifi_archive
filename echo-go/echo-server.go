package main

import (
    "encoding/json"
    "net/http"
)

type Echo struct {
    Text string `json:"text"`
}
    
func handler(w http.ResponseWriter, r *http.Request) {
    decoder := json.NewDecoder(r.Body)
    var echo Echo
    err := decoder.Decode(&echo)
    if err != nil {
        panic("malformed post data")
    }
    encoder := json.NewEncoder(w)
    encoder.Encode(echo)
}

func main() {
    http.HandleFunc("/echo", handler)
    http.ListenAndServe(":8080", nil)
}
