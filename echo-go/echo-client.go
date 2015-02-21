package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "net/http"
	"io/ioutil"
)

type Echo struct {
    Text string `json:"text"`
}

func main() {
    echo := new(Echo)
	echo.Text = "just testing a simple echo server"
    post, err := json.Marshal(echo)
	resp, err := http.Post("http://localhost:8080/echo",
			"application/json",
            bytes.NewReader(post))
	if err != nil {
		panic("Request failed")
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	fmt.Printf("%s\n", body)
}
