package main

import (
    "fmt"
    "net/http"
	"net/url"
	"io/ioutil"
)

func main() {
	text := "just testing a simple echo server"
	resp, err := http.PostForm("http://localhost:8080",
			url.Values{"echo": {text}})
	if err != nil {
		panic("Request failed")
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	fmt.Printf("%s\n", body)
}
