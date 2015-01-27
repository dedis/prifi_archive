package coco

import (
	"io/ioutil"
	"log"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	_, err := LoadConfig("data/exconf.json")
	if err != nil {
		t.Error("error parsing json file:", err)
	}
}

func TestPubKeysConfig(t *testing.T) {
	hc, err := LoadConfig("data/exconf.json", ConfigOptions{ConnType: "tcp", GenHosts: true})
	if err != nil {
		t.Fatal("error parsing json file:", err)
	}
	if err := ioutil.WriteFile("data/exconf_wkeys.json", []byte(hc.String()), 0666); err != nil {
		t.Fatal(err)
	}
}

func TestPubKeysOneNode(t *testing.T) {
	// has hosts 8089 - 9094 @ 172.27.187.80
	done := make(chan bool)
	hosts := []string{"172.27.187.80:8095",
		"172.27.187.80:8096",
		"172.27.187.80:8097",
		"172.27.187.80:8098",
		"172.27.187.80:8099",
		"172.27.187.80:8100"}
	for _, host := range hosts {
		go func(host string) {
			hc, err := LoadConfig("data/exconf_wkeys.json", ConfigOptions{ConnType: "tcp", Host: host})
			if err != nil {
				t.Fatal(err)
			}
			log.Println("Loaded Config For: ", host)
			log.Printf("%#+v\n", hc)
			log.Println(hc.String())
			err = hc.Run(host)
			if err != nil {
				t.Fatal(err)
			}
			log.Println("announcing")
			if hc.SNodes[0].IsRoot() {
				hc.SNodes[0].LogTest = []byte("Hello World")
				err = hc.SNodes[0].Announce(&AnnouncementMessage{hc.SNodes[0].LogTest})
				if err != nil {
					t.Fatal(err)
				}
				done <- true
			}
		}(host)
	}
	<-done
}
