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
	hc, err := LoadConfig("data/exconf.json")
	if err != nil {
		t.Fatal("error parsing json file:", err)
	}
	if err := ioutil.WriteFile("data/exconf_wkeys.json", []byte(hc.String()), 0666); err != nil {
		t.Fatal(err)
	}
	hc, err = LoadConfig("data/exconf_wkeys.json")
	if err != nil {
		t.Fatal(err)
	}
	err = hc.Run()
	if err != nil {
		t.Fatal(err)
	}
	log.Println("announcing")
	hc.SNodes[0].logTest = []byte("Hello World")
	err = hc.SNodes[0].Announce(&AnnouncementMessage{hc.SNodes[0].logTest})
	if err != nil {
		t.Fatal(err)
	}
}
