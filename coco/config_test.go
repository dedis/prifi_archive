package coco

import "testing"

func TestLoadConfig(t *testing.T) {
	_, err := LoadConfig("data/exconf.json")
	if err != nil {
		t.Error("error parsing json file:", err)
	}
}
