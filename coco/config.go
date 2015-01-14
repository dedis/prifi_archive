package coco

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
)

/*
file format: json

ex.json
{
	hosts: ["host1", "host2", "host3"],
	tree: {host1:{
		    host2:{},
			host3:{}}
		  }
}

*/

type HostConfig struct {
	Hosts map[string]*HostNode // maps hostname to host
	Dir   *directory
}

func NewHostConfig() *HostConfig {
	return &HostConfig{make(map[string]*HostNode), newDirectory()}
}

// Depth-First search construction of the host tree
func ConstructTree(tree map[string]interface{}, hc *HostConfig, parent Peer) error {
	// get the first key in the tree there should only be one
	for k, v := range tree {
		if _, ok := hc.Hosts[k]; !ok {
			fmt.Println("unknown host in tree:", k)
			return errors.New("unknown host in tree")
		}

		h := hc.Hosts[k]
		h.parent = parent
		// this key should map to a map[string]interface{} that represents the
		// rest of the tree
		rest := v.(map[string]interface{})
		for child := range rest {
			gp, err := NewGoPeer(hc.Dir, child)
			if err != nil {
				h.AddChildren(gp)
			}
		}
		ConstructTree(rest, hc, hc.Dir.nameToPeer[h.name])
	}
	return nil
}

func ReadConfig(fname string) (*HostConfig, error) {
	hc := NewHostConfig()
	file, err := ioutil.ReadFile(fname)
	if err != nil {
		return hc, err
	}
	var m map[string]interface{}
	json.Unmarshal(file, &m)
	// read the hosts lists
	hnames := m["hosts"].([]string)
	for _, h := range hnames {
		// add to the hosts list if we havent added it before
		if _, ok := hc.Hosts[h]; !ok {
			hc.Hosts[h] = NewHostNode(h)
		}
	}
	tree := m["tree"].(map[string]interface{})
	ConstructTree(tree, hc, nil)
	// construct the host tree
	return hc, nil
}
