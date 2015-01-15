package coco

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
)

/*
Example configuration file.
file format: json

ex.json
{
	hosts: ["host1", "host2", "host3"],
	tree: {host1:{
		    host2:{},
			host3:{}}
		  }
}

This will be compiled into the specified tree structure with HostNode Hosts and goPeer Peers.
*/

// HostConfig stores all of the relevant information of the configuration file.
type HostConfig struct {
	Hosts map[string]*HostNode // maps hostname to host
	Dir   *directory           // the directory mapping hostnames to goPeers
	Root  *HostNode            // the host root of the tree
}

// NewHostConfig creates a new host configuration that can be populated with
// hosts.
func NewHostConfig() *HostConfig {
	return &HostConfig{Hosts: make(map[string]*HostNode), Dir: newDirectory(), Root: nil}
}

// ConstructTree does a depth-first construction of the tree specified in the
// config file. It detects unknown hosts but does not detect the error of
// multiple root nodes, rather it silently choses just one. ConstructTree must
// be call AFTER populating the HostConfig with ALL the possible hosts.
func ConstructTree(tree map[string]interface{}, hc *HostConfig, parent Peer) error {
	// each k will be a sibling in the tree
	// for each sibling add its children
	for k, subtree := range tree {
		if _, ok := hc.Hosts[k]; !ok {
			fmt.Println("unknown host in tree:", k)
			return errors.New("unknown host in tree")
		}
		h := hc.Hosts[k]
		if parent == nil {
			fmt.Printf("root node is %v\n", h.name)
			hc.Root = h
		}
		h.parent = parent

		children := subtree.(map[string]interface{})
		for child := range children {
			// ignore the error because we don't care if we have already
			// constructed this peer before.
			gp, _ := NewGoPeer(hc.Dir, child)
			h.AddChildren(gp)
			fmt.Printf("added %v as child of %v\n", gp.hostname, h.name)
		}
		if err := ConstructTree(children, hc, hc.Dir.nameToPeer[h.name]); err != nil {
			return err
		}
	}
	return nil
}

// LoadConfig loads a configuration file in the format specified above. It
// populates a HostConfig with HostNode Hosts and goPeer Peers.
func LoadConfig(fname string) (*HostConfig, error) {
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
	err = ConstructTree(tree, hc, nil)
	// construct the host tree
	return hc, err
}
