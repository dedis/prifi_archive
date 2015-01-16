package coco

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/openssl"
)

/*
Example configuration file.
file format: json

ex.json
{
	hosts: ["host1", "host2", "host3"],
	tree: {name: host1,
		   children: [
		     {name: host2,
			  children: [{name: host3}, {name: host4}]}
			 {name: host5,
			  children: [{name: host6}]}}
}
*/
type ConfigFile struct {
	Hosts []string `json:"hosts"`
	Tree  Node     `json:"tree"`
}

type Node struct {
	Name     string `json:"name"`
	Children []Node `json:"children,omitempty"`
}

// HostConfig stores all of the relevant information of the configuration file.
type HostConfig struct {
	SNodes []*SigningNode       // an array of signing nodes
	Hosts  map[string]*HostNode // maps hostname to host
	Dir    *directory           // the directory mapping hostnames to goPeers
	Root   *HostNode            // the host root of the tree
}

// NewHostConfig creates a new host configuration that can be populated with
// hosts.
func NewHostConfig() *HostConfig {
	return &HostConfig{SNodes: make([]*SigningNode, 0), Hosts: make(map[string]*HostNode), Dir: newDirectory(), Root: nil}
}

// ConstructTree does a depth-first construction of the tree specified in the
// config file. ConstructTree must be call AFTER populating the HostConfig with
// ALL the possible hosts.
func ConstructTree(n Node, hc *HostConfig, parent *HostNode) error {
	// get the HostNode associated with n
	h, ok := hc.Hosts[n.Name]
	if !ok {
		fmt.Println("unknown host in tree:", n.Name)
		return errors.New("unknown host in tree")
	}
	// if the parent of this call is nil then this must be the root node
	if parent == nil {
		hc.Root = h
	} else {
		// connect this node to its parent first
		gc, _ := NewGoConn(hc.Dir, h.name, parent.name)
		h.AddParent(gc)
	}
	for _, c := range n.Children {
		// connect this node to its children
		gc, _ := NewGoConn(hc.Dir, h.name, c.Name)
		h.AddChildren(gc)
		if err := ConstructTree(c, hc, h); err != nil {
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
	var cf ConfigFile
	err = json.Unmarshal(file, &cf)
	if err != nil {
		return hc, err
	}
	// read the hosts lists
	for _, h := range cf.Hosts {
		// add to the hosts list if we havent added it before
		if _, ok := hc.Hosts[h]; !ok {
			hc.Hosts[h] = NewHostNode(h)
		}
	}
	err = ConstructTree(cf.Tree, hc, nil)
	if err != nil {
		return hc, err
	}
	suite := openssl.NewAES128SHA256P256()
	rand := abstract.HashStream(suite, []byte("example"), nil)
	for _, h := range hc.Hosts {
		hc.SNodes = append(hc.SNodes, NewSigningNode(h, suite, rand))
	}
	for _, sn := range hc.SNodes {
		sn.Listen()
	}
	var X_hat abstract.Point = hc.SNodes[1].pubKey
	for i := 2; i < len(hc.SNodes); i++ {
		X_hat.Add(X_hat, hc.SNodes[i].pubKey)
	}
	hc.SNodes[0].X_hat = X_hat
	return hc, err
}
