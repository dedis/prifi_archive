package coco

import (
	"bytes"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"

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
	SNodes []*SigningNode          // an array of signing nodes
	Hosts  map[string]*SigningNode // maps hostname to host
	Dir    *directory              // the directory mapping hostnames to goPeers
}

func (hc *HostConfig) Verify() error {
	root := hc.SNodes[0]
	traverseTree(root, hc, publicKeyCheck)
	fmt.Println("tree verified")
	return nil
}

func publicKeyCheck(n *SigningNode, hc *HostConfig) error {
	x_hat := n.pubKey
	for cn := range n.Children() {
		c := hc.Hosts[cn]
		x_hat.Add(x_hat, c.X_hat)
	}
	if x_hat != n.X_hat {
		return errors.New("parent X_hat != Sum(child.X_hat)+pubKey")
	}
	return nil
}

func traverseTree(p *SigningNode, hc *HostConfig, f func(*SigningNode, *HostConfig) error) error {
	if err := f(p, hc); err != nil {
		return err
	}
	for cn := range p.Children() {
		c := hc.Hosts[cn]
		err := traverseTree(c, hc, f)
		if err != nil {
			return err
		}
	}
	return nil
}

func (hc *HostConfig) String() string {
	b := bytes.NewBuffer([]byte{})
	b.WriteString("{\"hosts\": [")
	for i, sn := range hc.SNodes {
		if i != 0 {
			b.WriteString(", ")
		}
		b.WriteString("\"" + sn.Name() + "\"")
	}
	b.WriteString("],")
	b.WriteString("\"tree\": ")
	root := hc.SNodes[0]
	writeHC(b, hc, root)
	b.WriteString("}\n")
	bformatted := bytes.NewBuffer([]byte{})
	err := json.Indent(bformatted, b.Bytes(), "", "\t")
	if err != nil {
		fmt.Println(string(b.Bytes()))
		fmt.Println("ERROR: ", err)
	}
	return string(bformatted.Bytes())
}

func writeHC(b *bytes.Buffer, hc *HostConfig, p *SigningNode) {
	fmt.Fprint(b, "{\"name\":", "\""+p.Name()+"\"", ",")
	fmt.Fprint(b, "\"children\":[")
	i := 0
	for n := range p.Children() {
		if i != 0 {
			b.WriteString(", ")
		}
		c := hc.Hosts[n]
		writeHC(b, hc, c)
		i++
	}
	fmt.Fprint(b, "]")
	fmt.Fprint(b, "}")
}

// NewHostConfig creates a new host configuration that can be populated with
// hosts.
func NewHostConfig() *HostConfig {
	return &HostConfig{SNodes: make([]*SigningNode, 0), Hosts: make(map[string]*SigningNode), Dir: newDirectory()}
}

// ConstructTree does a depth-first construction of the tree specified in the
// config file. ConstructTree must be call AFTER populating the HostConfig with
// ALL the possible hosts.
func ConstructTree(n Node, hc *HostConfig, parent *HostNode, suite abstract.Suite, rand cipher.Stream, hosts map[string]*HostNode) (*SigningNode, error) {
	// get the HostNode associated with n
	h, ok := hosts[n.Name]
	if !ok {
		fmt.Println("unknown host in tree:", n.Name)
		return nil, errors.New("unknown host in tree")
	}
	hc.SNodes = append(hc.SNodes, NewSigningNode(h, suite, rand))
	sn := hc.SNodes[len(hc.SNodes)-1]
	hc.Hosts[n.Name] = sn
	// if the parent of this call is nil then this must be the root node
	if parent != nil {
		// connect this node to its parent first
		gc, _ := NewGoConn(hc.Dir, h.name, parent.name)
		h.AddParent(gc)
	}
	sn.X_hat = sn.pubKey
	for _, c := range n.Children {
		// connect this node to its children
		gc, _ := NewGoConn(hc.Dir, h.name, c.Name)
		h.AddChildren(gc)
		csn, err := ConstructTree(c, hc, h, suite, rand, hosts)
		if err != nil {
			return nil, err
		}
		sn.X_hat.Add(sn.X_hat, csn.X_hat)
	}
	return sn, nil
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
	hosts := make(map[string]*HostNode)
	// read the hosts lists
	for _, h := range cf.Hosts {
		// add to the hosts list if we havent added it before
		if _, ok := hc.Hosts[h]; !ok {
			hosts[h] = NewHostNode(h)
		}
	}
	suite := openssl.NewAES128SHA256P256()
	rand := suite.Cipher([]byte("example"))
	rn, err := ConstructTree(cf.Tree, hc, nil, suite, rand, hosts)
	if err != nil {
		return hc, err
	}
	if rn != hc.SNodes[0] {
		log.Fatal("root node is not the zeroth")
	}
	if err := hc.Verify(); err != nil {
		log.Fatal(err)
	}
	for _, sn := range hc.SNodes {
		sn.Listen()
	}
	return hc, err
}
