package coco

import (
	"bytes"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/nist"
)

/*
Example configuration file.
file format: json

conn: indicates what protocol should be used
	by default it uses the "tcp" protocol
	"tcp": uses TcpConn for communications
	"goroutine": uses GoConn for communications

multiprocess: indicates whether each node should be run in its own process
	true: run each in its own process
	false: run each in its own goroutine
	--> create executable to run a signing node

process_hosts: indicates what hosts to run these processes on
	default: just this one
	[] // non empty list: tries ssh'ing ?
	???: how to do this best
		cross compile the SigningNode binary
		scp this to the host node (after establishing ssh key pairs)
		ssh run command

ex.json
{
	conn: "tcp"
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
	Conn  string   `json:"conn,omitempty"`
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
	Dir    *GoDirectory            // the directory mapping hostnames to goPeers
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
	/*if x_hat != n.X_hat {
		return errors.New("parent X_hat != Sum(child.X_hat)+pubKey")
	}*/
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
	return &HostConfig{SNodes: make([]*SigningNode, 0), Hosts: make(map[string]*SigningNode), Dir: NewGoDirectory()}
}

type ConnType int

const (
	GoC ConnType = iota
	TcpC
)

// ConstructTree does a depth-first construction of the tree specified in the
// config file. ConstructTree must be call AFTER populating the HostConfig with
// ALL the possible hosts.
func ConstructTree(n Node, hc *HostConfig, parent Host, suite abstract.Suite, rand cipher.Stream, hosts map[string]Host, nameToAddr map[string]string) (*SigningNode, error) {
	// get the HostNode associated with n
	name, ok := nameToAddr[n.Name]
	if !ok {
		fmt.Println("unknown name in address book:", n.Name)
		return nil, errors.New("unknown name in address book")
	}
	h, ok := hosts[name]
	if !ok {
		fmt.Println("unknown host in tree:", name)
		return nil, errors.New("unknown host in tree")
	}
	hc.SNodes = append(hc.SNodes, NewSigningNode(h, suite, rand))
	sn := hc.SNodes[len(hc.SNodes)-1]
	hc.Hosts[name] = sn
	// if the parent of this call is nil then this must be the root node
	if parent != nil {
		h.AddParent(parent.Name())
	}
	sn.X_hat = sn.pubKey
	for _, c := range n.Children {
		// connect this node to its children
		cname, ok := nameToAddr[c.Name]
		if !ok {
			fmt.Println("unknown name in address book:", n.Name)
			return nil, errors.New("unknown name in address book")
		}
		h.AddChildren(cname)
		csn, err := ConstructTree(c, hc, h, suite, rand, hosts, nameToAddr)
		if err != nil {
			return nil, err
		}
		sn.X_hat.Add(sn.X_hat, csn.X_hat)
	}
	return sn, nil
}

var ipv4Reg = regexp.MustCompile(`\d+\.\d+\.\d+\.\d+`)
var ipv4host = "NONE"

// getAddress gets the localhosts IPv4 address.
func getAddress() (string, error) {
	name, err := os.Hostname()
	if err != nil {
		log.Print("Error Resolving Hostname:", err)
		return "", err
	}
	if ipv4host == "NONE" {
		as, err := net.LookupHost(name)
		if err != nil {
			return "", err
		}
		addr := ""
		for _, a := range as {
			log.Printf("a = %+v", a)
			if ipv4Reg.MatchString(a) {
				log.Print("matches")
				addr = a
			}
		}
		if addr == "" {
			err = errors.New("No IPv4 Address for Hostname")
		}
		return addr, err
	}
	return ipv4host, nil
}

var startConfigPort = 8089

// TODO: if in tcp mode associate each hostname in the file with a different
// port. Get the remote address of this computer to combine with those for the
// complete hostnames to be used by the hosts.
func LoadJSON(file []byte, opts ...string) (*HostConfig, error) {
	hc := NewHostConfig()
	var cf ConfigFile
	err := json.Unmarshal(file, &cf)
	if err != nil {
		return hc, err
	}
	connT := GoC
	if cf.Conn == "tcp" {
		connT = TcpC
	}
	for _, o := range opts {
		if o == "tcp" {
			connT = TcpC
		}
	}
	dir := NewGoDirectory()
	hosts := make(map[string]Host)
	nameToAddr := make(map[string]string)
	// read the hosts lists
	if connT == GoC {
		for _, h := range cf.Hosts {
			if _, ok := hc.Hosts[h]; !ok {
				nameToAddr[h] = h
				hosts[h] = NewGoHost(h, dir)
			}
		}
	} else {
		localAddr, err := getAddress()
		if err != nil {
			return nil, err
		}
		//log.Println("Found localhost address:", localAddr)

		for _, h := range cf.Hosts {
			p := strconv.Itoa(startConfigPort)
			addr := localAddr + ":" + p
			//log.Println("created new host address: ", addr)
			nameToAddr[h] = addr
			// add to the hosts list if we havent added it before
			if _, ok := hc.Hosts[addr]; !ok {
				hosts[addr] = NewGoHost(addr, dir)
				hosts[addr] = NewTCPHost(addr)
			}
			startConfigPort++
		}
	}
	suite := nist.NewAES128SHA256P256()
	rand := suite.Cipher([]byte("example"))
	rn, err := ConstructTree(cf.Tree, hc, nil, suite, rand, hosts, nameToAddr)
	if err != nil {
		return hc, err
	}
	if rn != hc.SNodes[0] {
		log.Fatal("root node is not the zeroth")
	}
	/*if err := hc.Verify(); err != nil {
		log.Fatal(err)
	}*/
	for _, sn := range hc.SNodes {
		go func(sn *SigningNode) {
			// start listening for messages from within the tree
			sn.Host.Listen()
		}(sn)
	}
	for _, sn := range hc.SNodes {
		var err error
		for i := 0; i < 10; i++ {
			err = sn.Connect()
			if err == nil {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
		if err != nil {
			log.Fatal("failed to connect: ", err)
		}
	}
	// need to make sure connections are setup properly first
	// wait for a little bit for connections to establish fully
	if connT == TcpC {
		time.Sleep(200 * time.Millisecond)
	}
	for _, sn := range hc.SNodes {
		go func(sn *SigningNode) {
			// start listening for messages from within the tree
			sn.Listen()
		}(sn)
	}
	return hc, err
}

// LoadConfig loads a configuration file in the format specified above. It
// populates a HostConfig with HostNode Hosts and goPeer Peers.
func LoadConfig(fname string, opts ...string) (*HostConfig, error) {
	file, err := ioutil.ReadFile(fname)
	if err != nil {
		return nil, err
	}
	return LoadJSON(file, opts...)

}
