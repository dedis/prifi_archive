package coco

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
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
	"goroutine": uses GoConn for communications [default]

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

// why can't I just deal with nist.Point
type JSONPoint json.RawMessage

type Node struct {
	Name     string `json:"name"`
	PriKey   string `json:"prikey,omitempty"`
	PubKey   string `json:"pubkey,omitempty"`
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

func traverseTree(p *SigningNode,
	hc *HostConfig,
	f func(*SigningNode, *HostConfig) error) error {
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

	// write the hosts
	b.WriteString("{\"hosts\": [")
	for i, sn := range hc.SNodes {
		if i != 0 {
			b.WriteString(", ")
		}
		b.WriteString("\"" + sn.Name() + "\"")
	}
	b.WriteString("],")

	// write the tree structure
	b.WriteString("\"tree\": ")
	root := hc.SNodes[0]
	writeHC(b, hc, root)
	b.WriteString("}\n")

	// format the resulting JSON for readability
	bformatted := bytes.NewBuffer([]byte{})
	err := json.Indent(bformatted, b.Bytes(), "", "\t")
	if err != nil {
		fmt.Println(string(b.Bytes()))
		fmt.Println("ERROR: ", err)
	}

	return string(bformatted.Bytes())
}

func writeHC(b *bytes.Buffer, hc *HostConfig, p *SigningNode) {
	// Node{name, pubkey, x_hat, children}
	fmt.Fprint(b, "{\"name\":", "\""+p.Name()+"\",")
	fmt.Fprint(b, "\"pubkey\":", "\""+string(hex.EncodeToString(p.pubKey.Encode()))+"\",")
	fmt.Fprint(b, "\"prikey\":", "\""+string(hex.EncodeToString(p.privKey.Encode()))+"\",")

	// recursively format children
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
	fmt.Fprint(b, "]}")
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
func ConstructTree(
	n Node,
	hc *HostConfig,
	parent string,
	suite abstract.Suite,
	rand cipher.Stream,
	hosts map[string]Host,
	nameToAddr map[string]string,
	opts ConfigOptions) (abstract.Point, error) {
	// passes up its X_hat, and/or an error

	// get the name associated with this address
	name, ok := nameToAddr[n.Name]
	if !ok {
		fmt.Println("unknown name in address book:", n.Name)
		return nil, errors.New("unknown name in address book")
	}

	// generate indicates whether we should generate the signing
	// node for this hostname
	generate := opts.Host == "" || opts.Host == name

	// check to make sure the this hostname is in the tree
	// it can be backed by a nil pointer
	h, ok := hosts[name]
	if !ok {
		fmt.Println("unknown host in tree:", name)
		return nil, errors.New("unknown host in tree")
	}

	// pull out the public key from the json
	// initialize x_hat to be that public key
	var prikey abstract.Point
	var pubkey abstract.Point
	var x_hat abstract.Point
	if len(n.PubKey) != 0 {
		log.Println("decoding point")
		encoded, err := hex.DecodeString(string(n.PubKey))
		if err != nil {
			log.Print("failed to decode hex from encoded")
			return nil, err
		}
		pubkey = suite.Point()
		err = pubkey.Decode(encoded)
		if err != nil {
			log.Print("failed to decode point from hex")
			return nil, err
		}
		log.Println("decoding point")
		encoded, err = hex.DecodeString(string(n.PriKey))
		if err != nil {
			log.Print("failed to decode hex from encoded")
			return nil, err
		}
		prikey = suite.Point()
		err = prikey.Decode(encoded)
		if err != nil {
			log.Print("failed to decode point from hex")
			return nil, err
		}
		if generate {
			sn.privKey = prikey
			sn.pubKey = pubkey
			sn.X_hat = pubkey
		}
	}

	// only generate the signing node is specified
	var sn *SigningNode
	if generate {
		hc.SNodes = append(hc.SNodes, NewKeyedSigningNode(h, suite, prikey))
		sn = hc.SNodes[len(hc.SNodes)-1]
		hc.Hosts[name] = sn
	}

	// if the parent of this call is empty then this must be the root node
	if parent != "" && generate {
		h.AddParent(parent)
	}

	// pull out the public key from the json
	// initialize x_hat to be that public key
	var prikey abstract.Point
	var pubkey abstract.Point
	var x_hat abstract.Point
	if len(n.PubKey) != 0 {
		log.Println("decoding point")
		encoded, err := hex.DecodeString(string(n.PubKey))
		if err != nil {
			log.Print("failed to decode hex from encoded")
			return nil, err
		}
		pubkey = suite.Point()
		err = pubkey.Decode(encoded)
		if err != nil {
			log.Print("failed to decode point from hex")
			return nil, err
		}
		log.Println("decoding point")
		encoded, err = hex.DecodeString(string(n.PriKey))
		if err != nil {
			log.Print("failed to decode hex from encoded")
			return nil, err
		}
		prikey = suite.Point()
		err = prikey.Decode(encoded)
		if err != nil {
			log.Print("failed to decode point from hex")
			return nil, err
		}
		if generate {
			sn.privKey = prikey
			sn.pubKey = pubkey
			sn.X_hat = pubkey
		}
	} else {

		pubkey = suite.Point()
	}
	x_hat = pubkey

	for _, c := range n.Children {
		// connect this node to its children
		cname, ok := nameToAddr[c.Name]
		if !ok {
			fmt.Println("unknown name in address book:", n.Name)
			return nil, errors.New("unknown name in address book")
		}

		if generate {
			h.AddChildren(cname)
		}

		// recursively construct the children
		cpubkey, err := ConstructTree(c, hc, h.Name(), suite, rand, hosts, nameToAddr, opts)
		if err != nil {
			return nil, err
		}

		// if generating all csn will be availible
		log.Print("adding from child: ", x_hat, cpubkey)
		x_hat.Add(x_hat, cpubkey)
		if generate && opts.Host == "" {
			sn.X_hat.Add(sn.X_hat, cpubkey)
		}
	}
	return x_hat, nil
}

var ipv4Reg = regexp.MustCompile(`\d+\.\d+\.\d+\.\d+`)
var ipv4host = "NONE"

// getAddress gets the localhosts IPv4 address.
func GetAddress() (string, error) {
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

type ConfigOptions struct {
	ConnType  string   // "go", tcp"
	Hostnames []string // if not nil replace hostnames with these
	GenHosts  bool     // if true generate random hostnames (all tcp)
	Host      string   // hostname to load into memory: "" for all
}

// TODO: if in tcp mode associate each hostname in the file with a different
// port. Get the remote address of this computer to combine with those for the
// complete hostnames to be used by the hosts.
func LoadJSON(file []byte, optsSlice ...ConfigOptions) (*HostConfig, error) {
	opts := ConfigOptions{}
	if len(optsSlice) > 0 {
		opts = optsSlice[0]
	}

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

	// options override file
	if opts.ConnType == "tcp" {
		connT = TcpC
	}

	dir := NewGoDirectory()
	hosts := make(map[string]Host)
	nameToAddr := make(map[string]string)

	if connT == GoC {
		for _, h := range cf.Hosts {
			if _, ok := hc.Hosts[h]; !ok {
				nameToAddr[h] = h
				// it doesn't make sense to only make 1 go host
				hosts[h] = NewGoHost(h, dir)
			}
		}

	} else if connT == TcpC {
		localAddr := ""

		if opts.GenHosts {
			localAddr, err = GetAddress()
			if err != nil {
				return nil, err
			}
		}

		for _, h := range cf.Hosts {

			addr := h
			if opts.GenHosts {
				p := strconv.Itoa(startConfigPort)
				addr = localAddr + ":" + p
				//log.Println("created new host address: ", addr)
				startConfigPort++
			}

			nameToAddr[h] = addr
			// add to the hosts list if we havent added it before
			if _, ok := hc.Hosts[addr]; !ok {
				// only create the tcp hosts requested
				if opts.Host == "" || opts.Host == addr {
					hosts[addr] = NewTCPHost(addr)
				} else {
					hosts[addr] = nil // it is there but not backed
				}
			}
		}
	}
	suite := nist.NewAES128SHA256P256()
	rand := suite.Cipher([]byte("example"))
	_, err = ConstructTree(cf.Tree, hc, "", suite, rand, hosts, nameToAddr, opts)
	return hc, err
}

// run the given hostnames
func (hc *HostConfig) Run(hostnameSlice ...string) error {
	hostnames := make(map[string]*SigningNode)
	if hostnameSlice == nil {
		hostnames = hc.Hosts
	} else {

		for _, h := range hostnameSlice {
			sn, ok := hc.Hosts[h]
			if !ok {
				return errors.New("hostname given not in config file:" + h)
			}
			hostnames[h] = sn
		}
	}
	for _, sn := range hostnames {
		go func(sn *SigningNode) {
			// start listening for messages from within the tree
			sn.Host.Listen()
		}(sn)
	}

	for _, sn := range hostnames {
		var err error
		// exponential backoff for attempting to connect to parent
		startTime := time.Duration(200)
		maxTime := time.Duration(60000)
		for i := 0; i < 100; i++ {
			log.Println("attempting to connect to parent")
			err = sn.Connect()
			if err == nil {
				break
			}

			time.Sleep(startTime * time.Millisecond)
			startTime *= 2
			if startTime > maxTime {
				startTime = maxTime
			}
		}
		if err != nil {
			return errors.New("failed to connect")
		}
	}

	// need to make sure connections are setup properly first
	// wait for a little bit for connections to establish fully
	time.Sleep(1000 * time.Millisecond)
	for _, sn := range hostnames {
		go func(sn *SigningNode) {
			// start listening for messages from within the tree
			sn.Listen()
		}(sn)
	}
	return nil
}

// LoadConfig loads a configuration file in the format specified above. It
// populates a HostConfig with HostNode Hosts and goPeer Peers.
func LoadConfig(fname string, opts ...ConfigOptions) (*HostConfig, error) {
	file, err := ioutil.ReadFile(fname)
	if err != nil {
		return nil, err
	}
	return LoadJSON(file, opts...)
}
