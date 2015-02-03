package oldconfig

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
	"strings"
	"time"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/nist"
	"github.com/dedis/prifi/coco/coconet"
	"github.com/dedis/prifi/coco/sign"
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
	Tree  *Node    `json:"tree"`
}

// why can't I just deal with nist.Point
type JSONPoint json.RawMessage

type Node struct {
	Name     string  `json:"name"`
	PriKey   string  `json:"prikey,omitempty"`
	PubKey   string  `json:"pubkey,omitempty"`
	Children []*Node `json:"children,omitempty"`
}

// HostConfig stores all of the relevant information of the configuration file.
type HostConfig struct {
	SNodes []*sign.SigningNode          // an array of signing nodes
	Hosts  map[string]*sign.SigningNode // maps hostname to host
	Dir    *coconet.GoDirectory         // the directory mapping hostnames to goPeers
}

func (hc *HostConfig) Verify() error {
	root := hc.SNodes[0]
	traverseTree(root, hc, publicKeyCheck)
	fmt.Println("tree verified")
	return nil
}

func publicKeyCheck(n *sign.SigningNode, hc *HostConfig) error {
	x_hat := n.PubKey
	for _, cn := range n.Children() {
		c := hc.Hosts[cn.Name()]
		x_hat.Add(x_hat, c.X_hat)
	}
	/*if x_hat != n.X_hat {
		return errors.New("parent X_hat != Sum(child.X_hat)+PubKey")
	}*/
	return nil
}

func traverseTree(p *sign.SigningNode,
	hc *HostConfig,
	f func(*sign.SigningNode, *HostConfig) error) error {
	if err := f(p, hc); err != nil {
		return err
	}
	for _, cn := range p.Children() {
		c := hc.Hosts[cn.Name()]
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
	if len(hc.SNodes) != 0 {
		root := hc.SNodes[0]
		writeHC(b, hc, root)
	} else {
		b.WriteString("{}")
	}
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

func writeHC(b *bytes.Buffer, hc *HostConfig, p *sign.SigningNode) error {
	// Node{name, pubkey, x_hat, children}
	if p == nil {
		return errors.New("node does not exist")
	}
	fmt.Fprint(b, "{\"name\":", "\""+p.Name()+"\",")
	fmt.Fprint(b, "\"prikey\":", "\""+string(hex.EncodeToString(p.PrivKey.Encode()))+"\",")
	fmt.Fprint(b, "\"pubkey\":", "\""+string(hex.EncodeToString(p.PubKey.Encode()))+"\",")

	// recursively format children
	fmt.Fprint(b, "\"children\":[")
	i := 0
	for _, n := range p.Children() {
		if i != 0 {
			b.WriteString(", ")
		}
		c := hc.Hosts[n.Name()]
		err := writeHC(b, hc, c)
		if err != nil {
			b.WriteString("\"" + n.Name() + "\"")
		}
		i++
	}
	fmt.Fprint(b, "]}")
	return nil
}

// NewHostConfig creates a new host configuration that can be populated with
// hosts.
func NewHostConfig() *HostConfig {
	return &HostConfig{SNodes: make([]*sign.SigningNode, 0), Hosts: make(map[string]*sign.SigningNode), Dir: coconet.NewGoDirectory()}
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
	n *Node,
	hc *HostConfig,
	parent string,
	suite abstract.Suite,
	rand cipher.Stream,
	hosts map[string]coconet.Host,
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

	var prikey abstract.Secret
	var pubkey abstract.Point
	var sn *sign.SigningNode

	// if the JSON holds the fields field is set load from there
	if len(n.PubKey) != 0 {
		// log.Println("decoding point")
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
		// log.Println("decoding point")
		encoded, err = hex.DecodeString(string(n.PriKey))
		if err != nil {
			log.Print("failed to decode hex from encoded")
			return nil, err
		}
		prikey = suite.Secret()
		err = prikey.Decode(encoded)
		if err != nil {
			log.Print("failed to decode point from hex")
			return nil, err
		}
	}
	if generate {
		if prikey != nil {
			// if we have been given a private key load that
			hc.SNodes = append(hc.SNodes, sign.NewKeyedSigningNode(h, suite, prikey))
		} else {
			// otherwise generate a random new one
			hc.SNodes = append(hc.SNodes, sign.NewSigningNode(h, suite, rand))
		}
		sn = hc.SNodes[len(hc.SNodes)-1]
		hc.Hosts[name] = sn
		if prikey == nil {
			prikey = sn.PrivKey
			pubkey = sn.PubKey
		}
		// log.Println("pubkey:", sn.PubKey)
		// log.Println("given: ", pubkey)
	}
	// if the parent of this call is empty then this must be the root node
	if parent != "" && generate {
		h.AddParent(parent)
	}
	// log.Println("name: ", n.Name)
	// log.Println("prikey: ", prikey)
	// log.Println("pubkey: ", pubkey)
	x_hat := suite.Point().Null()
	x_hat.Add(x_hat, pubkey)
	// log.Println("x_hat: ", x_hat)
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
		// log.Print("ConstructTree:", h, suite, rand, hosts, nameToAddr, opts)
		cpubkey, err := ConstructTree(c, hc, name, suite, rand, hosts, nameToAddr, opts)
		if err != nil {
			return nil, err
		}

		// if generating all csn will be availible
		// log.Print("adding from child: ", x_hat, cpubkey)
		x_hat.Add(x_hat, cpubkey)
	}
	if generate {
		sn.X_hat = x_hat
	}
	// log.Println("name: ", n.Name)
	// log.Println("final x_hat: ", x_hat)
	// log.Println("final pubkey: ", pubkey)
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
	Port      string   // if specified rewrites all ports to be this
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

	dir := coconet.NewGoDirectory()
	hosts := make(map[string]coconet.Host)
	nameToAddr := make(map[string]string)

	if connT == GoC {
		for _, h := range cf.Hosts {
			if _, ok := hc.Hosts[h]; !ok {
				nameToAddr[h] = h
				// it doesn't make sense to only make 1 go host
				hosts[h] = coconet.NewGoHost(h, dir)
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

		for i, h := range cf.Hosts {

			addr := h
			if opts.GenHosts {
				p := strconv.Itoa(startConfigPort)
				addr = localAddr + ":" + p
				//log.Println("created new host address: ", addr)
				startConfigPort++
			} else if opts.Port != "" {
				log.Println("attempting to rewrite port: ", opts.Port)
				// if the port has been specified change the port
				hostport := strings.Split(addr, ":")
				log.Println(hostport)
				if len(hostport) == 2 {
					addr = hostport[0] + ":" + opts.Port
				}
				log.Println(addr)
			} else if len(opts.Hostnames) != 0 {
				addr = opts.Hostnames[i]
			}

			nameToAddr[h] = addr
			// add to the hosts list if we havent added it before
			if _, ok := hc.Hosts[addr]; !ok {
				// only create the tcp hosts requested
				if opts.Host == "" || opts.Host == addr {
					hosts[addr] = coconet.NewTCPHost(addr)
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
	hostnames := make(map[string]*sign.SigningNode)
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
		go func(sn *sign.SigningNode) {
			// start listening for messages from within the tree
			sn.Host.Listen()
		}(sn)
	}

	for _, sn := range hostnames {
		var err error
		// exponential backoff for attempting to connect to parent
		startTime := time.Duration(200)
		maxTime := time.Duration(2000)
		for i := 0; i < 20; i++ {
			// log.Println("attempting to connect to parent")
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
		// log.Println("Succssfully connected to parent")
		if err != nil {
			return errors.New("failed to connect")
		}
	}

	// need to make sure connections are setup properly first
	// wait for a little bit for connections to establish fully
	time.Sleep(1000 * time.Millisecond)
	for _, sn := range hostnames {
		go func(sn *sign.SigningNode) {
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
