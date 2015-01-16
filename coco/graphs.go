package coco

import (
	"bufio"
	"errors"
	"fmt"
	"os"

	"github.com/dedis/crypto/openssl"
	"github.com/dedis/crypto/random"
)

var testSuite = openssl.NewAES128SHA256P256()
var testRand = random.Stream

func loadHost(hostname string, m map[string]*SigningNode) *SigningNode {
	if h := m[hostname]; h != nil {
		return h
	}
	h := NewSigningNode(NewHostNode(hostname), testSuite, testRand)
	return h
}

// loadGraph reads in an edge list data file of the form.
// from1 to1
// from1 to2
// from2 to2
// ...
func loadGraph(name string) (root *SigningNode, hosts map[string]*SigningNode, err error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, nil, err
	}
	s := bufio.NewScanner(f)
	// generate the list of hosts
	hosts = make(map[string]*SigningNode)
	for s.Scan() {
		var host1, host2 string
		n, err := fmt.Sscan(s.Text(), &host1, &host2)
		if err != nil {
			return nil, nil, err
		}
		if n != 2 {
			return nil, nil, errors.New("improperly formatted file")
		}
		h1 := loadHost(host1, hosts)
		h2 := loadHost(host2, hosts)
		//h1.AddPeer(h2.pub, h2.id)
		//h2.AddPeer(h1.pub, h1.id)
		if root == nil {
			root = h1
		}
	}
	dijkstra(hosts, root)
	return root, hosts, err
}
