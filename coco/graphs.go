package coco

import (
	"bufio"
	"container/list"
	"crypto/cipher"
	"errors"
	"fmt"
	"os"

	"github.com/dedis/crypto/abstract"
)

// var testSuite = openssl.NewAES128SHA256P256()
// var testRand = random.Stream

// dijkstra is actually implemented as BFS right now because it is equivalent
// when edge weights are all 1.
func dijkstra(m map[string]*SigningNode, root *SigningNode) {
	l := list.New()
	visited := make(map[string]bool)
	l.PushFront(root)
	visited[root.Name()] = true
	for e := l.Front(); e != nil; e = l.Front() {
		l.Remove(e)
		sn := e.Value.(*SigningNode)
		// make all unvisited peers children
		// and mark them as visited
		for name, conn := range sn.Peers() {
			// visited means it is already on the tree.
			if visited[name] {
				continue
			}
			visited[name] = true
			// add the associated peer/connection as a child
			sn.AddChildren(conn.Name())
			cn, ok := m[name]
			if !ok {
				panic("error getting connection from map")
			}
			peers := cn.Peers()
			pconn, ok := peers[sn.Name()]
			if !ok {
				panic("parent connection doesn't exist: not bi-directional")
			}
			cn.AddParent(pconn.Name())
			l.PushFront(cn)
		}
	}
}

func loadHost(hostname string, m map[string]*SigningNode, testSuite abstract.Suite, testRand cipher.Stream, hc *HostConfig) *SigningNode {
	if h, ok := m[hostname]; ok {
		return h
	}
	host := NewHostNode(hostname, newDirectory())
	h := NewSigningNode(host, testSuite, testRand)
	hc.Hosts[hostname] = h
	m[hostname] = h
	return h
}

// loadGraph reads in an edge list data file of the form.
// from1 to1
// from1 to2
// from2 to2
// ...
func loadGraph(name string, testSuite abstract.Suite, testRand cipher.Stream) (*HostConfig, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	s := bufio.NewScanner(f)
	// generate the list of hosts
	hosts := make(map[string]*SigningNode)
	hc := NewHostConfig()
	var root *SigningNode
	for s.Scan() {
		var host1, host2 string
		n, err := fmt.Sscan(s.Text(), &host1, &host2)
		if err != nil {
			return nil, err
		}
		if n != 2 {
			return nil, errors.New("improperly formatted file")
		}
		h1 := loadHost(host1, hosts, testSuite, testRand, hc)
		h2 := loadHost(host2, hosts, testSuite, testRand, hc)
		h1.addPeer(h2.Name(), h2.pubKey)
		h2.addPeer(h1.Name(), h1.pubKey)
		if root == nil {
			root = h1
		}
		hc.SNodes = append(hc.SNodes, h1, h2)
	}
	dijkstra(hosts, root)
	for _, sn := range hc.SNodes {
		sn.Listen()
	}
	jhc, err := LoadJSON([]byte(hc.String()))
	return jhc, err
}
