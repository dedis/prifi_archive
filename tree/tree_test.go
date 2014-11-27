package tree

import (
	"os"
	"fmt"
	"bufio"
	"testing"
	"math"
	"math/rand"
	"github.com/dedis/crypto/random"
	"github.com/dedis/crypto/nist"
)

var testSuite = nist.NewAES128SHA256P256()
var testRand = random.Stream

/*
func build(suite abstract.Suite, rand cipher.Stream, 
		parent *node, depth, arity int) {
	
	for i := 0; i < arity; i++ {
		n := newNode(suite, rand, parent.pub)
		parent.addChild(n.pub)

		if depth > 0 {
			build(suite, rand, n, depth-1, arity)
		}
	}
}
*/

func testLevels() (int,int) {
	n := 1000
	//l := suite.HashLen()
	//ids := make([]float64, n)
	var c1,c2 int
	b := float64(1.01)
	max := float64(0.0)
	maxlev := 0
	for i := 0; i < n; i++ {
		f := rand.Float64()
		if f > max {
			c1++
			max = f
		}

		lev := 0
		for {
			if f < 0 || f > 1 {
				panic("XXX")
			}
			f := rand.Float64() * b
			if f >= 1.0 {
				break
			}
			lev++
		}

		if lev >= maxlev {
			c2++
		}
		if lev > maxlev {
			maxlev = lev
		}
	}
	println("expected",math.Log(float64(n)),"c1",c1,"c2",c2)
	return c1,c2
}

func loadHost(hostname string, m *map[string]*host) *host {
	if h := (*m)[hostname]; h != nil {
		return h
	}
	h := newHost(testSuite,testRand,hostname)
	(*m)[hostname] = h
	return h
}

// Form a shortest-path spanning tree over all hosts from the given root.
func dijkstra(hosts map[string]*host, root *host) {

	rootid := string(root.id)
	q := IntQ{}
	idmap := make(map[string]*host)

	// Prepare treeNodes on all hosts participating in this tree
	for _,host := range(hosts) {
		idmap[string(host.id)] = host

		tn := &treeNode{}
		host.trees[rootid] = tn

		tn.dist = math.MaxInt32
		if host == root {
			tn.dist = 0
			tn.path = []HashId{root.id}
		}
		q.Push(tn.dist, host)
	}

	//println("qlen",q.Len(),"hosts",len(hosts))

	for q.Len() > 0 {
		_,obj := q.Pop()
		host := obj.(*host)
		tn := host.trees[rootid]
		//println("dist",pri,"host",host.name,"qlen",q.Len())
		if len(tn.path) != tn.dist+1 {
			panic("dijkstra oops!")
		}

		for peerid,_ := range(host.peers) {
			peer := idmap[peerid]
			if peer == nil {
				panic("peer oops")
			}
			//println(" peer",peer.name)
			ptn := peer.trees[rootid]
			dist := tn.dist+1
			if dist >= ptn.dist {
				continue	// no better, so do nothing
			}

			// Form the new, shorter path to this peer
			ptn.dist = dist
			ptn.path = make([]HashId, dist+1)
			copy(ptn.path, tn.path)
			ptn.path[dist] = HashId(peerid)

			q.Push(ptn.dist, peer)
			//println("  dist",dist,"qlen",q.Len())
		}
	}
}

func loadGraph(name string) {
	f,e := os.Open(name)
	if e != nil {
		panic(e.Error())
	}

	s := bufio.NewScanner(f)
	hosts := make(map[string]*host)
	var root *host
	for s.Scan() {
		var host1,host2 string
		n,e := fmt.Sscan(s.Text(), &host1, &host2)
		if n != 2 {
			panic(e.Error())
		}
		h1 := loadHost(host1,&hosts)
		h2 := loadHost(host2,&hosts)
		h1.addPeer(h2.pub, h2.id)
		h2.addPeer(h1.pub, h1.id)
		if root == nil {
			root = h1
		}
	}

	dijkstra(hosts, root)
}

func TestTree(t *testing.T) {

	// Create a tree
/*
	arity := 3
	depth := 3
	root := newNode(suite, rand, nil)
	build(suite, rand, root, depth, arity)
*/

/*
	niter := 1000
	var sum1,sum2 int
	for i := 0; i < niter; i++ {
		c1,c2 := testLevels()
		sum1 += c1
		sum2 += c2
	}
	println("avg",float64(sum1)/float64(niter),float64(sum2)/float64(niter))
*/

	loadGraph("data/wax.dat")
}

