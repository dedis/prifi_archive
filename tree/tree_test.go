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
		if root == nil {
			root = h1
		}
		h2 := loadHost(host2,&hosts)
		h1.addPeer(h2.pub, h2.id)
		h2.addPeer(h1.pub, h1.id)
	}
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

