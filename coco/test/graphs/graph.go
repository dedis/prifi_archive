package graphs

import (
	"bytes"
	"container/list"
	"fmt"
	"log"
	"strconv"
)

type Graph struct {
	Names   []string
	mem     []float64 // underlying memory for the weights matrix
	Weights [][]float64
}

func NewGraph(names []string) *Graph {
	n := len(names)
	g := &Graph{}
	g.Names = make([]string, len(names))
	copy(g.Names, names[:])
	g.mem = make([]float64, n*n)
	mem := g.mem
	g.Weights = make([][]float64, n)
	for i := range g.Weights {
		g.Weights[i], mem = mem[:n], mem[n:]
	}
	return g
}

// takes in a byte array representing an edge list and loads the graph
func (g *Graph) LoadEdgeList(edgelist []byte) {
	log.Println(g.Names)
	fields := bytes.Fields(edgelist)
	// create name map from string to index
	log.Println(g.Names)
	names := make(map[string]int)
	for i, n := range g.Names {
		names[n] = i
	}

	// read fields in groups of three: from, to, edgeweight
	for i := 0; i < len(fields)-2; i += 3 {
		from := string(fields[i])
		to := string(fields[i+1])
		weight, err := strconv.ParseFloat(string(fields[i+2]), 64)
		if err != nil {
			log.Println(err)
			continue
		}
		fi, ok := names[from]
		if !ok {
			log.Println("from not ok:", from)
			continue
		}

		ti, ok := names[to]
		if !ok {
			log.Println("to not ok:", to)
			continue
		}

		g.Weights[fi][ti] = weight
	}
}

func (g *Graph) MST() *Tree {
	// select lowest weighted root
	root := &Tree{}
	return root
}

// breadth first_ish
// pi: parent index, bf: branching factor, visited: set of visited nodes, ti: tree index, tnodes: space for tree nodes
// returns the last used index for tree nodes
func (g *Graph) constructTree(ri int, bf int, visited []bool, tnodes []Tree) {
	log.Println("constructing tree: ", ri, bf)
	log.Println(g.Names)
	root := &tnodes[ri]
	root.Name = g.Names[ri]
	log.Println(root)
	visited[ri] = true
	tni := 1
	indmap := make([]int, len(visited))
	indmap[ri] = 0

	// queue for breadth first search
	queue := list.New()

	// push the root first
	queue.PushFront(ri)

	// has to iterate through all the nodes
	for {
		e := queue.Back()
		// have processed all values
		if e == nil {
			break
		}
		queue.Remove(e)
		// parent index
		pi := e.Value.(int)
		fmt.Println("next: ", pi)
		parent := &tnodes[indmap[pi]]

		fs := sortFloats(g.Weights[pi])
		nc := bf
		fmt.Println(fs)
		// iterate through children and select the bf closest ones
		for _, ci := range fs.I {
			if nc == 0 {
				break
			}

			// if this child hasn't been visited
			// it is the closest unvisited child
			if !visited[ci] {
				fmt.Println("adding child:", ci, tni)
				queue.PushFront(ci)
				cn := &tnodes[tni]
				indmap[ci] = tni
				cn.Name = g.Names[ci]
				tni++
				parent.Children = append(parent.Children, cn)
				visited[ci] = true
				nc--
			}
		}
	}
}

// nlevels : [0:n-1]
func (g *Graph) Tree(nlevels int) *Tree {
	// find node with lowest weights outbound and inbound
	n := len(g.Weights)

	tnodes := make([]Tree, n)
	root := &tnodes[0]
	ri := g.BestConnector()
	root.Name = g.Names[ri]
	if nlevels == 0 {
		return root
	}

	// find the branching factor needed
	bf := n/nlevels + 1
	fmt.Println("Tree:", n, nlevels, bf)
	g.constructTree(ri, bf, make([]bool, n), tnodes)
	log.Println("tnodes:", tnodes)
	return root
}

// return the index of the best connector
func (g *Graph) BestConnector() int {
	n := len(g.Weights)
	dist := make([]float64, n)
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			dist[i] += g.Weights[i][j] + g.Weights[j][i]
		}
	}
	index := 0
	min := dist[0]
	for i := 1; i < n; i++ {
		if dist[i] < min {
			index = i
			min = dist[i]
		}
	}
	return index
}
