package tree

import (
	"container/heap"
)

type intElt struct {
	pri int
	obj interface{}
}

// Internal Heap implementation struct
type intHeap struct {
	elts []intElt
}

func (h *intHeap) Len() int {
	return len(h.elts)
}

func (h *intHeap) Less(i,j int) bool {
	return h.elts[i].pri < h.elts[j].pri
}

func (h *intHeap) Swap(i,j int) {
	h.elts[i],h.elts[j] = h.elts[j],h.elts[i]
}

func (h *intHeap) Push(x interface{}) {
	h.elts = append(h.elts, x.(intElt))
}

func (h *intHeap) Pop() interface{} {
	last := len(h.elts)-1
	elt := h.elts[last]
	h.elts = h.elts[:last]
	return elt
}

// Integer-indexed priority queues.
// Probably horribly unoptimized way to implement an int-priority queue;
// we can consider improving if it ever becomes performance-critical.
type IntQ struct {
	heap intHeap
}

func (q *IntQ) Len() int {
	return q.heap.Len()
}

func (q *IntQ) Push(pri int, obj interface{}) {
	heap.Push(&q.heap, intElt{pri,obj})
}

func (q *IntQ) Pop() (int,interface{}) {
	elt := heap.Pop(&q.heap).(intElt)
	return elt.pri,elt.obj
}

