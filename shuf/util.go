package shuf

import (
	"math/rand"
)

// Generic deal function
func deal(total, size int) []int {
	result := make([]int, size)
	hash := make(map[int]*int)
	idx := 0
	for lim := total; lim > total-size; lim-- {
		i := rand.Intn(lim)
		if hash[i] != nil {
			result[idx] = *hash[i]
		} else {
			result[idx] = i
		}
		top := lim - 1
		if hash[top] != nil {
			hash[i] = hash[top]
		} else {
			hash[i] = &top
		}
		idx++
	}
	return result
}

// Create a range slice
func xrange(extent int) []int {
	result := make([]int, extent)
	for i := range result {
		result[i] = i
	}
	return result
}

// Break a slice into chunks of the given size
func chunks(in []int, size int) [][]int {
	result := make([][]int, len(in)/size)
	for c := range result {
		result[c] = make([]int, size)
		for i := 0; i < size; i++ {
			result[c][i] = in[c*size+i]
		}
	}
	return result
}
