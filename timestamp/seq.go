package time

import (
	"encoding/binary"
	"errors"
	"io"
)

const (
	MaxSeqLen = binary.MaxVarintLen64
)

var overflow = errors.New("sequence number overflows a 64-bit integer")

// putSeq encodes a 64-bit sequence number into buf,
// compressed based on sequence number ref,
// and returns the number of bytes written.
func putSeq(buf []byte, x, ref uint64) int {
	i := 0
	for x^ref >= 0x80 {
		buf[i] = byte(x) | 0x80
		x >>= 7
		ref >>= 7
		i++
	}
	buf[i] = byte(x) & 0x7f
	return i + 1
}

// getSeq decodes a sequence number from buf based on sequence number ref,
// and returns that value and the number of bytes read (> 0).
// If an error occurred, the value is 0 and the number of bytes n
// is <= 0 meaning:
//
//	n == 0: buf too small
//	n  < 0: value larger than 64 bits (overflow)
//              and -n is the number of bytes read
//
func getSeq(buf []byte, ref uint64) (uint64, int) {
	x := ref
	var s uint
	for i, b := range buf {
		x &^= 0x7f << s // clear out the next 7 bits
		if b < 0x80 {
			if i > 9 || i == 9 && b > 1 {
				return 0, -(i + 1) // overflow
			}
			return x | uint64(b)<<s, i + 1
		}
		x |= uint64(b&0x7f) << s
		s += 7
	}
	return 0, 0
}

// readSeq reads an encoded sequence number from r based on ref,
// and returns it as a uint64.
func readSeq(r io.ByteReader, ref uint64) (uint64, error) {
	x := ref
	var s uint
	for i := 0; ; i++ {
		b, err := r.ReadByte()
		if err != nil {
			return x, err
		}
		x &^= 0x7f << s // clear out the next 7 bits
		if b < 0x80 {
			if i > 9 || i == 9 && b > 1 {
				return x, overflow
			}
			return x | uint64(b)<<s, nil
		}
		x |= uint64(b&0x7f) << s
		s += 7
	}
}
