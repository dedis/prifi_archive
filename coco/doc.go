// This package is the beginning of the implementation of collective
// concurrency. It implements a basic collective signing protocol.
package coco

import "log"

func init() {
	// specialize logger
	log.SetFlags(log.Lshortfile)
}
