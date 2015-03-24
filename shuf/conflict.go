package shuf

func xorInto(a []byte, b []byte) {
	for i := range a {
		a[i] ^= b[i]
	}
}

// Potentially conflicting shuffle
type ConflictSwap Butterfly

func (s ConflictSwap) ShuffleStep(msgs [][]byte, node NodeId,
	round int, inf *Info) []RouteInstr {
	vnode := node.Virtual

	if round >= len(s.Left) {
		return []RouteInstr{RouteInstr{nil, msgs}}
	}

	leftBytes := make([]byte, inf.MsgSize)
	rightBytes := make([]byte, inf.MsgSize)
	switch s.rnd.Intn(1) {
	case 0:
		xorInto(leftBytes, msgs[0])
	case 1:
		xorInto(rightBytes, msgs[0])
	}
	switch s.rnd.Intn(1) {
	case 0:
		xorInto(leftBytes, msgs[1])
	case 1:
		xorInto(rightBytes, msgs[1])
	}

	// testing hack
	// leftBytes := msgs[0]
	// rightBytes := msgs[1]

	var pleft int = s.Left[round][vnode]
	var pright int = s.Right[round][vnode]
	return []RouteInstr{
		RouteInstr{&NodeId{s.Physical[pleft], pleft}, [][]byte{leftBytes}},
		RouteInstr{&NodeId{s.Physical[pright], pright}, [][]byte{rightBytes}},
	}
}

func (cs ConflictSwap) InitialNode(msg []byte, client int, inf *Info) NodeId {
	v := client % (inf.NumClients / 2)
	return NodeId{cs.Physical[v], v}
}
