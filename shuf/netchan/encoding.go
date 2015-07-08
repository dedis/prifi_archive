package netchan

import (
	"encoding/binary"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/prifi/shuf"
	"io"
	"log"
)

func errs(l ...error) error {
	for _, e := range l {
		if e != nil {
			return e
		}
	}
	return nil
}

func myWrite(w io.Writer, b []byte) error {
	_, e := w.Write(b)
	return e
}

func readProof(r io.Reader) ([][]byte, error) {
	var innerLen, outerLen int32
	e := binary.Read(r, binary.BigEndian, &outerLen)
	if e != nil || outerLen == 0 {
		return nil, e
	}
	log.Printf("Requested %d proofs of size %d", outerLen, innerLen)
	result := make([][]byte, outerLen)
	e = binary.Read(r, binary.BigEndian, &innerLen)
	if e != nil {
		return nil, e
	}
	for i := range result {
		result[i] = make([]byte, innerLen)
		_, err := io.ReadFull(r, result[i])
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

func ensureEqual(l int32, p [][]byte) {
	for _, x := range p {
		if int32(len(x)) != l {
			panic("Unequal lengths")
		}
	}
}

func writeProof(w io.Writer, p [][]byte) error {
	var innerlen, outerlen int32
	outerlen = int32(len(p))
	e := binary.Write(w, binary.BigEndian, outerlen)
	if e != nil {
		return e
	}
	if len(p) > 0 {
		innerlen = int32(len(p[0]))
		ensureEqual(innerlen, p)
		log.Printf("Writing %d proofs of size %d", outerlen, innerlen)
		e = binary.Write(w, binary.BigEndian, innerlen)
		if e != nil {
			return e
		}
	}
	for _, bs := range p {
		e = myWrite(w, bs)
		if e != nil {
			return e
		}
	}
	return nil
}

func writePoints(w io.Writer, X []abstract.Point) error {
	l := int32(len(X))
	log.Printf("Writing %d pairs", l)
	err1 := binary.Write(w, binary.BigEndian, l)
	if err1 != nil {
		return err1
	}
	for _, x := range X {
		_, e := x.MarshalTo(w)
		if e != nil {
			return e
		}
	}
	return nil
}

func writeShufProofs(w io.Writer, ps []shuf.ShufProof) error {
	e := binary.Write(w, binary.BigEndian, int32(len(ps)))
	if e != nil {
		return e
	}
	for _, p := range ps {
		e1 := errs(
			writePoints(w, p.X),
			writePoints(w, p.Y),
			writeProof(w, p.Proof))
		if e1 != nil {
			return e1
		}
	}
	return nil
}

func writeMsg(w io.Writer, m *shuf.Msg) error {
	return errs(
		writePoints(w, m.X),
		writePoints(w, m.Y),
		writePoints(w, m.NewX),
		writeShufProofs(w, m.ShufProofs),
		writeDecProofs(w, m.LeftProofs),
		writeDecProofs(w, m.RightProofs),
		writeSplitProof(w, m.SplitProof))
}

func writeDecProofs(w io.Writer, ps []shuf.DecProof) error {
	e1 := binary.Write(w, binary.BigEndian, int32(len(ps)))
	if e1 != nil {
		return e1
	}
	for _, p := range ps {
		e2 := errs(
			writePoints(w, p.Y),
			writeProof(w, p.Proof))
		if e2 != nil {
			return e2
		}
	}
	return nil
}

func writeSplitProof(w io.Writer, p *shuf.SplitProof) error {
	if p == nil {
		_, err := w.Write([]byte{0})
		return err
	}
	return errs(
		myWrite(w, []byte{byte(1)}),
		writePoints(w, p.X),
		writePoints(w, p.Y))
}

func (n Node) readMsg(r io.Reader, m *shuf.Msg) error {
	var err error
	m.X, err = n.readPoints(r)
	if err != nil {
		return err
	}
	m.Y, err = n.readPoints(r)
	if err != nil {
		return err
	}
	m.NewX, err = n.readPoints(r)
	if err != nil {
		return err
	}
	m.ShufProofs, err = n.readShufProofs(r)
	if err != nil {
		return err
	}
	m.LeftProofs, err = n.readDecProofs(r)
	if err != nil {
		return err
	}
	m.RightProofs, err = n.readDecProofs(r)
	if err != nil {
		return err
	}
	m.SplitProof, err = n.readSplitProof(r)
	return err
}

func (n Node) readShufProofs(reader io.Reader) ([]shuf.ShufProof, error) {
	var numProofs int32
	err := binary.Read(reader, binary.BigEndian, &numProofs)
	if numProofs < 1 || err != nil {
		return nil, err
	}
	Proofs := make([]shuf.ShufProof, numProofs)
	for i := range Proofs {
		Proofs[i].X, err = n.readPoints(reader)
		if err != nil {
			return nil, err
		}
		Proofs[i].Y, err = n.readPoints(reader)
		if err != nil {
			return nil, err
		}
		Proofs[i].Proof, err = readProof(reader)
		if err != nil {
			return nil, err
		}
	}
	return Proofs, nil
}

func (n Node) readSplitProof(reader io.Reader) (*shuf.SplitProof, error) {
	nilBuf := make([]byte, 1)
	_, err := io.ReadFull(reader, nilBuf)
	if err != nil || nilBuf[0] == 0 {
		return nil, err
	}
	splitProof := new(shuf.SplitProof)
	splitProof.X, err = n.readPoints(reader)
	if err != nil {
		return nil, err
	}
	splitProof.Y, err = n.readPoints(reader)
	return splitProof, err
}

func (n Node) readDecProofs(reader io.Reader) ([]shuf.DecProof, error) {
	var numProofs int32
	err := binary.Read(reader, binary.BigEndian, &numProofs)
	if numProofs < 1 || err != nil {
		return nil, err
	}
	proofs := make([]shuf.DecProof, numProofs)
	for i := range proofs {
		proofs[i].Y, err = n.readPoints(reader)
		if err != nil {
			return nil, err
		}
		proofs[i].Proof, err = readProof(reader)
		if err != nil {
			return nil, err
		}
	}
	return proofs, nil
}

func (n Node) readPoints(reader io.Reader) ([]abstract.Point, error) {
	var numPairs int32
	err := binary.Read(reader, binary.BigEndian, &numPairs)
	if numPairs > 0 && err == nil {
		log.Printf("Requested space for %d pairs", numPairs)
		X := make([]abstract.Point, numPairs)
		for i := range X {
			X[i] = n.Inf.Suite.Point()
			_, err = X[i].UnmarshalFrom(reader)
			if err != nil {
				return nil, err
			}
		}
		return X, nil
	} else {
		return nil, err
	}
}
