package shuf

import (
	"errors"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/random"
)

// Generic interface for methods of dividing pairs in two halves
type Splitter interface {
	Split(m *Msg) // fill new m.X and m.Y
	VerifySplit(p *SplitProof, X, leftY, rightY []abstract.Point) error
}

// Random swapping
type Butterfly struct {
	Inf *Info
}

func arrEq(a []abstract.Point, b []abstract.Point) bool {
	for i := range a {
		if !a[i].Equal(b[i]) {
			return false
		}
	}
	return true
}

func (b Butterfly) Split(m *Msg) {}

func (b Butterfly) VerifySplit(p *SplitProof, X, leftY, rightY []abstract.Point) error {
	half := len(p.X) / 2
	if arrEq(p.Y[:half], leftY) && arrEq(p.Y[half:], rightY) && arrEq(p.X, X) {
		return nil
	} else {
		return errors.New("Invalid butterfly split")
	}
}

// Random routing
type Conflict struct {
	Inf *Info
}

func (c Conflict) Split(m *Msg) {
	rnd := c.Inf.Suite.Cipher(nil)
	X := make([]abstract.Point, len(m.X))
	Y := make([]abstract.Point, len(m.Y))
	for i := range X {
		X[i] = c.Inf.Suite.Point().Null()
		Y[i] = c.Inf.Suite.Point().Null()
	}
	half := len(m.X) / 2
	for i := range m.X {
		bit := int(random.Byte(rnd) & 1)
		p := (i + half*bit) % len(m.X)
		X[i] = c.Inf.Suite.Point().Add(X[i], m.X[p])
		Y[i] = c.Inf.Suite.Point().Add(Y[i], m.Y[p])
	}
	m.X = X
	m.Y = Y
}

func (c Conflict) VerifySplit(p *SplitProof, X, leftY, rightY []abstract.Point) error {
	half := len(X) / 2
	for i, x := range p.X[:half] {
		otherX := p.X[i+half]
		if !(X[i].Equal(x) || X[i].Equal(otherX) || X[i].Equal(c.Inf.Suite.Point().Add(x, otherX))) {
			return errors.New("Invalid conflict split")
		}
	}
	for i, y := range p.Y[:half] {
		otherY := p.Y[i+half]
		if !(leftY[i].Equal(y) || leftY[i].Equal(otherY) || leftY[i].Equal(c.Inf.Suite.Point().Add(y, otherY))) {
			return errors.New("Invalid conflict split")
		}
	}
	for i, y := range p.Y[half:] {
		otherY := p.Y[i]
		if !(rightY[i].Equal(y) || rightY[i].Equal(otherY) || rightY[i].Equal(c.Inf.Suite.Point().Add(y, otherY))) {
			return errors.New("Invalid conflict split")
		}
	}
	return nil
}
