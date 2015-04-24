package shuf

import (
	"fmt"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/proof"
	"github.com/dedis/crypto/shuffle"
	"math/rand"
)

func GetRight(m Msg) *Msg {
	half := len(m.X) / 2
	m.LeftProofs = nil
	m.X = m.X[half:]
	m.Y = m.Y[half:]
	return &m
}

func GetLeft(m Msg) *Msg {
	half := len(m.X) / 2
	m.RightProofs = nil
	m.X = m.X[:half]
	m.Y = m.Y[:half]
	return &m
}

func (inf *Info) HandleClient(i int, m *Msg) {
	inf.VerifyDecrypts(m.LeftProofs, m.Y, inf.Suite.Point().Null())
	for _, val := range m.Y {
		d, e := val.Data()
		if e != nil {
			fmt.Printf("Client %v: Data got corrupted\n", i)
		} else {
			fmt.Printf("Client %v: %v\n", i, string(d))
		}
	}
}

func (inf *Info) Setup(msg abstract.Point, client int) (
	[]abstract.Point, []abstract.Point, int) {
	n := client % inf.NumNodes
	x, y := inf.Encrypt([]abstract.Point{msg}, inf.GroupKeys[n][0])
	return x, y, n
}

func MakeInfo(uinf UserInfo, seed int64) *Info {
	// Initialization
	inf := new(Info)
	inf.UserInfo = uinf
	rand.Seed(seed)
	inf.NumGroups = inf.NumClients / inf.MsgsPerGroup
	inf.NeffLen = inf.NumNodes / inf.NumGroups
	numLevels := inf.NumRounds / (2 * inf.NeffLen)
	inf.Routes = make([][][]int, inf.NumNodes)
	inf.EncryptKeys = make([][][2]abstract.Point, inf.NumNodes)
	inf.GroupKeys = make([][]abstract.Point, inf.NumNodes)
	for n := range inf.Routes {
		inf.Routes[n] = make([][]int, inf.NumRounds)
		inf.EncryptKeys[n] = make([][2]abstract.Point, numLevels)
		inf.GroupKeys[n] = make([]abstract.Point, numLevels)
	}
	inf.Active = make([][]int, inf.NumNodes)
	for n := range inf.Active {
		inf.Active[n] = make([]int, 0)
	}

	oldEnders := make([]int, inf.NumGroups)
	for level := 0; level < numLevels; level++ {
		groups := chunks(rand.Perm(inf.NumNodes), inf.NeffLen)
		p := rand.Perm(inf.NumGroups)

		// Establish the cross-connections between Neff Shuffle groups
		if level != 0 {
			for i, e := range oldEnders {
				inf.Routes[e][(level+1)*2*inf.NeffLen-1] = []int{groups[i][0], groups[p[i]][0]}
				inf.EncryptKeys[e][level] = [2]abstract.Point{
					inf.PublicKey(groups[i]),
					inf.PublicKey(groups[p[i]]),
				}
			}
		}

		// Fix the directions within each group
		for gi, g := range groups {
			for i := range g {
				inf.GroupKeys[g[i]][level] = inf.PublicKey(g)
				inf.Active[g[i]] = append(inf.Active[g[i]], level*2*inf.NeffLen+i)
				if i < len(g)-1 {
					inf.Routes[g[i]][level*2*inf.NeffLen+i] = []int{g[i+1]}
				}
			}
			for i := range g {
				inf.Active[g[i]] = append(inf.Active[g[i]], (level*2+1)*inf.NeffLen+i)
				if i < len(g)-1 {
					inf.Routes[g[i]][(level*2+1)*inf.NeffLen+i] = []int{g[i+1]}
				}
			}
			lst := g[len(g)-1]
			inf.Routes[lst][(level*2+1)*inf.NeffLen-1] = []int{g[0]}
			oldEnders[gi] = lst
		}
	}
	// need to set encryptkeys for the last level to be for null
	// can't just set encryptkeys for oldEnders. set it for everyone.
	// wasted space... is there a way not to?
	// yes: map node to groupid, then groupid to key
	return inf
}

func check(i int, e error) bool {
	if e != nil {
		fmt.Printf("Node %v: %s\n", i, e.Error())
		return true
	}
	return false
}

func (inf *Info) shuffle(x, y []abstract.Point, h abstract.Point, rnd abstract.Cipher) (
	[]abstract.Point, []abstract.Point, Proof) {
	xx, yy, prover := shuffle.Shuffle(inf.Suite, nil, h, x, y, rnd)
	prf, err := proof.HashProve(inf.Suite, "PairShuffle", rnd, prover)
	if err != nil {
		fmt.Printf("Error creating proof: %s\n", err.Error())
	}
	return xx, yy, Proof{x, y, prf}
}

func nonNil(left, right []Proof) []Proof {
	if left == nil {
		return right
	} else {
		return left
	}
}

func (inf *Info) HandleRound(i int, m *Msg) *Msg {
	subround := m.Round % (2 * inf.NeffLen)
	group := m.Round / (2 * inf.NeffLen)
	half := len(m.X) / 2
	rnd := inf.Suite.Cipher(nil)
	switch {

	// Is it a collection round?
	case subround == 0:
		inf.Cache.X = append(inf.Cache.X, m.X...)
		inf.Cache.Y = append(inf.Cache.Y, m.Y...)
		proofs := nonNil(m.LeftProofs, m.RightProofs)
		if proofs != nil && check(i, inf.VerifyDecrypts(proofs, m.Y, inf.GroupKeys[i][group])) {
			return nil
		}
		if len(inf.Cache.X) < inf.NumClients {
			inf.Cache.Proofs = proofs
			return nil
		} else {
			fmt.Printf("Done collecting for round %d\n", m.Round)
			var prf Proof
			m.X, m.Y, prf = inf.shuffle(inf.Cache.X, inf.Cache.Y, inf.GroupKeys[i][m.Round], rnd)
			if inf.Cache.Proofs != nil {
				m.LeftProofs = inf.Cache.Proofs[1:]
				m.RightProofs = proofs[1:]
			}
			m.ShufProofs = []Proof{prf}
			m.Round = m.Round + 1
			return m
		}

	// Is it the first part of a cycle?
	case subround < inf.NeffLen:
		if check(i, inf.VerifyShuffles(m.ShufProofs, m.X, m.Y, inf.GroupKeys[i][group])) ||
			(m.LeftProofs != nil &&
				(check(i, inf.VerifyDecrypts(m.LeftProofs, m.ShufProofs[0].Y[:half], inf.GroupKeys[i][group])) ||
					check(i, inf.VerifyDecrypts(m.RightProofs, m.ShufProofs[0].Y[half:], inf.GroupKeys[i][group])))) {
			return nil
		}
		var prf Proof
		m.X, m.Y, prf = inf.shuffle(m.X, m.Y, inf.GroupKeys[i][m.Round], rnd)
		m.Round = m.Round + 1
		m.LeftProofs = m.LeftProofs[1:]
		m.RightProofs = m.RightProofs[1:]
		m.ShufProofs = append(m.ShufProofs, prf)

	// Verify a part of the second cycle
	case subround >= inf.NeffLen:
		var b bool
		if m.LeftProofs == nil || m.RightProofs == nil {
			m.LeftProofs = []Proof{}
			m.RightProofs = []Proof{}
			b = check(i, inf.VerifyShuffles(m.ShufProofs, m.X, m.Y, inf.GroupKeys[i][group]))
		} else {
			xs := append(m.LeftProofs[0].X, m.RightProofs[0].X...)
			ys := append(m.LeftProofs[0].Y, m.RightProofs[0].Y...)
			b = check(i, inf.VerifyShuffles(m.ShufProofs, xs, ys, inf.GroupKeys[i][group]))
			b = b || check(i, inf.VerifyDecrypts(m.LeftProofs, m.Y[:half], inf.EncryptKeys[i][group][0]))
			b = b || check(i, inf.VerifyDecrypts(m.RightProofs, m.Y[half:], inf.EncryptKeys[i][group][1]))
		}
		if b {
			return nil
		}
		leftNewX, leftY, leftPrf, lerr :=
			inf.Decrypt(m.X[:half], m.Y[:half], m.NewX[:half], i, inf.EncryptKeys[i][group][0])
		rightNewX, rightY, rightPrf, rerr :=
			inf.Decrypt(m.X[half:], m.Y[half:], m.NewX[:half], i, inf.EncryptKeys[i][group][0])
		if check(i, lerr) || check(i, rerr) {
			return nil
		}
		m.Y = append(leftY, rightY...)
		m.NewX = append(leftNewX, rightNewX...)
		m.ShufProofs = m.ShufProofs[1:]
		m.LeftProofs = append(m.LeftProofs, leftPrf)
		m.RightProofs = append(m.RightProofs, rightPrf)
		m.NewX = append(leftNewX, rightNewX...)
		m.Round = m.Round + 1

	}
	return m
}
