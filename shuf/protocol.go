package shuf

import (
	"fmt"
	"github.com/dedis/crypto/abstract"
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
	g := client % inf.NumGroups
	x, y := inf.Encrypt([]abstract.Point{msg}, inf.GroupKeys[g][0])
	return x, y, inf.StartNodes[g]
}

func MakeInfo(uinf UserInfo, seed int64) *Info {
	inf := new(Info)
	inf.UserInfo = uinf
	rand.Seed(seed)
	inf.NumGroups = inf.NumClients / inf.MsgsPerGroup
	inf.NeffLen = inf.NumNodes / inf.NumGroups
	numLevels := inf.NumRounds / (2 * inf.NeffLen)
	inf.Routes = make([][][]int, inf.NumNodes)
	inf.EncryptKeys = make([][][2]abstract.Point, inf.NumGroups)
	inf.GroupKeys = make([][]abstract.Point, inf.NumGroups)
	inf.NodeGroup = make([]int, inf.NumNodes)
	inf.StartNodes = make([]int, inf.NumGroups)
	for n := range inf.Routes {
		inf.Routes[n] = make([][]int, inf.NumRounds)
	}
	for n := range inf.EncryptKeys {
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
				inf.Routes[e][level*2*inf.NeffLen-1] = []int{groups[i][0], groups[p[i]][0]}
				inf.EncryptKeys[i][level-1] = [2]abstract.Point{
					inf.PublicKey(groups[i]),
					inf.PublicKey(groups[p[i]]),
				}
			}
		} else {
			for gi, g := range groups {
				inf.StartNodes[gi] = g[0]
			}
		}

		// Fix the directions within each group
		for gi, g := range groups {
			inf.GroupKeys[gi][level] = inf.PublicKey(g)
			for i := range g {
				inf.NodeGroup[g[i]] = gi
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

	// Set the last EncryptKeys to the null element
	for i := range inf.EncryptKeys {
		inf.EncryptKeys[i][numLevels-1] = [2]abstract.Point{
			inf.Suite.Point().Null(),
			inf.Suite.Point().Null(),
		}
	}
	return inf
}

func check(i, r int, e error) bool {
	if e != nil {
		fmt.Printf("Node %v, round %d: %s\n", i, r, e.Error())
		return true
	}
	return false
}

func nonNil(left, right []Proof) []Proof {
	if left == nil {
		return right
	} else {
		return left
	}
}

func clearCache(cache *Cache) {
	cache.X = nil
	cache.Y = nil
	cache.Proofs = nil
}

func (inf *Info) HandleRound(i int, m *Msg, cache *Cache) *Msg {
	subround := m.Round % (2 * inf.NeffLen)
	level := m.Round / (2 * inf.NeffLen)
	groupKey := inf.GroupKeys[inf.NodeGroup[i]][level]
	half := len(m.X) / 2
	rnd := inf.Suite.Cipher(nil)
	switch {

	// Is it a collection round?
	case subround == 0:
		cache.X = append(cache.X, m.X...)
		cache.Y = append(cache.Y, m.Y...)
		proofs := nonNil(m.LeftProofs, m.RightProofs)
		if proofs != nil && check(i, m.Round, inf.VerifyDecrypts(proofs, m.Y, groupKey)) {
			return nil
		}
		if len(cache.X) < inf.MsgsPerGroup {
			cache.Proofs = proofs
			return nil
		} else {
			var prf Proof
			m.X, m.Y, prf = inf.Shuffle(cache.X, cache.Y, groupKey, rnd)
			if cache.Proofs != nil {
				m.LeftProofs = cache.Proofs[1:]
				m.RightProofs = proofs[1:]
			}
			m.ShufProofs = []Proof{prf}
			m.Round = m.Round + 1
			clearCache(cache)
			return m
		}

	// Is it the first part of a cycle?
	case subround < inf.NeffLen:
		if check(i, m.Round, inf.VerifyShuffles(m.ShufProofs, m.X, m.Y, groupKey)) ||
			m.LeftProofs != nil &&
				(check(i, m.Round, inf.VerifyDecrypts(m.LeftProofs, m.ShufProofs[0].Y[:half], groupKey)) ||
					check(i, m.Round, inf.VerifyDecrypts(m.RightProofs, m.ShufProofs[0].Y[half:], groupKey))) {
			return nil
		}
		var prf Proof
		m.X, m.Y, prf = inf.Shuffle(m.X, m.Y, groupKey, rnd)
		m.Round = m.Round + 1
		if m.LeftProofs != nil && m.RightProofs != nil {
			m.LeftProofs = m.LeftProofs[1:]
			m.RightProofs = m.RightProofs[1:]
		}
		m.ShufProofs = append(m.ShufProofs, prf)

	// Verify a part of the second cycle
	case subround >= inf.NeffLen:
		encryptKey := inf.EncryptKeys[inf.NodeGroup[i]][level]
		var b bool
		if len(m.LeftProofs) < 1 || len(m.RightProofs) < 1 {
			b = check(i, m.Round, inf.VerifyShuffles(m.ShufProofs, m.X, m.Y, groupKey))
		} else {
			xs := append(m.LeftProofs[0].X, m.RightProofs[0].X...)
			ys := append(m.LeftProofs[0].Y, m.RightProofs[0].Y...)
			b = check(i, m.Round, inf.VerifyShuffles(m.ShufProofs, xs, ys, groupKey))
			b = b || check(i, m.Round, inf.VerifyDecrypts(m.LeftProofs, m.Y[:half], encryptKey[0]))
			b = b || check(i, m.Round, inf.VerifyDecrypts(m.RightProofs, m.Y[half:], encryptKey[1]))
		}
		if b {
			return nil
		}
		if m.NewX == nil {
			m.NewX = make([]abstract.Point, len(m.X))
			for x := range m.NewX {
				m.NewX[x] = inf.Suite.Point().Null()
			}
		}
		leftNewX, leftY, leftPrf, lerr :=
			inf.Decrypt(m.X[:half], m.Y[:half], m.NewX[:half], i, encryptKey[0])
		rightNewX, rightY, rightPrf, rerr :=
			inf.Decrypt(m.X[half:], m.Y[half:], m.NewX[:half], i, encryptKey[1])
		if check(i, m.Round, lerr) || check(i, m.Round, rerr) {
			return nil
		}
		m.Y = append(leftY, rightY...)
		m.ShufProofs = m.ShufProofs[1:]
		m.LeftProofs = append(m.LeftProofs, leftPrf)
		m.RightProofs = append(m.RightProofs, rightPrf)
		m.NewX = append(leftNewX, rightNewX...)
		m.Round = m.Round + 1
		if subround == inf.NeffLen*2-1 {
			m.X = m.NewX
			m.NewX = nil
		}

	}
	return m
}
