package shuf

import (
	"fmt"
	"github.com/dedis/crypto/abstract"
	"log"
	"math/rand"
)

func GetRight(m Msg) *Msg {
	half := len(m.Y) / 2
	m.LeftProofs = nil
	m.NewX = m.NewX[half:]
	m.X = m.X[half:]
	m.Y = m.Y[half:]
	return &m
}

func GetLeft(m Msg) *Msg {
	half := len(m.Y) / 2
	m.RightProofs = nil
	m.NewX = m.NewX[:half]
	m.X = m.X[:half]
	m.Y = m.Y[:half]
	return &m
}

// Return value indicates whether the client is done
func (inf *Info) HandleClient(i int, m *Msg) int {
	half := len(m.Y) / 2
	if check(i, m.Round, inf.VerifyDecrypts(m.LeftProofs, m.X[:half], m.Y[:half], inf.Suite.Point().Null())) ||
		check(i, m.Round, inf.VerifyDecrypts(m.RightProofs, m.X[half:], m.Y[half:], inf.Suite.Point().Null())) {
		fmt.Printf("Client %v: Invalid message proof\n", i)
		return 0
	}
	for _, val := range m.Y {
		d, e := val.Data()
		if e != nil {
			fmt.Printf("Client %v: Data got corrupted\n", i)
		} else {
			fmt.Printf("Client %v: %v\n", i, string(d))
		}
	}
	return len(m.Y)
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
	inf.NodeGroup = make([][]int, inf.NumNodes)
	inf.StartNodes = make([]int, inf.NumGroups)
	for n := range inf.Routes {
		inf.Routes[n] = make([][]int, inf.NumRounds)
	}
	for n := range inf.NodeGroup {
		inf.NodeGroup[n] = make([]int, numLevels)
	}
	for n := range inf.EncryptKeys {
		inf.EncryptKeys[n] = make([][2]abstract.Point, numLevels)
		inf.GroupKeys[n] = make([]abstract.Point, numLevels)
	}
	inf.Active = make([][]int32, inf.NumNodes)
	for n := range inf.Active {
		inf.Active[n] = make([]int32, 0)
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
				inf.NodeGroup[g[i]][level] = gi
				inf.Active[g[i]] = append(inf.Active[g[i]], int32(level*2*inf.NeffLen+i))
				if i < len(g)-1 {
					inf.Routes[g[i]][level*2*inf.NeffLen+i] = []int{g[i+1]}
				}
			}
			for i := range g {
				inf.Active[g[i]] = append(inf.Active[g[i]], int32((level*2+1)*inf.NeffLen+i))
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

func check(i int, r int32, e error) bool {
	if e != nil {
		log.Printf("Node %v round %d: %s\n", i, r, e.Error())
		return true
	}
	return false
}

func nonNil(left, right []DecProof) []DecProof {
	if len(left) < 1 {
		return right
	} else {
		return left
	}
}

func clearCache(cache *Cache) {
	cache.X = nil
	cache.Y = nil
	cache.NewX = nil
	cache.Proofs = nil
}

func (inf *Info) HandleRound(i int, m *Msg, cache *Cache) *Msg {
	subround := int(m.Round) % (2 * inf.NeffLen)
	level := int(m.Round) / (2 * inf.NeffLen)
	groupKey := inf.GroupKeys[inf.NodeGroup[i][level]][level]
	encryptKey := inf.EncryptKeys[inf.NodeGroup[i][level]][level]
	half := len(m.Y) / 2
	rnd := inf.Suite.Cipher(nil)
	switch {

	// Is it a collection round?
	case subround == 0:
		cache.NewX = append(cache.NewX, m.NewX...)
		cache.X = append(cache.X, m.X...)
		cache.Y = append(cache.Y, m.Y...)
		proofs := nonNil(m.LeftProofs, m.RightProofs)
		if len(proofs) > 0 && check(i, m.Round, inf.VerifyDecrypts(proofs, m.X, m.Y, groupKey)) {
			return nil
		}
		if len(cache.NewX) < inf.MsgsPerGroup {
			cache.Proofs = proofs
			return nil
		} else {
			var prf ShufProof
			m.NewX, m.Y, prf = inf.Shuffle(cache.NewX, cache.Y, groupKey, rnd)
			m.X = cache.X

			if len(cache.Proofs) > 0 {
				m.LeftProofs = cache.Proofs[1:]
				m.RightProofs = proofs[1:]
			}
			if subround != inf.NeffLen-1 {
				m.ShufProofs = []ShufProof{prf}
			}
			m.Round = m.Round + 1
			clearCache(cache)
		}

	// Is it the first cycle?
	case subround < inf.NeffLen:
		lastY := m.ShufProofs[0].Y
		if check(i, m.Round, inf.VerifyShuffles(m.ShufProofs, m.NewX, m.Y, groupKey)) ||
			len(m.LeftProofs) > 0 &&
				(check(i, m.Round, inf.VerifyDecrypts(m.LeftProofs, m.X[:half], lastY[:half], groupKey)) ||
					check(i, m.Round, inf.VerifyDecrypts(m.RightProofs, m.X[half:], lastY[half:], groupKey))) {
			return nil
		}
		var prf ShufProof
		m.NewX, m.Y, prf = inf.Shuffle(m.NewX, m.Y, groupKey, rnd)
		m.Round = m.Round + 1
		if len(m.LeftProofs) > 0 && len(m.RightProofs) > 0 {
			m.LeftProofs = m.LeftProofs[1:]
			m.RightProofs = m.RightProofs[1:]
		}
		m.ShufProofs = append(m.ShufProofs, prf)
		if subround == inf.NeffLen-1 {
			m.ShufProofs = m.ShufProofs[1:]
		}

	// Is it the start of the second cycle?
	case subround == inf.NeffLen:
		if len(m.ShufProofs) > 0 {
			if check(i, m.Round, inf.VerifyShuffles(m.ShufProofs, m.NewX, m.Y, groupKey)) {
				return nil
			}
			m.ShufProofs = m.ShufProofs[1:]
		}
		temp := m.X
		m.X = m.NewX
		m.NewX = temp
		if len(m.NewX) < 1 {
			m.NewX = make([]abstract.Point, len(m.X))
		}
		for x := range m.NewX {
			m.NewX[x] = inf.Suite.Point().Null()
		}
		m.SplitProof = new(SplitProof)
		m.SplitProof.X = m.X
		m.SplitProof.Y = m.Y
		inf.Split.Split(inf, m)
		newY := make([]abstract.Point, len(m.Y))
		leftPrf, lerr := inf.Decrypt(m.X[:half], m.Y[:half], m.NewX[:half], newY[:half], i, encryptKey[0])
		rightPrf, rerr := inf.Decrypt(m.X[half:], m.Y[half:], m.NewX[half:], newY[half:], i, encryptKey[1])
		if check(i, m.Round, lerr) || check(i, m.Round, rerr) {
			return nil
		}
		m.Y = newY
		m.Round = m.Round + 1
		switch {
		case m.Round == int32(inf.NumRounds):
			m.NewX = nil
			m.SplitProof = nil
		case subround == inf.NeffLen*2-1:
			m.SplitProof = nil
		default:
			m.LeftProofs = []DecProof{leftPrf}
			m.RightProofs = []DecProof{rightPrf}
		}

	// Is it in the second cycle?
	case subround >= inf.NeffLen:
		if len(m.LeftProofs) < 1 || len(m.RightProofs) < 1 || len(m.NewX) < 1 {
			log.Printf("Node %d round %d: no encryption proofs\n", i, m.Round)
			return nil
		}
		if check(i, m.Round, inf.VerifyShuffles(m.ShufProofs, m.SplitProof.X, m.SplitProof.Y, groupKey)) ||
			check(i, m.Round, inf.Split.VerifySplit(inf, m.SplitProof, m.X, m.LeftProofs[0].Y, m.RightProofs[0].Y)) ||
			check(i, m.Round, inf.VerifyDecrypts(m.LeftProofs, m.X[:half], m.Y[:half], encryptKey[0])) ||
			check(i, m.Round, inf.VerifyDecrypts(m.RightProofs, m.X[half:], m.Y[half:], encryptKey[1])) {
			return nil
		}
		newY := make([]abstract.Point, len(m.Y))
		leftPrf, lerr := inf.Decrypt(m.X[:half], m.Y[:half], m.NewX[:half], newY[:half], i, encryptKey[0])
		rightPrf, rerr := inf.Decrypt(m.X[half:], m.Y[half:], m.NewX[half:], newY[half:], i, encryptKey[1])
		if check(i, m.Round, lerr) || check(i, m.Round, rerr) {
			return nil
		}
		m.Y = newY
		if len(m.ShufProofs) > 0 {
			m.ShufProofs = m.ShufProofs[1:]
		}
		m.LeftProofs = append(m.LeftProofs, leftPrf)
		m.RightProofs = append(m.RightProofs, rightPrf)
		m.Round = m.Round + 1
		switch {
		case m.Round == int32(inf.NumRounds):
			m.NewX = nil
			m.SplitProof = nil
			m.LeftProofs = m.LeftProofs[1:]
			m.RightProofs = m.RightProofs[1:]
		case subround == inf.NeffLen*2-1:
			m.SplitProof = nil
			m.LeftProofs = m.LeftProofs[1:]
			m.RightProofs = m.RightProofs[1:]
		}
	}
	return m
}
