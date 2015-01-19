package coco

import (
	"fmt"
	"testing"

	"github.com/dedis/crypto/openssl"
	"github.com/dedis/crypto/random"
	"github.com/pkg/profile"
)

func TestTreeFromRandomGraph(t *testing.T) {
	defer profile.Start(profile.CPUProfile, profile.ProfilePath(".")).Stop()
	hc, _ := loadGraph("data/wax.dat", openssl.NewAES128SHA256P256(), random.Stream)

	// Have root node initiate the signing protocol
	// via a simple annoucement
	hc.SNodes[0].logTest = []byte("Hello World")
	fmt.Println(hc.SNodes[0].NChildren())
	fmt.Println(hc.SNodes[0].Peers())
	hc.SNodes[0].Announce(&AnnouncementMessage{hc.SNodes[0].logTest})
}
