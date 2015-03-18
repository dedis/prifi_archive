package sign_test

import (
	"testing"
	"time"

	_ "github.com/dedis/prifi/coco"
	"github.com/dedis/prifi/coco/sign"
	"github.com/dedis/prifi/coco/test/oldconfig"
)

// Configuration file data/exconf.json
//       0
//      / \
//     1   4
//    / \   \
//   2   3   5
func TestTreeSmallConfigVote(t *testing.T) {
	hc, err := oldconfig.LoadConfig("../test/data/exconf.json")
	if err != nil {
		t.Fatal(err)
	}

	err = hc.Run(false, sign.Vote)
	if err != nil {
		t.Fatal(err)
	}

	// Achieve consensus on removing a node
	hc.SNodes[0].LogTest = []byte("Hello Voting")
	vr := &sign.VoteRequest{Name: "host5", Action: "remove"}

	err = hc.SNodes[0].Announce(DefaultView,
		&sign.AnnouncementMessage{LogTest: hc.SNodes[0].LogTest,
			Round:       1,
			VoteRequest: vr})
	if err != nil {
		t.Error(err)
	}

	// Run a round with one less node
	// hc.SNodes[0].LogTest = []byte("Hello No Voting")
	// vr = &sign.VoteRequest{}

	// err = hc.SNodes[0].Announce(DefaultView,
	// 	&sign.AnnouncementMessage{LogTest: hc.SNodes[0].LogTest,
	// 		Round:       2,
	// 		VoteRequest: vr})
	// if err != nil {
	// 	t.Error(err)
	// }

}

func TestTCPStaticConfigVote(t *testing.T) {
	hc, err := oldconfig.LoadConfig("../test/data/extcpconf.json", oldconfig.ConfigOptions{ConnType: "tcp", GenHosts: true})
	if err != nil {
		t.Error(err)
	}
	defer func() {
		for _, n := range hc.SNodes {
			n.Close()
		}
		time.Sleep(1 * time.Second)
	}()

	err = hc.Run(false, sign.Vote)
	if err != nil {
		t.Fatal(err)
	}

	// give it some time to set up
	time.Sleep(2 * time.Second)

	hc.SNodes[0].LogTest = []byte("Hello Voting")
	vr := &sign.VoteRequest{Name: "host2", Action: "remove"}

	err = hc.SNodes[0].Announce(DefaultView,
		&sign.AnnouncementMessage{LogTest: hc.SNodes[0].LogTest,
			Round:       1,
			VoteRequest: vr})
	if err != nil {
		t.Error(err)
	}
}
