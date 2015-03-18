package sign_test

import (
	"testing"

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
	hostConfig, err := oldconfig.LoadConfig("../test/data/exconf.json")
	if err != nil {
		t.Fatal(err)
	}

	err = hostConfig.Run(false, sign.Vote)
	if err != nil {
		t.Fatal(err)
	}

	// Have root node initiate the signing votes protocol via a simple annoucement
	hostConfig.SNodes[0].LogTest = []byte("Hello Voting")
	vr := &sign.VoteRequest{Name: "host5", Action: "remove"}

	hostConfig.SNodes[0].Announce(DefaultView,
		&sign.AnnouncementMessage{LogTest: hostConfig.SNodes[0].LogTest,
			Round:       1,
			VoteRequest: vr})
}
