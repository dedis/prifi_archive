package sign

import (
	log "github.com/Sirupsen/logrus"
	"golang.org/x/net/context"
)

func (sn *Node) AddSelf(parent string) error {
	log.Println("AddSelf: connecting to:", parent)
	err := sn.ConnectTo(parent)
	if err != nil {
		return err
	}

	log.Println("AddSelf: putting group change message to:", parent)
	return sn.PutTo(
		context.TODO(),
		parent,
		&SigningMessage{
			Type: GroupChange,
			View: -1,
			Vrm: &VoteRequestMessage{
				Vote: &Vote{
					Type: AddVT,
					Av: &AddVote{
						Name:   sn.Name(),
						Parent: parent}}}})
}

func (sn *Node) RemoveSelf() error {
	return sn.PutUp(
		context.TODO(),
		int(sn.lastView),
		&SigningMessage{
			Type: GroupChange,
			View: -1,
			Vrm: &VoteRequestMessage{
				Vote: &Vote{
					Type: RemoveVT,
					Rv: &RemoveVote{
						Name:   sn.Name(),
						Parent: sn.Parent(sn.lastView)}}}})
}
