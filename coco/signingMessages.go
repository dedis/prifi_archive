package coco

import (
	"github.com/dedis/crypto/abstract"
)

// Broadcasted message initiated and signed by proposer
type AnnouncementMessage struct {
	logTest []byte
}

type CommitmentMessage struct {
	V     abstract.Point // commitment Point
	V_hat abstract.Point // product of children's commitment points
}

type ChallengeMessage struct {
	c abstract.Secret // challenge
}

type ResponseMessage struct {
	r_hat abstract.Secret // response
}
