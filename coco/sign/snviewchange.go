package sign

import (
	"sync/atomic"

	log "github.com/Sirupsen/logrus"
)

func (sn *Node) ViewChange(view int, parent string, vcm *ViewChangeMessage) error {
	atomic.StoreInt64(&sn.ChangingView, TRUE)
	lsr := atomic.LoadInt64(&sn.LastSeenRound)
	log.Println(sn.Name(), "VIEW CHANGE MESSAGE: new Round == , oldlsr == , view == ", vcm.Round, lsr, view)

	atomic.StoreInt64(&sn.LastSeenRound, max(int64(vcm.Round), lsr))
	lsr = atomic.LoadInt64(&sn.LastSeenRound)

	iAmNextRoot := FALSE
	if sn.RootFor(vcm.ViewNo) == sn.Name() {
		iAmNextRoot = TRUE
	}

	sn.Views().Lock()
	_, exists := sn.Views().Views[vcm.ViewNo]
	sn.Views().Unlock()
	if !exists {
		log.Println("PEERS:", sn.Peers())
		children := sn.childrenForNewView(parent)
		log.Println("CREATING NEW VIEW with ", len(sn.HostListOn(view-1)), "hosts", "on view", view)
		sn.NewView(vcm.ViewNo, parent, children, sn.HostListOn(view-1))
	}

	sn.ActionsLock.Lock()

	sn.Actions = make([]*VoteRequest, 0)
	sn.ActionsLock.Unlock()

	log.Println(sn.Name(), ":multiplexing onto children:", sn.Children(view))
	sn.multiplexOnChildren(vcm.ViewNo, &SigningMessage{View: view, Type: ViewChange, Vcm: vcm})

	log.Println(sn.Name(), "waiting on view accept messages from children:", sn.Children(view))

	votes := len(sn.Children(view))

	log.Println(sn.Name(), "received view accept messages from children:", votes)

	var err error
	if iAmNextRoot == TRUE {

		if votes > len(sn.HostListOn(view))*2/3 {

			log.Println(sn.Name(), "quorum", votes, "of", len(sn.HostListOn(view)), "confirmed me as new root")
			vcfm := &ViewConfirmedMessage{ViewNo: vcm.ViewNo}
			sm := &SigningMessage{Type: ViewConfirmed, Vcfm: vcfm, From: sn.Name(), View: vcm.ViewNo}
			sn.multiplexOnChildren(vcm.ViewNo, sm)

			atomic.StoreInt64(&sn.ChangingView, FALSE)
			atomic.StoreInt64(&sn.lastView, int64(vcm.ViewNo))
			sn.viewChangeCh <- "root"
		} else {
			log.Errorln(sn.Name(), " (ROOT) DID NOT RECEIVE quorum", votes, "of", len(sn.HostList))
			return ViewRejectedError
		}
	} else {
		sn.RoundsAsRoot = 0

		vam := &ViewAcceptedMessage{ViewNo: vcm.ViewNo, Votes: votes}

		log.Println(sn.Name(), "putting up on view", view, "accept for view", vcm.ViewNo)
		err = sn.PutUp(context.TODO(), vcm.ViewNo, &SigningMessage{
			View: view,
			From: sn.Name(),
			Type: ViewAccepted,
			Vam:  vam})

		return err
	}

	return err
}

func (sn *Node) ViewChanged(view int, sm *SigningMessage) {
	log.Println(sn.Name(), "view CHANGED to", view)

	atomic.StoreInt64(&sn.ChangingView, FALSE)

	sn.viewChangeCh <- "regular"

	log.Println("in view change, children for view", view, sn.Children(view))
	sn.multiplexOnChildren(view, sm)
	log.Println(sn.Name(), " exited view CHANGE to", view)
}
