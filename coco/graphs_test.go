package coco

import "testing"

func TestTreeFromRandomGraph(t *testing.T) {
	//defer profile.Start(profile.CPUProfile, profile.ProfilePath(".")).Stop()
	//hc, _ := loadGraph("data/wax.dat", openssl.NewAES128SHA256P256(), random.Stream)
	/*if err := ioutil.WriteFile("data/wax.json", []byte(hc.String()), 0666); err != nil {
		fmt.Println(err)
	}*/
	//fmt.Println(hc.String())

	// Have root node initiate the signing protocol
	// via a simple annoucement
	//hc.SNodes[0].logTest = []byte("Hello World")
	//fmt.Println(hc.SNodes[0].NChildren())
	//fmt.Println(hc.SNodes[0].Peers())
	//hc.SNodes[0].Announce(&AnnouncementMessage{hc.SNodes[0].logTest})
}
