package netchan

import (
	// "fmt"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/prifi/shuf"
	"net"
	"time"
)

// TCP Protocol for Servers:
// All connections are handled by the server on separate threads
// Two types of messages (check header):

// MSG:
// round int
// wait for OK
// then MsgsPerGroup xs
// then MsgsPerGroup ys
// then H

// PROOFMSG
// proof sized []byte
// MsgsPerGroup newXs
// MsgsPerGroup newYs
// MsgsPerGroup oldXs
// MsgsPerGroup oldYs
// then H

// TCP Protocol for Clients:
// Send server an MSG
// Then listen, handling connections on separate threads
// Two types of messages (check header):

// RESULT:
// MsgsPerGroup Xs
// MsgsPerGroup Ys

// PROOFMSG
// proof sized []byte
// MsgsPerGroup newXs
// MsgsPerGroup newYs
// MsgsPerGroup oldXs
// MsgsPerGroup oldYs
// then H

func check(e error) {
	if e != nil {
		panic(e.Error())
	}
}

func StartClient(s shuf.Shuffle, c int, nodes []string,
	inf *shuf.Info, msg string, port string) {

	rand := inf.Suite.Cipher(abstract.RandomKey)
	p, _ := inf.Suite.Point().Pick([]byte(msg), rand)
	X, Y, H := shuf.OnionEncrypt([]abstract.Point{p}, inf, []int{0})

	for _, node := range nodes {
		go func() {
			for {
				conn, err := net.Dial("tcp", node)
				check(err)
				_, err = conn.Write([]byte{0})
				conn.SetReadDeadline(time.Now().Add(inf.ResendTime))
				okBuf := make([]byte, 1)
				_, err = conn.Read(okBuf)
				if err == nil {
					_, err = conn.Write([]byte{1})
					check(err)
					Xbytes, _ := X[0].MarshalBinary()
					_, err = conn.Write(Xbytes)
					check(err)
					Ybytes, _ := Y[0].MarshalBinary()
					_, err = conn.Write(Ybytes)
					check(err)
					Hbytes, _ := H.MarshalBinary()
					_, err = conn.Write(Hbytes)
					check(err)
					break
				} else {
					conn.Close()
				}
			}
		}()
	}

	// ln, err := net.Listen("tcp", port)
	// check(err)
	// now collect all entries
}

func StartServer(s shuf.Shuffle, c int, clients []string,
	inf *shuf.Info, port string) {

}
