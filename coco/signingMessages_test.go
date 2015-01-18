package coco

import (
	"fmt"
	"testing"
)

func TestMarshallUnmarshall(t *testing.T) {
	logTest := []byte("Hello World")
	am := AnnouncementMessage{LogTest: logTest}

	dataBytes, err := AnnouncementMessage.MarshalBinary(am)
	if err != nil {
		t.Error("Marshaling didn't work")
	}

	am2 := &AnnouncementMessage{}
	am2.UnmarshalBinary(dataBytes)
	if err != nil {
		t.Error("Unmarshaling didn't work")
	}

	fmt.Println(am2)
	fmt.Println("Marshal and Unmarshal work")
}
