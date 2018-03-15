package main

import (
	_ "net"
	"testing"
)

func TestAddr(t *testing.T) {
	ifi, err := InterfaceByAddr("192.168.1.1")

	if err != nil {
		t.Error(err)
	}

	t.Log(ifi)

	if ifi != nil {
		t.Log(ifi.Name)
	}
}
