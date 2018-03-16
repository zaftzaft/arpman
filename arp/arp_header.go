package arp

import (
	"encoding/binary"
	"fmt"
	"net"
)

type ArpOp uint16

const (
	ArpOpRequest ArpOp = 0x0001
	ArpOpReplay  ArpOp = 0x0002
)

func (o ArpOp) String() string {
	switch o {
	case ArpOpRequest:
		return "Request"
	case ArpOpReplay:
		return "Replay"
	default:
		return "Unknown: " + string(o)
	}

}

type ArpHeader struct {
	HwType uint16
	PrType uint16
	HwLen  uint8
	IPLen  uint8
	Op     ArpOp
	HwSrc  net.HardwareAddr
	IPSrc  net.IP
	HwDst  net.HardwareAddr
	IPDst  net.IP
}

func (a *ArpHeader) Length() int {
	return 28
}

func (a *ArpHeader) Marshal() ([]byte, error) {
	b := make([]byte, 28)
	binary.BigEndian.PutUint16(b[0:2], a.HwType)
	binary.BigEndian.PutUint16(b[2:4], a.PrType)
	b[4] = a.HwLen
	b[5] = a.IPLen
	binary.BigEndian.PutUint16(b[6:8], uint16(a.Op))

	copy(b[8:14], a.HwSrc[0:6])
	copy(b[14:18], a.IPSrc[0:4])
	copy(b[18:24], a.HwDst[0:6])
	copy(b[24:28], a.IPDst[0:4])

	return b, nil
}

func (a *ArpHeader) Unmarshal(b []byte) error {
	// length check
	if len(b) < 28 {
		return fmt.Errorf("invaild arp length: %d", len(b))
	}

	a.HwType = binary.BigEndian.Uint16(b[0:2])
	a.PrType = binary.BigEndian.Uint16(b[2:4])
	a.HwLen = b[4]
	a.IPLen = b[5]
	a.Op = ArpOp(binary.BigEndian.Uint16(b[6:8]))

	c := make([]byte, 20)
	copy(c[0:20], b[8:28])

	a.HwSrc = c[0:6]
	a.IPSrc = c[6:10]
	a.HwDst = c[10:16]
	a.IPDst = c[16:20]

	return nil
}
