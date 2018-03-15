package ether

import (
	"encoding/binary"
	"net"
)

type EtherHeader struct {
	Dst  net.HardwareAddr
	Src  net.HardwareAddr
	Type uint16
}

func (e *EtherHeader) Length() int {
	return 14
}

func (e *EtherHeader) Marshal() ([]byte, error) {
	b := make([]byte, 14)
	copy(b[0:6], e.Dst[0:6])
	copy(b[6:12], e.Src[0:6])
	binary.BigEndian.PutUint16(b[12:14], e.Type)
	return b, nil
}

func (e *EtherHeader) Unmarshal(b []byte) error {
	c := make([]byte, 12)
	copy(c[0:12], b[0:12])
	e.Dst = c[0:6]
	e.Src = c[6:12]
	e.Type = binary.BigEndian.Uint16(b[12:14])

	return nil
}
