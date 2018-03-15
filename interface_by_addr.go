package main

import (
	"net"
)

// TODO longest match
func InterfaceByAddr(s string) (*net.Interface, error) {
	target := net.ParseIP(s)

	ifis, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, ifi := range ifis {
		if ifi.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := ifi.Addrs()
		if err != nil {
			return nil, err
		}

		for _, a := range addrs {
			_, ipnet, err := net.ParseCIDR(a.String())
			if err != nil {
				return nil, err
			}

			if ipnet.Contains(target) {
				return &ifi, nil
			}

		}

	}

	return nil, nil
}
