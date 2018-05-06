package main

import (
	"net"
	"strconv"
	"strings"
)

func InterfaceByAddr(s string) (*net.Interface, error) {
	target := net.ParseIP(s)
	var retIfi net.Interface
	longest := 0

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
				mask, err := strconv.Atoi(strings.Split(a.String(), "/")[1])

				if err != nil {
					continue
				}

				if mask > longest {
					retIfi = ifi
					longest = mask
				}
			}

		}

	}

	if retIfi.Index != 0 {
		return &retIfi, nil
	}

	return nil, nil
}
