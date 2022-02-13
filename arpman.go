package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/mdlayher/raw"
	"github.com/nsf/termbox-go"
	"github.com/zaftzaft/arpman/arp"
	"github.com/zaftzaft/arpman/ether"
	"gopkg.in/alecthomas/kingpin.v2"
)

const version = "0.0.5"

var (
	timeout    = kingpin.Flag("timeout", "timeout").Short('t').Default("1s").Duration()
	stdout     = kingpin.Flag("stdout", "stdout flag").Short('o').Bool()
	lookup     = kingpin.Flag("lookup", "OUI lookup").Short('l').Bool()
	burst      = kingpin.Flag("burst", "burst size").Short('b').Default("1").Int()
	configfile = kingpin.Arg("configfile", "config file path").Required().String()
)

type ExpirationAddr struct {
	IP   net.IP
	Time time.Time
	Addr net.HardwareAddr
	Own  bool
}

type Arpman struct {
	IfName  string
	Address net.IP
	Macs    []ExpirationAddr
}

type UseInterfaces []*net.Interface

func (u UseInterfaces) Contains(ifi *net.Interface) bool {
	for _, uifi := range u {
		if uifi.Name == ifi.Name {
			return true
		}
	}
	return false
}

func SetAttr(x, y int, fg, bg termbox.Attribute) {
	w, _ := termbox.Size()
	cells := termbox.CellBuffer()
	c := cells[y*w+x]

	cells[y*w+x] = termbox.Cell{c.Ch, fg, bg}
}

func main() {
	kingpin.Version(version)
	kingpin.Parse()
	os.Exit(Run())
}

func Run() int {
	var useInterfaces UseInterfaces
	sockets := make(map[string]*raw.Conn)
	arpmanList := make([]*Arpman, 0)

	fp, err := os.Open(*configfile)
	if err != nil {
		log.Printf("%v", err)
		return 1
	}
	defer fp.Close()

	scanner := bufio.NewScanner(fp)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}

		ip := net.ParseIP(line)

		if ip != nil {
			arpmanList = append(arpmanList,
				&Arpman{Address: ip},
			)
		}
	}

	// TODO error -> skip ?
	for i, arpman := range arpmanList {
		ifi, err := InterfaceByAddr(arpman.Address.String())
		if err != nil {
			log.Printf("failed to find interface : %v", err)
			return 1
		}
		if ifi == nil {
			log.Printf("failed to find interface by addr %s", arpman.Address.String())
			return 1
		}

		if !useInterfaces.Contains(ifi) {
			useInterfaces = append(useInterfaces, ifi)

			sockets[ifi.Name], err = raw.ListenPacket(ifi, 0x0806, nil)
			if err != nil {
				log.Printf("failed to listen %s : %v", ifi.Name, err)
				return 1
			}
		}

		arpmanList[i].IfName = ifi.Name
	}

	exa := make(chan *ExpirationAddr, 10)
	for _, uifi := range useInterfaces {
		go sniffer(sockets[uifi.Name], exa)
	}

	if !*stdout {
		err = termbox.Init()
		if err != nil {
			log.Printf("%v", err)
			return 1
		}
		defer termbox.Close()
	}

	events := make(chan termbox.Event)
	go func() {
		for {
			events <- termbox.PollEvent()
		}
	}()

	index := 0

	drawLine := func(x int, y int, str string) {
		for n, r := range []rune(str) {
			termbox.SetCell(x+n, y, r, termbox.ColorDefault, termbox.ColorDefault)
		}
	}

	render := func() {
		w, _ := termbox.Size()

		drawLine(0, 0, "arpman")

		//for y, arpman := range list {
		for y, arpman := range arpmanList {
			drawLine(0, y+1, strings.Repeat(" ", w)) // reset

			drawLine(2, y+1, arpman.Address.String())
			//drawLine(19, y+1, strconv.Itoa(len(arpman.Macs)))

			macs := len(arpman.Macs)
			if macs > 0 {
				for i := 0; i < macs; i++ {
					if arpman.Macs[i].Own {
						drawLine((i*19)+23, y+1, "Own!")
					} else {
						drawLine((i*19)+23, y+1, arpman.Macs[i].Addr.String())
					}
				}

				// DUP
				if macs > 1 {
					drawLine(19, y+1, "DUP")

					for i := 0; i < w; i++ {
						SetAttr(i, y+1, termbox.ColorRed, termbox.ColorDefault)
					}

				} else {
					// Success
					for i := 0; i < w; i++ {
						SetAttr(i, y+1, termbox.ColorGreen, termbox.ColorDefault)
					}
				}

			}
		}

		// draw arrow >
		//for y, _ := range list {
		for y, _ := range arpmanList {
			termbox.SetCell(0, y+1, ' ', termbox.ColorDefault, termbox.ColorDefault)
		}
		termbox.SetCell(0, index+1, '>', termbox.ColorDefault, termbox.ColorDefault)
	}

	nxch := make(chan int)
	srBurst := func(arpmanList []*Arpman) {
		for _, arpman := range arpmanList {
			SendARP(*arpman, sockets)
			arpman.Macs = make([]ExpirationAddr, 0)

			if IsInterfaceOwnAddr(arpman.IfName, arpman.Address) {
				arpman.Macs = append(arpman.Macs, ExpirationAddr{
					Own: true,
				})
			}
		}

		func() {
			for {
				select {
				case exaddr := <-exa:
					for _, arpman := range arpmanList {
						if exaddr.IP.Equal(arpman.Address) {
							arpman.Macs = append(arpman.Macs, *exaddr)
						}
					}

				case <-time.After(*timeout):
					return
				}
			}
		}()

		// next
		nxch <- 1
	}

	// ignition
	go func() {
		nxch <- 1
	}()

	lastFlag := false
	// main loop
	func() {
		prev := 0
		for {
			select {
			case <-nxch:

				if *stdout {

					if index > 0 {
						for _, arpman := range arpmanList[prev:index] {
							fmt.Printf("%s ", arpman.Address.String())
							for i := 0; i < len(arpman.Macs); i++ {
								if arpman.Macs[i].Own {
									fmt.Printf("Own! ")
								} else {
									fmt.Printf("%s ", arpman.Macs[i].Addr.String())
									if *lookup {
										b := arpman.Macs[i].Addr
										fmt.Printf("[%s] ", oui[((uint64(b[0])<<16)|(uint64(b[1])<<8)|(uint64(b[2])))])
									}
								}

							}
							fmt.Printf("\n")
						}
					}

				} else {
					render()
					termbox.Flush()
				}

				if lastFlag {
					return
				}

				t := *burst
				if index+t > len(arpmanList) {
					t = len(arpmanList) - index
				}
				go srBurst(arpmanList[index : index+t])
				prev = index
				index += t

				if index >= len(arpmanList) {
					if *stdout {
						lastFlag = true
					} else {
						index = 0
					}
				}

			case ev := <-events:
				switch ev.Type {
				case termbox.EventKey:
					if ev.Key == termbox.KeyEsc || ev.Key == termbox.KeyCtrlC {
						//break loop
						return
					}
				}
			}
		} // :loop
	}()

	return 0
}

func sniffer(c *raw.Conn, exa chan *ExpirationAddr) {
	var eh ether.EtherHeader
	var ah arp.ArpHeader

	data := make([]byte, 9100)
	for {
		n, _, err := c.ReadFrom(data)
		if err != nil {
			log.Printf("failed to read : %v", err)
			continue
		}
		exaddr := ExpirationAddr{}

		err = (&eh).Unmarshal(data[:n])
		if err != nil {
			continue
		}

		if eh.Type != 0x0806 {
			continue
		}

		err = (&ah).Unmarshal(data[eh.Length():n])
		if err != nil {
			continue
		}

		if ah.Op == arp.ArpOpReplay {
			exaddr.IP = ah.IPSrc
			exaddr.Addr = eh.Src
			exaddr.Time = time.Now()
			exaddr.Own = false

			exa <- &exaddr
		}

	}
}

func SendARP(arpman Arpman, sockets map[string]*raw.Conn) error {
	var srcIP net.IP

	ifi, err := net.InterfaceByName(arpman.IfName)
	if err != nil {
		return fmt.Errorf("failed to get interface %s", arpman.IfName)
	}

	srcMac := ifi.HardwareAddr

	addrs, err := ifi.Addrs()
	if err != nil || len(addrs) == 0 {
		return fmt.Errorf("failed to get IP Address in %s", ifi.Name)
	}

	for _, a := range addrs {
		// is4
		if strings.Contains(a.String(), ".") {
			srcIP, _, err = net.ParseCIDR(a.String())

			if err != nil {
				return fmt.Errorf("failed parseCIDR %s", a.String())
			}

			srcIP = srcIP.To4()
			break
		}
	}

	eth := ether.EtherHeader{
		Dst:  net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		Src:  srcMac,
		Type: 0x0806,
	}

	arp := arp.ArpHeader{
		HwType: 0x0001,
		PrType: 0x0800,
		HwLen:  0x06,
		IPLen:  0x04,
		Op:     arp.ArpOpRequest,
		HwSrc:  srcMac,
		IPSrc:  srcIP,
		HwDst:  net.HardwareAddr{0, 0, 0, 0, 0, 0},
		IPDst:  arpman.Address.To4(),
	}

	e, _ := eth.Marshal()
	a, _ := arp.Marshal()

	frame := make([]byte, eth.Length()+arp.Length())
	copy(frame[0:eth.Length()], e)
	copy(frame[eth.Length():eth.Length()+arp.Length()], a)

	addr := &raw.Addr{
		HardwareAddr: net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	}

	sockets[arpman.IfName].WriteTo(frame, addr)

	if err != nil {
		return fmt.Errorf("failed to write : %v", err)
	}

	return nil
}

func IsInterfaceOwnAddr(ifName string, target net.IP) bool {
	ifi, err := net.InterfaceByName(ifName)
	if err != nil {
		return false
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return false
	}

	for _, a := range addrs {
		ip, _, err := net.ParseCIDR(a.String())
		if err != nil {
			return false
		}

		if ip.Equal(target) {
			return true
		}
	}

	return false
}
