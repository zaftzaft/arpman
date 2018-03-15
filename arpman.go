package main

import (
	"log"
	"net"
	"os"
	//"strconv"
	//"fmt"
	//"encoding/binary"
	"github.com/mdlayher/raw"
	"github.com/nsf/termbox-go"
	"strings"
	"time"
	"bufio"

	"./arp"
	"./ether"
)

type ExpirationAddr struct {
	IP   net.IP
	Time time.Time
	Addr net.HardwareAddr
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

func main() {
	os.Exit(Run())
}

func Run() int {
	var useInterfaces UseInterfaces
	list := make([]Arpman, 0)
	sockets := make(map[string]*raw.Conn)



	fp, err := os.Open(os.Args[1])
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
			list = append(list,
				Arpman{Address: ip},
			)
		}
	}


	for i, arpman := range list {
		ifi, err := InterfaceByAddr(arpman.Address.String())
		if err != nil {
			log.Fatalf("failed to find interface : %v", err)
		}
		if ifi == nil {
			log.Fatalf("failed to find interface")
		}

		if !useInterfaces.Contains(ifi) {
			useInterfaces = append(useInterfaces, ifi)

			sockets[ifi.Name], err = raw.ListenPacket(ifi, 0x0806, nil)
			if err != nil {
				log.Fatalf("failed to listen : %v", err)
			}
		}

		list[i].IfName = ifi.Name
	}


	exa := make(chan *ExpirationAddr, 10)
	for _, uifi := range useInterfaces {
		go sniffer(sockets[uifi.Name], exa)
	}

	err = termbox.Init()
	if err != nil {
		panic(err)
	}
	defer termbox.Close()

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


		for y, arpman := range list {
			drawLine(0, y+1, strings.Repeat(" ", w)) // reset

			drawLine(2, y+1, arpman.Address.String())
			//drawLine(19, y+1, strconv.Itoa(len(arpman.Macs)))

			macs := len(arpman.Macs)
			if macs > 0 {
				for i := 0;i < macs;i++ {
					drawLine((i*19) + 23, y+1, arpman.Macs[i].Addr.String())
				}

				// DUP
				if macs > 1 {
					drawLine(19, y+1, "DUP")
				}


			}
		}

		// draw arrow >
		for y, _ := range list {
			termbox.SetCell(0, y+1, ' ', termbox.ColorDefault, termbox.ColorDefault)
		}
		termbox.SetCell(0, index+1, '>', termbox.ColorDefault, termbox.ColorDefault)
	}


	nxch := make(chan int)
	sr := func(arpman *Arpman) {
		SendARP(*arpman, sockets)

		arpman.Macs = make([]ExpirationAddr, 0)

	wait:
		for {
			select {
			case exaddr := <-exa:
				if exaddr.IP.Equal(arpman.Address) {
					//for i, ex := range arpman.Macs {
					//	if ex.Addr.String() == exaddr.Addr.String() {
					//		// delete same addr
					//		arpman.Macs = append(arpman.Macs[:i], arpman.Macs[i+1:]...)
					//	}
					//}
					arpman.Macs = append(arpman.Macs, *exaddr)
				}

			case <-time.After(1 * time.Second):
				// delete timeout macs
				//for i, ex := range arpman.Macs {
				//	if time.Now().Sub(ex.Time) > 3 * time.Second {
				//		// delete timeout
				//		arpman.Macs = append(arpman.Macs[:i], arpman.Macs[i+1:]...)
				//	}
				//}
				break wait
			}

		}

		nxch <- 1
	}

	// ignition
	go func() {
		nxch <- 1
	}()

loop:
	for {
		select {

		case <-nxch:
			go sr(&list[index])
			render()
			termbox.Flush()
			index++

			if index >= len(list) {
				index = 0
			}

		case ev := <-events:
			switch ev.Type {
			case termbox.EventKey:
				if ev.Key == termbox.KeyEsc {
					break loop
				}
			}

		}
	}

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
		if eh.Type != 0x0806 {
			continue
		}

		err = (&ah).Unmarshal(data[eh.Length():n])

		if ah.Op == arp.ArpOpReplay {
			exaddr.IP = ah.IPSrc
			exaddr.Addr = eh.Src
			exaddr.Time = time.Now()

			exa <- &exaddr
		}

	}
}

func SendARP(arpman Arpman, sockets map[string]*raw.Conn) error {
	var srcIP net.IP

	ifi, err := net.InterfaceByName(arpman.IfName)
	if err != nil {
		log.Fatalf("failed to get interface %s", arpman.IfName)
	}

	srcMac := ifi.HardwareAddr

	addrs, err := ifi.Addrs()
	if err != nil || len(addrs) == 0 {
		log.Fatalf("failed to get IP Address in %s", ifi.Name)
	}

	for _, a := range addrs {
		// is4
		if strings.Contains(a.String(), ".") {
			srcIP, _, err = net.ParseCIDR(a.String())
			srcIP = srcIP.To4()
			break
		}
	}
	if err != nil {
		log.Fatal(err)
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
		log.Fatalf("failed to write : %v", err)
	}

	return nil
}

