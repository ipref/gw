/* Copyright (c) 2018 Waldemar Augustyn */

package main

import (
	"bufio"
	"github.com/mdlayher/raw"
	"golang.org/x/net/bpf"
	"net"
	"os"
	"strconv"
	"strings"
)

const (
	ETHER_HDRLEN = 6 + 6 + 2
	// ETHER types
	ETHER_IPv4 = 0x0800
	ETHER_IPv6 = 0x86dd
	// ETHER offsets
	ETHER_DST_MAC = 0
	ETHER_SRC_MAC = 6
	ETHER_TYPE    = 12
	// L2 hdw types
	L2_ETHERNET = 0x01
	// L2 flags
	L2_COMPLETED = 0x02
)

const (
	// columns in /proc/net/route
	ROUTE_IFC   = 0
	ROUTE_DST   = 1
	ROUTE_GW    = 2
	ROUTE_FLAGS = 3
	ROUTE_MASK  = 7
	// flags
	ROUTE_FLAG_U = 0x01 // up
	ROUTE_FLAG_G = 0x02 // gateway
)

type L2Addr struct {
	hwtype byte
	flags  byte
	mac    string // mac address as a string f4:4d:30:61:54:da
}

func (l2 *L2Addr) Network() string {
	return "raw"
}

func (l2 *L2Addr) String() string {
	return l2.mac
}

var recv_gw chan *PktBuf
var send_gw chan *PktBuf
var slow_gw chan *PktBuf

// deduce network on gw ifc and default next hop
func get_gw_network() (net.IPNet, IP32) {

	const fname = "/proc/net/route"

	fd, err := os.Open(fname)
	if err != nil {
		log.fatal("gw: cannot open %v", fname)
	}
	defer fd.Close()

	gw_network := net.IPNet{IP: net.IP{0, 0, 0, 0}, Mask: net.IPMask{0, 0, 0, 0}}
	gw_nexthop := IP32(0)

	scanner := bufio.NewScanner(fd)
	for scanner.Scan() {

		toks := strings.Fields(scanner.Text())
		if len(toks) != 11 {
			log.fatal("gw: expecing 11 columns in %v, got %v instead", fname, len(toks))
		}

		// ifc

		if toks[ROUTE_IFC] != cli.ifc.Name {
			continue
		}

		// flags

		flags, err := strconv.ParseUint(toks[ROUTE_FLAGS], 16, 16)
		if err != nil {
			log.fatal("gw: cannot parse flags from %v: %v", fname, err)
		}

		if flags&ROUTE_FLAG_U == 0 {
			continue // route is not up
		}

		// default next hop

		if flags&ROUTE_FLAG_G != 0 {
			gw_nexthop = proc2ip(toks[ROUTE_GW])
			log.debug("gw: detected default route next hop: %v", gw_nexthop)
			continue
		}

		// network

		dst := proc2ip(toks[ROUTE_DST])
		mask := proc2ip(toks[ROUTE_MASK])

		be.PutUint32(gw_network.IP, uint32(dst))
		be.PutUint32(gw_network.Mask, uint32(mask))
		log.debug("gw: detected gw ifc network: %v", gw_network)
	}

	if err := scanner.Err(); err != nil {
		log.err("gw: error reading %v", fname)
	}

	return gw_network, gw_nexthop
}

func gw_sender_slow() {

	// find mac address of nexthop then put packet back onto send_gw queue

	for pb := range slow_gw {

		retbuf <- pb
	}
}

func gw_sender(con net.PacketConn) {

	arpcache := make(map[IP32]L2Addr)

	gw_network, gw_nexthop := get_gw_network()

	log.info("gw network: %v", gw_network)
	log.info("gw nexthop: %v", gw_nexthop)

	for pb := range send_gw {

		if len(pb.pkt)-int(pb.data) < MIN_PKT_LEN {

			log.err("gw out:  short packet data/end(%v/%v), dropping", pb.data, len(pb.pkt))
			retbuf <- pb
			continue
		}

		// send raw packet

		dst := net.IP(pb.pkt[pb.iphdr+IP_DST : pb.iphdr+IP_DST+4])

		if gw_network.Contains(dst) {
			pb.nexthop = IP32(be.Uint32(dst))
		} else if gw_nexthop == 0 {
			icmpreq <- pb
			continue // no route to destination
		} else {
			pb.nexthop = gw_nexthop
		}

		l2addr, ok := arpcache[pb.nexthop]

		if !ok {
			slow_gw <- pb
			continue
		}

		if l2addr.flags&L2_COMPLETED == 0 {
			icmpreq <- pb // no route to destination
			continue
		}

		if cli.debug["gw"] || cli.debug["all"] {
			log.debug("gw out:  %v", pb.pp_pkt())
		}

		if log.level <= TRACE {
			pb.pp_net("gw out:  ")
			pb.pp_tran("gw out:  ")
			pb.pp_raw("gw out:  ")
		}

		con.WriteTo(pb.pkt[pb.iphdr:pb.tail], &l2addr)

		// return buffer to the pool

		retbuf <- pb
	}
}

func gw_receiver(con net.PacketConn) {

	for {

		pb := <-getbuf
		pb.data = 2 // make sure IP header is on 32 bit boundary
		pkt := pb.pkt[pb.data:]
		pktlen := 0

		rlen, haddr, err := con.ReadFrom(pkt)
		log.debug("gw in: src mac: %v  rcvlen(%v)", haddr, rlen)
		if rlen == 0 {
			log.err("gw in: read failed: %v", err)
			goto drop
		}

		if rlen < ETHER_HDRLEN+20 {
			log.err("gw in: packet too short: %v bytes, dropping", rlen)
			goto drop
		}

		if be.Uint16(pkt[ETHER_TYPE:ETHER_TYPE+2]) != ETHER_IPv4 ||
			pkt[ETHER_HDRLEN+IP_VER]&0xf0 != 0x40 {

			log.err("gw in: not an IPv4 packet, dropping")
			goto drop
		}

		pktlen = int(be.Uint16(pkt[ETHER_HDRLEN+IP_LEN : ETHER_HDRLEN+IP_LEN+2]))
		if len(pkt)-ETHER_HDRLEN < pktlen {
			log.err("gw in: packet truncated, dropping")
			goto drop
		}

		pb.data += ETHER_HDRLEN
		pb.tail = pb.data + pktlen
		pb.set_iphdr()

		if cli.debug["gw"] || cli.debug["all"] {
			log.debug("gw_in: %v", pb.pp_pkt())
		}

		if log.level <= TRACE {
			pb.pp_net("gw_in:   ")
			pb.pp_tran("gw_in:   ")
			pb.pp_raw("gw_in:   ")
		}

		recv_gw <- pb
		continue

	drop:
		retbuf <- pb
	}

}

func start_gw() {

	con, err := raw.ListenPacket(&cli.ifc, ETHER_IPv4, &raw.Config{false, true, false})
	if err != nil {
		log.fatal("gw: cannot get raw socket: %v", err)
	}

	/* filter IPREF packets: UDP with src or dst equal to IPREF_PORT

	Kernel will still be forwarding these packets. Use netfilter to silently
	drop them. For example, the following firewall-cmd rules could be used:

	firewall-cmd --add-rich-rule 'rule source-port port=1045 protocol=udp drop'
	firewall-cmd --add-rich-rule 'rule port port=1045 protocol=udp drop'

	*/

	filter, err := bpf.Assemble([]bpf.Instruction{
		bpf.LoadAbsolute{Off: ETHER_TYPE, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: ETHER_IPv4, SkipTrue: 1},
		bpf.RetConstant{Val: 0}, // not IPv4 packet
		bpf.LoadAbsolute{Off: ETHER_HDRLEN + IP_DST, Size: 4},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(cli.gw_ip), SkipTrue: 1},
		bpf.RetConstant{Val: 0}, // not our gateway IP address
		bpf.LoadAbsolute{Off: ETHER_HDRLEN + IP_PROTO, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: UDP, SkipTrue: 1},
		bpf.RetConstant{Val: 0}, // not UDP
		bpf.LoadMemShift{Off: ETHER_HDRLEN + IP_VER},
		bpf.LoadIndirect{Off: ETHER_HDRLEN + UDP_SPORT, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: IPREF_PORT, SkipTrue: 1},
		bpf.RetConstant{Val: uint32(cli.pktbuflen)}, // src port match, copy packet
		bpf.LoadIndirect{Off: ETHER_HDRLEN + UDP_DPORT, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: IPREF_PORT, SkipTrue: 1},
		bpf.RetConstant{Val: uint32(cli.pktbuflen)}, // dst port match, copy packet
		bpf.RetConstant{Val: 0},                     // no match, ignore packet
	})

	if err != nil {
		log.fatal("gw: cannot assemble bpf filter: %v", err)
	}

	err = con.SetBPF(filter)

	if err != nil {
		log.fatal("gw: cannot set bpf filter: %v", err)
	}

	log.info("gw: gateway %v %v mtu(%v)", cli.gw_ip, cli.ifc.Name, cli.ifc.MTU)

	go gw_sender_slow()
	go gw_sender(con)
	go gw_receiver(con)
}
