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

/* ARP cache

Raw packet send requires to supply destinatin mac address. Mac addresses are
normally obtained through ARP. In this implementation, we take a short cut
where we examine /proc arp entries instead. This is augmented with running
arping utility to induce ARP query for destinations not listed in /proc.

Since arping takes seconds to produce a result, we queue packets destined for
the ip address being queried to allow other packets go through. Packets are
released from the queue once arping completes.
*/

const (
	ETHER_HDRLEN = 6 + 6 + 2
	// ETHER types
	ETHER_IPv4 = 0x0800
	ETHER_IPv6 = 0x86dd
	// ETHER offsets
	ETHER_DST_MAC = 0
	ETHER_SRC_MAC = 6
	ETHER_TYPE    = 12
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

const (
	// columns in /proc/net/arp
	ARP_IP     = 0
	ARP_HWTYPE = 1
	ARP_FLAGS  = 2
	ARP_MAC    = 3
	ARP_IFC    = 5
	// hwtype
	ARP_HW_ETHER = 0x1
	// flags
	ARP_FLAG_COMPLETED = 0x2
	ARP_FLAG_PERMANENT = 0x4
	ARP_FLAG_DONTKNOW  = 0x40 // nothing in proc (re-using DONTPUB)
)

type ArpRec struct {
	hwtype byte
	flags  byte
	mac    string    // mac address as a string f4:4d:30:61:54:da
	pbq    []*PktBuf // packets waiting for mac address
}

func (arprec *ArpRec) fill_from_proc(ip IP32) {

	const fname = "/proc/net/arp"

	fd, err := os.Open(fname)
	if err != nil {
		log.fatal("gw: cannot open %v", fname)
	}
	defer fd.Close()

	arprec.hwtype = 0
	arprec.flags = ARP_FLAG_DONTKNOW
	ipstr := ip.String()

	scanner := bufio.NewScanner(fd)
	scanner.Scan() // skip header line
	for scanner.Scan() {

		line := scanner.Text()
		toks := strings.Fields(line)
		if len(toks) != 6 {
			log.fatal("gw: expecting 6 columns in %v, got %v instead", fname, len(toks))
		}

		// match ip address and ifc

		if toks[ARP_IP] != ipstr || toks[ARP_IFC] != cli.ifc.Name {
			continue
		}

		// hw type

		hwtype, err := strconv.ParseUint(toks[ARP_HWTYPE], 0, 8)
		if err != nil {
			log.fatal("gw: cannot parse hw type from %v: %v", fname, err)
		}
		arprec.hwtype = byte(hwtype)

		// flags

		flags, err := strconv.ParseUint(toks[ARP_FLAGS], 0, 8)
		if err != nil {
			log.fatal("gw: cannot parse flags from %v: %v", fname, err)
		}
		arprec.flags = byte(flags)

		// mac

		arprec.mac = toks[ARP_MAC]

		log.info("gw: detected arp entry %-15v  %v  %v  %v  %v",
			toks[ARP_IP], toks[ARP_HWTYPE], toks[ARP_FLAGS], toks[ARP_MAC], toks[ARP_IFC])

		break
	}

	if err := scanner.Err(); err != nil {
		log.err("gw: error reading %v", fname)
	}

}

func (arprec *ArpRec) Network() string {
	return cli.ifc.Name
}

func (arprec *ArpRec) String() string {
	return arprec.mac
}

var arpcache map[IP32]*ArpRec
var arping chan IP32
var recv_gw chan *PktBuf
var send_gw chan *PktBuf

// deduce what network is configured on gw ifc and what default next hop is
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

func get_arprec(ip IP32) *ArpRec {

	arprec, ok := arpcache[ip]
	if !ok {
		arprec = &ArpRec{0, 0, "00:00:00:00:00:00", make([]*PktBuf, 0, 5)}
		arprec.fill_from_proc(ip)
		arpcache[ip] = arprec
	}

	return arprec
}

func gw_arping() {

	for ip := range arping {
		log.debug("gw: arping %v", ip)
	}
}

func gw_sender(con net.PacketConn) {

	arpcache = make(map[IP32]*ArpRec)

	gw_network, gw_nexthop := get_gw_network()

	log.info("gw network: %v", gw_network)
	log.info("gw nexthop: %v", gw_nexthop)

	for pb := range send_gw {

		if len(pb.pkt)-int(pb.data) < MIN_PKT_LEN {

			log.err("gw out:  short packet data/end(%v/%v), dropping", pb.data, len(pb.pkt))
			retbuf <- pb
			continue
		}

		// find next hop

		nexthop := IP32(0)
		dst := net.IP(pb.pkt[pb.iphdr+IP_DST : pb.iphdr+IP_DST+4])

		if gw_network.Contains(dst) {
			nexthop = IP32(be.Uint32(dst))
		} else if gw_nexthop == 0 {
			icmpreq <- pb
			continue // no route to destination
		} else {
			nexthop = gw_nexthop
		}

		// find next hop's mac address

		arprec := get_arprec(nexthop)

		if len(arprec.pbq) != 0 {
			// already trying to get mac address, add pkt to the queue
			arprec.pbq = append(arprec.pbq, pb)
			continue
		}

		if arprec.flags&ARP_FLAG_DONTKNOW != 0 {
			// nothing in proc, run arping
			arprec.pbq = append(arprec.pbq, pb)
			arping <- nexthop
			continue
		}

		if arprec.flags&ARP_FLAG_COMPLETED == 0 {
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

		con.WriteTo(pb.pkt[pb.iphdr:pb.tail], arprec)

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

	go gw_sender(con)
	go gw_receiver(con)
	go gw_arping()
}
