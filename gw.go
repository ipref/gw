/* Copyright (c) 2018-2020 Waldemar Augustyn */

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
where we examine /proc arp entries instead. This is augmented with inducing
ARP queries for destinations not listed in /proc plus a periodic check for
stale entries.

Since inducing arp queries may take seconds to complete, we queue packets
destined for the ip being queried to allow other packets go through. Packets
are released from the queue once queries complete.
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
)

const (
	ARP_REC_EXPIRE = 29 // [s] expiration time for arp records at TIMER_TICK granularity
	ARP_MAX_QUEUE  = 10 // max packets on queue awaiting arp
)

type ArpRec struct {
	hwtype  byte
	flags   byte
	macaddr raw.Addr
	pbq     []*PktBuf // packets waiting for mac address
	expire  M32       // proc arp expiration mark
}

func (arprec *ArpRec) fill_from_proc(ip IP32) {

	const fname = "/proc/net/arp"

	fd, err := os.Open(fname)
	if err != nil {
		log.fatal("gw: cannot open %v", fname)
	}
	defer fd.Close()

	arprec_changed := false
	arprec.expire = marker.now() + ARP_REC_EXPIRE
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
		if arprec.hwtype != byte(hwtype) {
			arprec_changed = true
		}
		arprec.hwtype = byte(hwtype)

		// flags

		flags, err := strconv.ParseUint(toks[ARP_FLAGS], 0, 8)
		if err != nil {
			log.fatal("gw: cannot parse flags from %v: %v", fname, err)
		}
		if arprec.flags != byte(flags) {
			arprec_changed = true
		}
		arprec.flags = byte(flags)

		// mac

		mac, err := net.ParseMAC(toks[ARP_MAC])
		if err != nil {
			log.fatal("gw: cannot parse mac address from %v: %v", fname, err)
		}
		if arprec.macaddr.HardwareAddr.String() != toks[ARP_MAC] {
			arprec_changed = true
		}
		arprec.macaddr.HardwareAddr = mac

		if arprec_changed {
			log.info("gw: arp entry update:  %-15v  0x%02x  0x%02x  %v  %v  expire(%v)",
				toks[ARP_IP], arprec.hwtype, arprec.flags, arprec.macaddr.HardwareAddr,
				toks[ARP_IFC], arprec.expire)
		}

		break
	}

	if err := scanner.Err(); err != nil {
		log.err("gw: error reading %v", fname)
	}
}

var arpcache map[IP32]*ArpRec
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
			continue
		}

		// network

		dst := proc2ip(toks[ROUTE_DST])
		mask := proc2ip(toks[ROUTE_MASK])

		be.PutUint32(gw_network.IP, uint32(dst))
		be.PutUint32(gw_network.Mask, uint32(mask))
	}

	if err := scanner.Err(); err != nil {
		log.err("gw: error reading %v", fname)
	}

	return gw_network, gw_nexthop
}

func get_arprec(ip IP32) *ArpRec {

	arprec, ok := arpcache[ip]
	if !ok {
		arprec = &ArpRec{0, 0, raw.Addr{[]byte{0, 0, 0, 0, 0, 0}}, make([]*PktBuf, 0, 5), 0}
		arprec.fill_from_proc(ip)
		arpcache[ip] = arprec
	}

	return arprec
}

func induce_arp(nexthop IP32) {

	cmd, out, ret := shell("ping -n4 -c1 -W 1 -I %v %v", cli.gw_ip, nexthop)
	if ret < 0 {
		log.fatal("gw induce arp: shell command failed: %v", cmd)
	}

	if cli.debug["gw"] {
		log.debug("gw induce arp: %v", strings.Split(out, "\n")[0])
	}

	pb := <-getbuf

	pb.write_v1_header(V1_INDUCE_ARP, 0)
	pb.tail = pb.iphdr + V1_HDR_LEN + 4
	pkt := pb.pkt[pb.iphdr:pb.tail]
	off := V1_HDR_LEN
	be.PutUint32(pkt[off:off+4], uint32(nexthop))
	be.PutUint16(pkt[V1_PKTLEN:V1_PKTLEN+2], uint16(len(pkt)/4))

	pb.peer = "gw"
	send_gw <- pb
}

func gw_sender(con net.PacketConn) {

	arpcache = make(map[IP32]*ArpRec)

	var gw_network net.IPNet
	var gw_nexthop IP32

	if !cli.mbroker {

		gw_network, gw_nexthop = get_gw_network()

		log.info("gw network: %v", gw_network)
		log.info("gw nexthop: %v", gw_nexthop)
	}

	arp_marker := marker.now()

	for pb := range send_gw {

		if len(pb.pkt)-int(pb.data) < MIN_PKT_LEN {

			log.err("gw out:  short packet data/end(%v/%v), dropping", pb.data, len(pb.pkt))
			retbuf <- pb
			continue
		}

		var arprec *ArpRec

		if pb.pkt[pb.data+V1_VER] == V1_SIG {

			pb.set_iphdr()
			pkt := pb.pkt[pb.iphdr:pb.tail]

			if pkt[V1_CMD] == V1_SET_MARK {

				// update time mark

				off := V1_HDR_LEN
				oid := O32(be.Uint32(pkt[off+V1_OID : off+V1_OID+4]))
				if oid == arp_oid {
					arp_marker = M32(be.Uint32(pkt[off+V1_MARK : off+V1_MARK+4]))
				} else {
					log.err("gw out:  arp timer update oid(%v) does not match arp_oid(%v), ignoring", oid, arp_oid)
				}
				retbuf <- pb
				continue

			} else if pkt[V1_CMD] == V1_INDUCE_ARP {

				// update arprec following query

				ip := IP32(be.Uint32(pb.pkt[pb.iphdr+V1_HDR_LEN : pb.iphdr+V1_HDR_LEN+4]))
				arprec = get_arprec(ip)
				arprec.fill_from_proc(ip)

			} else {
				log.err("gw out:  unknown v1 packet data/end(%v/%v), dropping", pb.data, len(pb.pkt))
				retbuf <- pb
				continue
			}

		} else {

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

			arprec = get_arprec(nexthop)

			if len(arprec.pbq) != 0 {
				if len(arprec.pbq) < ARP_MAX_QUEUE {
					if cli.debug["gw"] {
						log.debug("gw out:  already incuding arp for %v, queuing packet", nexthop)
					}
					arprec.pbq = append(arprec.pbq, pb)
				} else {
					if cli.debug["gw"] {
						log.debug("gw out:  queue waiting for %v arp full, dropping packet", nexthop)
					}
					retbuf <- pb
				}
				continue
			}

			arprec.pbq = append(arprec.pbq, pb)

			if arprec.flags&ARP_FLAG_COMPLETED == 0 {
				if cli.debug["gw"] {
					log.debug("gw out:  mac unavailable for %v, inducing arp", nexthop)
				}
				go induce_arp(nexthop)
				continue
			}

			if arprec.expire < arp_marker {
				arprec.expire = arp_marker + ARP_REC_EXPIRE
				if cli.debug["gw"] {
					log.debug("gw out:  mac for %v, expired, induce arp", nexthop)
				}
				go induce_arp(nexthop)
			}
		}

		if arprec.flags&ARP_FLAG_COMPLETED == 0 {

			for ix, pb := range arprec.pbq {
				if ix == 0 {
					icmpreq <- pb // no route to destination, first packet on the queue
				} else {
					retbuf <- pb // drop the rest
				}
			}
			arprec.pbq = arprec.pbq[0:0]

		} else {

			for _, pb := range arprec.pbq {

				if pb.data < ETHER_HDRLEN {
					log.fatal("gw out: not enough space for ether header data/tail(%v/%v)", pb.data, pb.tail)
				}

				pb.data -= ETHER_HDRLEN
				copy(pb.pkt[pb.data+ETHER_DST_MAC:pb.data+ETHER_DST_MAC+6], arprec.macaddr.HardwareAddr)
				copy(pb.pkt[pb.data+ETHER_SRC_MAC:pb.data+ETHER_SRC_MAC+6], cli.ifc.HardwareAddr)
				be.PutUint16(pb.pkt[pb.data+ETHER_TYPE:pb.data+ETHER_TYPE+2], ETHER_IPv4)

				if cli.debug["gw"] {
					log.debug("gw out:  %v", pb.pp_pkt())
				}

				if cli.trace {
					pb.pp_net("gw out:  ")
					pb.pp_tran("gw out:  ")
					pb.pp_raw("gw out:  ")
				}

				wlen, err := con.WriteTo(pb.pkt[pb.data:pb.tail], &arprec.macaddr)
				if err != nil {
					log.err("gw out:  raw pkt send to %v failed: %v)",
						arprec.macaddr.HardwareAddr, err)
				} else if wlen != pb.tail-pb.data {
					log.err("gw out:  raw pkt send to %v truncated wlen(%v) data/tail(%v/%v)",
						arprec.macaddr.HardwareAddr, wlen, pb.data, pb.tail)
				}
				retbuf <- pb
			}
			arprec.pbq = arprec.pbq[0:0]
		}
	}
}

func gw_receiver(con net.PacketConn) {

	if cli.mbroker {
		return
	}

	for {

		pb := <-getbuf
		pb.data = 2 // make sure IP header is on 32 bit boundary
		pkt := pb.pkt[pb.data:]
		pktlen := 0

		rlen, haddr, err := con.ReadFrom(pkt)
		if cli.debug["gw"] {
			log.debug("gw in: src mac: %v  rcvlen(%v)", haddr, rlen)
		}
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

		if cli.debug["gw"] {
			log.debug("gw in: %v", pb.pp_pkt())
		}

		if cli.trace {
			pb.pp_net("gw in:   ")
			pb.pp_tran("gw in:   ")
			pb.pp_raw("gw in:   ")
		}

		recv_gw <- pb
		continue

	drop:
		retbuf <- pb
	}

}

func start_gw() {

	var con *raw.Conn

	if !cli.mbroker {

		var err error

		con, err = raw.ListenPacket(&cli.ifc, ETHER_IPv4, &raw.Config{false, true, []bpf.RawInstruction{}, 0})
		if err != nil {
			log.fatal("gw: cannot get raw socket: %v", err)
		}

		/* filter IPREF packets: UDP with src or dst equal to IPREF_PORT

		Kernel will still be forwarding these packets. Use netfilter to silently
		drop them. For example, the following firewall-cmd rules could be used:

		firewall-cmd --add-rich-rule 'rule source-port port=1045 protocol=udp drop'
		firewall-cmd --add-rich-rule 'rule port port=1045 protocol=udp drop'
		firewall-cmd --runtime-to-permanent

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

		log.info("gw: gateway %v %v mtu(%v) %v pkt buffers",
			cli.gw_ip, cli.ifc.Name, cli.ifc.MTU, cli.maxbuf)
	}

	go gw_sender(con)
	go gw_receiver(con)
}
