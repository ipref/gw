/* Copyright (c) 2018-2021 Waldemar Augustyn */

package main

import (
	"bufio"
	"github.com/mdlayher/raw"
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
	pb.tail = pb.data + V1_HDR_LEN + 4
	pkt := pb.pkt[pb.data:pb.tail]
	off := V1_HDR_LEN
	be.PutUint32(pkt[off:off+4], uint32(nexthop))
	be.PutUint16(pkt[V1_PKTLEN:V1_PKTLEN+2], uint16(len(pkt)/4))

	pb.peer = "gw"
	send_gw <- pb
}

func gw_sender(con *net.UDPConn) {

	arpcache = make(map[IP32]*ArpRec)

	var gw_network net.IPNet
	var gw_nexthop IP32

	if !cli.devmode {

		gw_network, gw_nexthop = get_gw_network()

		log.info("gw network: %v", gw_network)
		log.info("gw nexthop: %v", gw_nexthop)
	}

	// arp_marker := marker.now()

	for pb := range send_gw {

		var arprec *ArpRec

		switch pb.typ {

		case PKT_V1:

			pkt := pb.pkt[pb.data:pb.tail]

			if pkt[V1_CMD] == V1_SET_MARK {

				// update time mark

				off := V1_HDR_LEN
				oid := O32(be.Uint32(pkt[off+V1_OID : off+V1_OID+4]))
				if oid == arp_oid {
					// arp_marker = M32(be.Uint32(pkt[off+V1_MARK : off+V1_MARK+4]))
				} else {
					log.err("gw out:  arp timer update oid(%v) does not match arp_oid(%v), ignoring", oid, arp_oid)
				}
				retbuf <- pb
				continue

			} else if pkt[V1_CMD] == V1_INDUCE_ARP {

				// update arprec following query

				ip := IP32(be.Uint32(pb.pkt[pb.data+V1_HDR_LEN : pb.data+V1_HDR_LEN+4]))
				arprec = get_arprec(ip)
				arprec.fill_from_proc(ip)

			} else {
				log.err("gw out:  unknown v1 packet data/end(%v/%v), dropping", pb.data, len(pb.pkt))
				retbuf <- pb
				continue
			}

		case PKT_IPREF:

			if cli.debug["gw"] {
				log.debug("gw out:  %v", pb.pp_pkt())
			}

			if cli.trace {
				pb.pp_net("gw out:  ")
				pb.pp_tran("gw out:  ")
				pb.pp_raw("gw out:  ")
			}

			src := []byte{0, 0, 0, 0}
			be.PutUint32(src, uint32(pb.src))
			dst := []byte{0, 0, 0, 0}
			be.PutUint32(dst, uint32(pb.dst))

			if !gw_network.Contains(dst) {
				log.fatal("gw out:  dst(%v) not in network", pb.dst)
			}
			if pb.src != cli.gw_ip {
				log.fatal("gw out:  src(%v) is not gateway", pb.src)
			}

			daddr := net.UDPAddr{dst, int(pb.dport), ""}
			wlen, err := con.WriteToUDP(pb.pkt[pb.data:pb.tail], &daddr)
			if err != nil {
				log.fatal("gw out: write failed: %v", err)
			}
			if wlen != pb.tail - pb.data {
				log.fatal("gw out: write failed")
			}

			retbuf <- pb

		default:
			log.fatal("gw out: unknown packet type: %v", pb.typ)
		}
	}
}

func gw_receiver(con *net.UDPConn) {

	if cli.devmode {
		return
	}

	for {

		pb := <-getbuf
		pb.typ = PKT_IPREF
		pb.data = TUN_HDR_LEN + IPREF_HDR_MAX_LEN - IP_HDR_MIN_LEN

		rlen, addr, err := con.ReadFromUDP(pb.pkt[pb.data:])
		if cli.debug["gw"] {
			log.debug("gw in: src IP: %v  rcvlen(%v)", addr, rlen)
		}
		if err != nil {
			log.err("gw in: read failed: %v", err)
			goto drop
		}
		if rlen == 0 || rlen == len(pb.pkt) - pb.data {
			log.err("gw in: read failed")
			goto drop
		}
		pb.tail = pb.data + rlen
		pb.src = IP32(be.Uint32(addr.IP))
		pb.sport = uint16(addr.Port)
		pb.dst = cli.gw_ip
		pb.dport = IPREF_PORT

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

	var con *net.UDPConn

	if !cli.devmode {

		var err error

		gw_ip := []byte{0, 0, 0, 0}
		be.PutUint32(gw_ip, uint32(cli.gw_ip))
		con, err = net.ListenUDP("udp4", &net.UDPAddr{gw_ip, IPREF_PORT, ""})
		if err != nil {
			log.fatal("gw: cannot listen on UDP: %v", err)
		}

		log.info("gw: gateway %v %v mtu(%v) %v pkt buffers",
			cli.gw_ip, cli.ifc.Name, cli.ifc.MTU, cli.maxbuf)
	}

	go gw_sender(con)
	go gw_receiver(con)
}
