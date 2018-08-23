/* Copyright (c) 2018 Waldemar Augustyn */

package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

/* Packet flow

               ╭──────────╮     ┏━━━━━━━━━━━━┓     ╭──────────╮
       ╭────▷──┤ recv_tun ├──▷──┨ fwd_to_gw  ┠──▷──┤ send_gw  ├──▷────╮
       │       ╰──────────╯     ┗━━━━━━━━━━━━┛     ╰──────────╯       │
    ┏━━┷━━┓                                                        ┏━━┷━━┓
 ─▷─┨ tun ┃                                                        ┃ gw  ┠─▷─
 ─◁─┨ ifc ┃                                                        ┃ ifc ┠─◁─
    ┗━━┯━━┛                                                        ┗━━┯━━┛
       │       ╭──────────╮     ┏━━━━━━━━━━━━┓     ╭──────────╮       │
       ╰────◁──┤ send_tun ├──◁──┨ fwd_to_tun ┠──◁──┤ recv_gw  ├──◁────╯
               ╰──────────╯     ┗━━━━━━━━━━━━┛     ╰──────────╯
*/

var be = binary.BigEndian

/* PktBuf helper functions */

func ip_proto(proto byte) string {

	switch proto {
	case TCP:
		return "tcp"
	case UDP:
		return "udp"
	case ICMP:
		return "icmp"
	}
	return fmt.Sprintf("%v", proto)
}

func (pb *PktBuf) pp_pkt() (ss string) {

	// IP(udp)  192.168.84.97  192.168.84.98  len(60)  data/tail(0/60)
	// IPREF(udp)  192.168.84.97 + 8af2819566  192.168.84.98 + 31fba013c  len(60) data/tail(48/158)
	// V1 SET_MARK(1)  mapper(1)  mark(12342)  data/tail(12/68)
	// PKT 0532ab04 data/tail(18/20)

	pkt := pb.pkt[pb.data:] // note: for debug it's from data to end (not from data to tail)

	// data too far into the buffer

	if len(pkt) < MIN_PKT_LEN {

		ss = fmt.Sprintf("PKT  short  data/tail(%v/%v)", pb.data, pb.tail)
		return
	}

	reflen := pb.reflen(pb.data)

	// IPREF packet

	if reflen != 0 {

		var sref Ref
		var dref Ref

		udp := int(pkt[IP_VER]&0xf) * 4
		encap := udp + 8
		opt := encap + 4

		if reflen == IPREF_OPT128_LEN {
			sref.h = be.Uint64(pkt[opt+OPT_SREF128 : opt+OPT_SREF128+8])
			sref.l = be.Uint64(pkt[opt+OPT_SREF128+8 : opt+OPT_SREF128+8+8])
			dref.h = be.Uint64(pkt[opt+OPT_DREF128 : opt+OPT_DREF128+8])
			dref.l = be.Uint64(pkt[opt+OPT_DREF128+8 : opt+OPT_DREF128+8+8])
		} else if reflen == IPREF_OPT64_LEN {
			sref.h = 0
			sref.l = be.Uint64(pkt[opt+OPT_SREF64 : opt+OPT_SREF64+8])
			dref.h = 0
			dref.l = be.Uint64(pkt[opt+OPT_DREF64 : opt+OPT_DREF64+8])
		}

		ss = fmt.Sprintf("IPREF(%v)  %v + %v  %v + %v  len(%v)  data/tail(%v/%v)",
			ip_proto(pkt[encap+ENCAP_PROTO]),
			net.IP(pkt[IP_SRC:IP_SRC+4]),
			&sref,
			net.IP(pkt[IP_DST:IP_DST+4]),
			&dref,
			be.Uint16(pkt[IP_LEN:IP_LEN+2]),
			pb.data, pb.tail)

		return
	}

	// IP packet

	if pkt[IP_VER]&0xf0 == 0x40 && len(pkt) >= 20 {

		ss = fmt.Sprintf("IP(%v)  %v  %v  len(%v)  data/tail(%v/%v)",
			ip_proto(pkt[IP_PROTO]),
			net.IP(pkt[IP_SRC:IP_SRC+4]),
			net.IP(pkt[IP_DST:IP_DST+4]),
			be.Uint16(pkt[IP_LEN:IP_LEN+2]),
			pb.data, pb.tail)

		return
	}

	// V1 packet

	if pkt[V1_VER] == V1_SIG && len(pkt) >= V1_HDR_LEN {

		ss = "V1"

		cmd := pkt[V1_CMD]
		switch cmd {
		case V1_SET_AREC:
			ss += fmt.Sprintf(" SET_AREC(%v)", cmd)
		case V1_SET_MARK:
			ss += fmt.Sprintf(" SET_MARK(%v)", cmd)
		case V1_SET_SOFT:
			ss += fmt.Sprintf(" SET_SOFT(%v)", cmd)
		case V1_PURGE_EXPIRED:
			ss += fmt.Sprintf(" PURGE_EXPIRED(%v)", cmd)
		default:
			ss += fmt.Sprintf(" cmd(%v)", cmd)
		}

		oid := be.Uint32(pkt[V1_OID : V1_OID+4])
		mark := be.Uint32(pkt[V1_MARK : V1_MARK+4])
		ss += fmt.Sprintf("  %v(%v)  mark(%v)  data/tail(%v/%v)",
			owners.name(oid), oid, mark, pb.data, pb.tail)

		return
	}

	// unknown or invalid packet

	ss = fmt.Sprintf("PKT  %08x  data/tail(%v/%v)", be.Uint32(pkt[0:4]), pb.data, pb.tail)

	return
}

func (pb *PktBuf) pp_raw(pfx string) {

	// RAW  45 00 00 74 2e 52 40 00 40 11 d0 b6 0a fb 1b 6f c0 a8 54 5e 04 15 04 15 00 ..

	const max = 128
	var sb strings.Builder

	pkt := pb.pkt[pb.data:pb.tail]
	sb.WriteString(pfx)
	sb.WriteString("RAW ")
	for ii := 0; ii < len(pkt); ii++ {
		if ii < max {
			sb.WriteString(" ")
			sb.WriteString(hex.EncodeToString(pkt[ii : ii+1]))
		} else {
			sb.WriteString("  ..")
			break
		}
	}
	log.trace(sb.String())
}

func (pb *PktBuf) pp_net(pfx string) {

	// IP(udp) 4500  192.168.84.93  10.254.22.202  len(64) id(1) ttl(64) csum:0000
	// IPREF(udp) 4500  192.168.84.93 + 8af2819566  10.254.22.202 + 31fba013c  len(64) id(1) ttl(64) csum:0000

	pkt := pb.pkt[pb.iphdr:pb.tail]

	// Non-IP

	if (len(pkt) < 20) || (pkt[IP_VER]&0xf0 != 0x40) || (len(pkt) < int(pkt[IP_VER]&0xf)*4) {
		log.trace(pfx + pb.pp_pkt())
		return
	}

	reflen := pb.reflen(pb.iphdr)

	// IPREF

	if reflen == IPREF_OPT128_LEN || reflen == IPREF_OPT64_LEN {

		var sref Ref
		var dref Ref

		udp := int(pkt[IP_VER]&0xf) * 4
		encap := udp + 8
		opt := encap + 4

		if reflen == IPREF_OPT128_LEN {
			sref.h = be.Uint64(pkt[opt+OPT_SREF128 : opt+OPT_SREF128+8])
			sref.l = be.Uint64(pkt[opt+OPT_SREF128+8 : opt+OPT_SREF128+8+8])
			dref.h = be.Uint64(pkt[opt+OPT_DREF128 : opt+OPT_DREF128+8])
			dref.l = be.Uint64(pkt[opt+OPT_DREF128+8 : opt+OPT_DREF128+8+8])
		} else if reflen == IPREF_OPT64_LEN {
			sref.h = 0
			sref.l = be.Uint64(pkt[opt+OPT_SREF64 : opt+OPT_SREF64+8])
			dref.h = 0
			dref.l = be.Uint64(pkt[opt+OPT_DREF64 : opt+OPT_DREF64+8])
		}

		log.trace("%vIPREF(%v)  %v + %v  %v + %v  len(%v) id(%v) ttl(%v) csum: %04x",
			pfx,
			ip_proto(pkt[encap+ENCAP_PROTO]),
			IP32(be.Uint32(pkt[IP_SRC:IP_SRC+4])),
			&sref,
			IP32(be.Uint32(pkt[IP_DST:IP_DST+4])),
			&dref,
			be.Uint16(pkt[IP_LEN:IP_LEN+2]),
			be.Uint16(pkt[IP_ID:IP_ID+2]),
			pkt[IP_TTL],
			be.Uint16(pkt[IP_CSUM:IP_CSUM+2]))

		return
	}

	// IP

	log.trace("%vIP(%v)  %v  %v  len(%v) id(%v) ttl(%v) csum: %04x",
		pfx,
		ip_proto(pkt[IP_PROTO]),
		IP32(be.Uint32(pkt[IP_SRC:IP_SRC+4])),
		IP32(be.Uint32(pkt[IP_DST:IP_DST+4])),
		be.Uint16(pkt[IP_LEN:IP_LEN+2]),
		be.Uint16(pkt[IP_ID:IP_ID+2]),
		pkt[IP_TTL],
		be.Uint16(pkt[IP_CSUM:IP_CSUM+2]))
}

func (pb *PktBuf) pp_tran(pfx string) {

	pkt := pb.pkt[pb.iphdr:pb.tail]

	// Non-IP

	if (len(pkt) < 20) || (pkt[IP_VER]&0xf0 != 0x40) || (len(pkt) < int(pkt[IP_VER]&0xf)*4) {
		return
	}

	l4 := int(pkt[IP_VER]&0xf) * 4
	reflen := pb.reflen(pb.iphdr)
	if reflen != 0 {
		l4 += 8 + 4 + reflen
	}

	switch pkt[IP_PROTO] {
	case TCP:
	case UDP:

		// UDP  1045  1045  len(96) csum 0

		if len(pkt) < l4+8 {
			return
		}
		log.trace("%vUDP  %v  %v  len(%v) csum: %04x",
			pfx,
			be.Uint16(pkt[l4+UDP_SPORT:l4+UDP_SPORT+2]),
			be.Uint16(pkt[l4+UDP_DPORT:l4+UDP_DPORT+2]),
			be.Uint16(pkt[l4+UDP_LEN:l4+UDP_LEN+2]),
			be.Uint16(pkt[l4+UDP_CSUM:l4+UDP_CSUM+2]))

	case ICMP:
	}
}

func (pb *PktBuf) fill_tunhdr() {

	tunhdr := pb.tail
	pb.tail += TUN_HDR_LEN

	if len(pb.pkt[tunhdr:]) < pb.len() {
		log.fatal("fill tunhdr: not enough space for TUN header")
	}

	pkt := pb.pkt[tunhdr:]

	be.PutUint16(pkt[TUN_FLAGS:TUN_FLAGS+2], TUN_IFF_TUN)
	be.PutUint16(pkt[TUN_PROTO:TUN_PROTO+2], TUN_IPv4)
}

func (pb *PktBuf) fill_iphdr() {

	pb.iphdr = pb.tail
	pb.tail += 20

	if len(pb.pkt[pb.iphdr:]) < pb.len() {
		log.fatal("fill iphdr: not enough space for IP header")
	}

	pkt := pb.pkt[pb.iphdr:]

	pkt[IP_VER] = 0x45
	pkt[IP_DSCP] = 0
	be.PutUint16(pkt[IP_LEN:IP_LEN+2], uint16(pb.tail-pb.iphdr))
	be.PutUint16(pkt[IP_ID:IP_ID+2], 0x0001)
	be.PutUint16(pkt[IP_FRAG:IP_FRAG+2], 0x4000) // DF + fragment offset
	pkt[IP_TTL] = 64
	pkt[IP_PROTO] = 0
	be.PutUint16(pkt[IP_CSUM:IP_CSUM+2], 0x0000)          // hdr csum
	copy(pkt[IP_SRC:IP_SRC+4], []byte{192, 168, 73, 127}) // src taro-7
	copy(pkt[IP_DST:IP_DST+4], []byte{10, 254, 22, 202})  // dst tikopia-8
}

func (pb *PktBuf) fill_udphdr() {

	pb.l4hdr = pb.tail
	pb.tail += 8

	if len(pb.pkt[pb.iphdr:]) < pb.len() {
		log.fatal("fill udphdr: not enough space for UDP header")
	}

	pkt := pb.pkt[pb.l4hdr:]

	pb.pkt[pb.iphdr+IP_PROTO] = UDP

	be.PutUint16(pkt[UDP_SPORT:UDP_SPORT+2], 44123)
	be.PutUint16(pkt[UDP_DPORT:UDP_DPORT+2], ECHO)
	be.PutUint16(pkt[UDP_LEN:UDP_LEN+2], uint16(pb.tail-pb.l4hdr))
	be.PutUint16(pkt[UDP_CSUM:UDP_CSUM+2], 0x0000) // udp csum

	be.PutUint16(pb.pkt[pb.iphdr+IP_LEN:pb.iphdr+IP_LEN+2], uint16(pb.tail-pb.iphdr)) // pktlen
}

func (pb *PktBuf) fill_payload() {

	bb := byte(7)
	beg := pb.tail
	pb.tail += 64

	if len(pb.pkt[pb.iphdr:]) < pb.len() {
		log.fatal("fill payload: not enough space for payload")
	}

	for ii := beg; ii < pb.tail; ii++ {
		pb.pkt[ii] = bb
		bb++
	}

	switch pb.pkt[pb.iphdr+IP_PROTO] {
	case UDP:
		be.PutUint16(pb.pkt[pb.l4hdr+UDP_LEN:pb.l4hdr+UDP_LEN+2], uint16(pb.tail-pb.l4hdr)) // udp datalen
	}
	be.PutUint16(pb.pkt[pb.iphdr+IP_LEN:pb.iphdr+IP_LEN+2], uint16(pb.tail-pb.iphdr)) // pktlen
}

func (pb *PktBuf) fill(proto int) {

	if len(pb.pkt) < int(cli.gw_mtu) {
		log.fatal("packet buffer too short: %v, needs %v", len(pb.pkt), cli.gw_mtu)
	}

	pb.data = OPTLEN - TUN_HDR_LEN
	pb.tail = pb.data
	pb.fill_tunhdr()
	pb.fill_iphdr()

	switch proto {
	case TCP:
	case UDP:
		pb.fill_udphdr()
		pb.fill_payload()
	case ICMP:
	}
}

func insert_ipref_option(pb *PktBuf) int {

	pkt := pb.pkt

	if (be.Uint16(pkt[pb.iphdr+IP_FRAG:pb.iphdr+IP_FRAG+2]) & 0x1fff) != 0 {
		log.debug("inserting opt: pkt is a fragment, dropping")
		return DROP
	}

	src := IP32(be.Uint32(pkt[pb.iphdr+IP_SRC : pb.iphdr+IP_SRC+4]))
	dst := IP32(be.Uint32(pkt[pb.iphdr+IP_DST : pb.iphdr+IP_DST+4]))

	iprefdst := map_gw.get_dst_ipref(dst)
	if iprefdst.ip == 0 {
		pb.icmp.thype = ICMP_DEST_UNREACH
		pb.icmp.code = ICMP_NET_UNREACH
		pb.icmp.mtu = 0
		icmpreq <- pb
		return STOLEN
	}

	iprefsrc := map_gw.get_src_ipref(src)
	if iprefsrc.ip == 0 {
		log.err("inserting opt: unknown src address: %v %v , dropping", src, dst)
		return DROP // couldn't get src ipref for some reason
	}

	// get soft state

	soft, ok := map_gw.soft[iprefdst.ip]
	if !ok {
		soft.init(iprefdst.ip) // missing soft state, use defaults
	}

	// insert option

	if pb.iphdr < OPTLEN {
		log.err("inserting opt: no space for ipref option, dropping")
		return DROP
	}

	iphdrlen := pb.iphdr_len()
	optlen := byte(0)

	if iprefsrc.ref.h == 0 && iprefdst.ref.h == 0 {
		pb.data = pb.iphdr - OPTLEN + 16 // both refs 64 bit
		optlen = IPREF_OPT64_LEN
	} else {
		pb.data = pb.iphdr - OPTLEN // at least one 128 bit ref
		optlen = IPREF_OPT128_LEN
	}

	copy(pkt[pb.data:pb.data+iphdrlen], pkt[pb.iphdr:pb.iphdr+iphdrlen])
	pb.set_iphdr()

	udp := pb.iphdr + iphdrlen
	be.PutUint16(pkt[udp+UDP_SPORT:udp+UDP_SPORT+2], soft.port)
	be.PutUint16(pkt[udp+UDP_DPORT:udp+UDP_DPORT+2], IPREF_PORT)
	be.PutUint16(pkt[udp+UDP_LEN:udp+UDP_LEN+2], uint16(pb.tail-udp))
	be.PutUint16(pkt[udp+UDP_CSUM:udp+UDP_CSUM+2], 0)

	encap := udp + 8
	pkt[encap+ENCAP_TTL] = pkt[pb.iphdr+8]
	pkt[encap+ENCAP_PROTO] = pkt[pb.iphdr+IP_PROTO]
	pkt[encap+ENCAP_HOPS] = soft.hops
	pkt[encap+ENCAP_RSVD] = 0

	opt := encap + 4
	pkt[opt+OPT_OPT] = IPREF_OPT
	pkt[opt+OPT_LEN] = optlen
	if optlen == IPREF_OPT64_LEN {
		be.PutUint64(pkt[opt+OPT_SREF64:opt+OPT_SREF64+8], iprefsrc.ref.l)
		be.PutUint64(pkt[opt+OPT_DREF64:opt+OPT_DREF64+8], iprefdst.ref.l)
	} else {
		be.PutUint64(pkt[opt+OPT_SREF128:opt+OPT_SREF128+8], iprefsrc.ref.h)
		be.PutUint64(pkt[opt+OPT_SREF128+8:opt+OPT_SREF128+16], iprefsrc.ref.l)
		be.PutUint64(pkt[opt+OPT_DREF128:opt+OPT_DREF128+8], iprefdst.ref.h)
		be.PutUint64(pkt[opt+OPT_DREF128+8:opt+OPT_DREF128+16], iprefdst.ref.l)
	}

	// adjust layer 4 headers

	// adjust ip header

	be.PutUint16(pkt[pb.iphdr+IP_LEN:pb.iphdr+IP_LEN+2], uint16(pb.len()))
	pkt[pb.iphdr+IP_PROTO] = UDP
	be.PutUint32(pkt[pb.iphdr+IP_SRC:pb.iphdr+IP_SRC+4], uint32(iprefsrc.ip))
	be.PutUint32(pkt[pb.iphdr+IP_DST:pb.iphdr+IP_DST+4], uint32(iprefdst.ip))

	if cli.debug["fwd"] || cli.debug["all"] {
		log.debug("inserting opt: %v", pb.pp_pkt())
	}

	return ACCEPT
}

// send soft record to the fwd_to_gw forwarder
func send_soft_rec(soft SoftRec) {

	pb := <-getbuf

	pb.set_v1hdr()
	pb.write_v1_header(V1_SIG, V1_SET_SOFT, 0, 0)

	pkt := pb.pkt[pb.v1hdr:]
	off := V1_HDR_LEN

	be.PutUint32(pkt[off+V1_SOFT_GW:off+V1_SOFT_GW+4], uint32(soft.gw))
	be.PutUint16(pkt[off+V1_SOFT_MTU:off+V1_SOFT_MTU+2], soft.mtu)
	be.PutUint16(pkt[off+V1_SOFT_PORT:off+V1_SOFT_PORT+2], soft.port)
	pkt[off+V1_SOFT_TTL] = soft.ttl
	pkt[off+V1_SOFT_HOPS] = soft.hops
	be.PutUint16(pkt[off+V1_SOFT_RSVD:off+V1_SOFT_RSVD+2], 0)

	pb.tail = pb.v1hdr + V1_HDR_LEN + V1_SOFT_LEN

	recv_tun <- pb
}

func remove_ipref_option(pb *PktBuf) int {

	pkt := pb.pkt[pb.iphdr:pb.tail]
	reflen := pb.reflen(pb.iphdr)

	if reflen == 0 {
		log.err("removing opt:  not an ipref packet, dropping")
		return DROP
	}

	// map addresses

	var sref Ref
	var dref Ref

	udp := pb.iphdr_len()
	encap := udp + 8
	opt := encap + 4

	src := IP32(be.Uint32(pkt[IP_SRC : IP_SRC+4]))
	dst := IP32(be.Uint32(pkt[IP_DST : IP_DST+4]))

	if reflen == IPREF_OPT128_LEN {
		sref.h = be.Uint64(pkt[opt+OPT_SREF128 : opt+OPT_SREF128+8])
		sref.l = be.Uint64(pkt[opt+OPT_SREF128+8 : opt+OPT_SREF128+8+8])
		dref.h = be.Uint64(pkt[opt+OPT_DREF128 : opt+OPT_DREF128+8])
		dref.l = be.Uint64(pkt[opt+OPT_DREF128+8 : opt+OPT_DREF128+8+8])
	} else if reflen == IPREF_OPT64_LEN {
		sref.h = 0
		sref.l = be.Uint64(pkt[opt+OPT_SREF64 : opt+OPT_SREF64+8])
		dref.h = 0
		dref.l = be.Uint64(pkt[opt+OPT_DREF64 : opt+OPT_DREF64+8])
	}

	dst_ip := map_tun.get_dst_ip(dst, dref)
	if dst_ip == 0 {
		log.err("removing opt:  unknown local destination  %v + %v  %v + %v, dropping",
			src, &sref, dst, &dref)
		return DROP // drop silently
	}

	src_ea := map_tun.get_src_ea(src, sref)
	if src_ea == 0 {
		log.err("removing opt:  unknown src ipref address  %v + %v  %v + %v, dropping",
			src, &sref, dst, &dref)
		return DROP // couldn't assign ea for some reason
	}

	// update soft state and tell the other forwarder if changed

	soft, ok := map_tun.soft[src]
	if !ok {
		soft.init(src)
		soft.port = 0 // force change
	}

	if soft.gw != src {
		log.err("removing opt:  soft record gw %v does match src %v, resetting", soft.gw, src)
		soft.init(src)
		soft.port = 0 // force change
	}

	if soft.ttl != pkt[encap+ENCAP_HOPS] ||
		soft.hops != pkt[encap+ENCAP_TTL] ||
		soft.port != be.Uint16(pkt[udp+UDP_SPORT:udp+UDP_SPORT+2]) {

		soft.ttl = pkt[encap+ENCAP_HOPS]
		soft.hops = pkt[encap+ENCAP_TTL]
		soft.port = be.Uint16(pkt[udp+UDP_SPORT : udp+UDP_SPORT+2])

		map_tun.soft[src] = soft

		// tel mgw about new or changed soft record

		send_soft_rec(soft)
	}

	// strip option

	hdrlen := pb.iphdr_len()
	pb.iphdr += 8 + 4 + reflen // udp header + encap + opt
	copy(pb.pkt[pb.iphdr:pb.iphdr+hdrlen], pb.pkt[pb.data:pb.data+hdrlen])
	pb.data = pb.iphdr

	pkt = pb.pkt[pb.iphdr:pb.tail]

	// adjust layer 4 headers

	// adjust ip header

	pktlen := be.Uint16(pkt[IP_LEN : IP_LEN+2])
	pktlen -= 8 + 4 + uint16(reflen)

	be.PutUint16(pkt[IP_LEN:IP_LEN+2], pktlen)
	be.PutUint32(pkt[IP_SRC:IP_SRC+4], uint32(src_ea))
	be.PutUint32(pkt[IP_DST:IP_DST+4], uint32(dst_ip))

	if cli.debug["fwd"] || cli.debug["all"] {
		log.debug("removing opt:  %v", pb.pp_pkt())
	}

	return ACCEPT
}

func fwd_to_gw() {

	for pb := range recv_tun {

		if cli.debug["fwd"] || cli.debug["all"] {
			log.debug("fwd_to_gw  in: %v", pb.pp_pkt())
		}

		verdict := DROP

		switch {

		case pb.pkt[pb.data]&0xf0 == 0x40:

			pb.set_iphdr()
			verdict = insert_ipref_option(pb)
			if verdict == ACCEPT {
				send_gw <- pb
			}

		case pb.pkt[pb.data] == V1_SIG:

			pb.set_v1hdr()
			switch pb.pkt[pb.v1hdr+V1_CMD] {
			case V1_SET_AREC:
				verdict = map_gw.set_new_address_records(pb)
			case V1_SET_MARK:
				verdict = map_gw.set_new_mark(pb)
			case V1_SET_SOFT:
				verdict = map_gw.update_soft(pb)
			default:
				log.err("fwd_to_gw: unknown address records command: %v, ignoring", pb.pkt[pb.v1hdr+V1_CMD])
			}

		default:
			log.err("fwd_to_gw: unknown packet type: 0x%02x, dropping", pb.pkt[pb.data])
		}

		if verdict == DROP {
			retbuf <- pb
		}
	}
}

func fwd_to_tun() {

	for pb := range recv_gw {

		if cli.debug["fwd"] || cli.debug["all"] {
			log.debug("fwd_to_tun in: %v", pb.pp_pkt())
		}

		verdict := DROP

		switch {

		case len(pb.pkt)-pb.data < MIN_PKT_LEN:

			log.err("fwd_to_tun in: short packet data/end(%v/%v), dropping", pb.data, len(pb.pkt))

		case pb.pkt[pb.data]&0xf0 == 0x40:

			verdict = remove_ipref_option(pb)
			if verdict == ACCEPT {
				send_tun <- pb
			}

		case pb.pkt[pb.data] == V1_SIG:

			pb.set_v1hdr()
			switch pb.pkt[pb.v1hdr+V1_CMD] {
			case V1_SET_AREC:
				verdict = map_tun.set_new_address_records(pb)
			case V1_SET_MARK:
				verdict = map_tun.set_new_mark(pb)
			default:
				log.err("fwd_to_tun: unknown address records command: %v, ignoring", pb.pkt[pb.v1hdr+V1_CMD])
			}

		default:
			log.err("fwd_to_tun: unknown packet type: 0x%02x, dropping", pb.pkt[pb.data])
		}

		if verdict == DROP {
			retbuf <- pb
		}
	}
}
