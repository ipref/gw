/* Copyright (c) 2018 Waldemar Augustyn */

package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

const (
	MAXBUF = 20
)

const ( // v1 constants

	V1_SIG          = 0x11 // v1 signature
	V1_HDR_LEN      = 16
	V1_AREC_HDR_LEN = 4
	V1_AREC_LEN     = 4 + 4 + 4 + 8 + 8     // ea + ip + gw + ref.h + ref.l
	V1_SOFT_LEN     = 4 + 2 + 2 + 1 + 1 + 2 // gw + mtu + port + ttl + hops + rsvd
	// v1 header offsets
	V1_VER       = 0
	V1_CMD       = 1
	V1_SRCQ      = 2
	V1_DSTQ      = 3
	V1_OID       = 4
	V1_MARK      = 8
	V1_RESERVED  = 12
	V1_ITEM_TYPE = 13
	V1_NUM_ITEMS = 14
	// v1 arec offsets
	V1_AREC_EA   = 0
	V1_AREC_IP   = 4
	V1_AREC_GW   = 8
	V1_AREC_REFH = 12
	V1_AREC_REFL = 20
	// v1 soft offsets
	V1_SOFT_GW   = 0
	V1_SOFT_MTU  = 4
	V1_SOFT_PORT = 6
	V1_SOFT_TTL  = 8
	V1_SOFT_HOPS = 9
	V1_SOFT_RSVD = 10
)

const ( // v1 item types

	V1_TYPE_NONE = iota
	V1_TYPE_AREC
	V1_TYPE_SOFT
	V1_TYPE_IPV4
)

const ( // v1 commands

	V1_SET_AREC = iota + 1
	V1_SET_MARK
	V1_SET_SOFT
	V1_PURGE
	V1_INDUCE_ARP
)

const ( // packet handling verdicts

	ACCEPT = iota + 1
	DROP
	STOLEN
)

const (
	MIN_PKT_LEN      = V1_HDR_LEN
	ICMP             = 1
	TCP              = 6
	UDP              = 17
	ECHO             = 7
	DISCARD          = 9
	IPREF_PORT       = 1045
	IPREF_OPT        = 0x9E // C(1) + CLS(0) + OptNum(30) (rfc3692 EXP 30)
	IPREF_OPT64_LEN  = 4 + 8 + 8
	IPREF_OPT128_LEN = 4 + 16 + 16
	OPTLEN           = 8 + 4 + 4 + 16 + 16 // udphdr + encap + opt + ref + ref
	TUN_HDR_LEN      = 4
	TUN_IFF_TUN      = uint16(0x0001)
	TUN_IPv4         = uint16(0x0800)
	PKTQLEN          = 2
	// TUN header offsets
	TUN_FLAGS = 0
	TUN_PROTO = 2
	// IP header offests
	IP_VER   = 0
	IP_DSCP  = 1
	IP_LEN   = 2
	IP_ID    = 4
	IP_FRAG  = 6
	IP_TTL   = 8
	IP_PROTO = 9
	IP_CSUM  = 10
	IP_SRC   = 12
	IP_DST   = 16
	// UDP offsets
	UDP_SPORT = 0
	UDP_DPORT = 2
	UDP_LEN   = 4
	UDP_CSUM  = 6
	// TCP offsets
	TCP_SPORT = 0
	TCP_DPORT = 2
	TCP_CSUM  = 16
	// ICMP offsets
	ICMP_TYPE = 0
	ICMP_CODE = 1
	ICMP_CSUM = 2
	ICMP_MTU  = 6
	ICMP_DATA = 8
	// encap offsets
	ENCAP_TTL   = 0
	ENCAP_PROTO = 1
	ENCAP_HOPS  = 2
	ENCAP_RSVD  = 3
	// opt offsets
	OPT_OPT     = 0
	OPT_LEN     = 1
	OPT_RSVD    = 2
	OPT_SREF64  = 4
	OPT_SREF128 = 4
	OPT_DREF64  = 12
	OPT_DREF128 = 20
)

type IcmpReq struct { // params for icmp requests
	typ  byte // we want 'type' but it's a reserved keyword so we use Polish spelling
	code byte
	mtu  uint16
}
type PktBuf struct {
	pkt   []byte
	data  int
	tail  int
	iphdr int
	icmp  IcmpReq
}

func (pb *PktBuf) clear() {

	pb.data = 0
	pb.tail = 0
	pb.iphdr = 0
	pb.icmp = IcmpReq{0, 0, 0}
}

func (pb *PktBuf) copy_from(pbo *PktBuf) {

	if len(pb.pkt) < int(pbo.tail) {
		log.fatal("pkt: buffer to small to copy from another pkt")
	}

	pb.data = pbo.data
	pb.tail = pbo.tail
	pb.iphdr = pbo.iphdr
	pb.icmp = pbo.icmp

	copy(pb.pkt[pb.data:pb.tail], pbo.pkt[pb.data:pb.tail])
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
		case V1_PURGE:
			ss += fmt.Sprintf(" PURGE(%v)", cmd)
		default:
			ss += fmt.Sprintf(" cmd(%v)", cmd)
		}

		oid := O32(be.Uint32(pkt[V1_OID : V1_OID+4]))
		mark := M32(be.Uint32(pkt[V1_MARK : V1_MARK+4]))
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

func (pb *PktBuf) set_iphdr() int {

	pb.iphdr = pb.data
	return pb.iphdr
}

func (pb *PktBuf) iphdr_len() int {
	return int((pb.pkt[pb.iphdr] & 0x0f) * 4)
}

func (pb *PktBuf) len() int {
	return int(pb.tail - pb.data)
}

func (pb *PktBuf) reflen(iphdr int) (reflen int) {

	pkt := pb.pkt[iphdr:]

	if len(pkt) < 20 {
		return // pkt way too short
	}

	udp := int(pkt[IP_VER]&0xf) * 4
	encap := udp + 8
	opt := encap + 4

	if pkt[IP_VER]&0xf0 == 0x40 &&
		len(pkt) >= opt+4 &&
		pkt[IP_PROTO] == UDP &&
		(be.Uint16(pkt[udp+UDP_SPORT:udp+UDP_SPORT+2]) == IPREF_PORT || be.Uint16(pkt[udp+UDP_DPORT:udp+UDP_DPORT+2]) == IPREF_PORT) &&
		pkt[opt+OPT_OPT] == IPREF_OPT {

		reflen = int(pkt[opt+OPT_LEN])

		if (reflen != IPREF_OPT128_LEN && reflen != IPREF_OPT64_LEN) || len(pkt) < opt+reflen {
			reflen = 0 // not a valid ipref packet after all
		}
	}

	return
}

// calculate iphdr csum and l4 csum
func (pb *PktBuf) verify_csum() (uint16, uint16) {

	var iphdr_csum uint16
	var l4_csum uint16

	pkt := pb.pkt[pb.iphdr:pb.tail]

	// iphdr csum

	iphdr_csum = csum_add(0, pkt[:pb.iphdr_len()])

	// l4 csum

	off := pb.iphdr_len()

	l4_csum = csum_add(0, pkt[IP_SRC:IP_DST+4])

	switch pkt[IP_PROTO] {
	case TCP:
	case UDP:

		l4_csum = csum_add(l4_csum, []byte{0, pkt[IP_PROTO]})
		l4_csum = csum_add(l4_csum, pkt[off+UDP_LEN:off+UDP_LEN+2])
		l4_csum = csum_add(l4_csum, pkt[off:])

	case ICMP:
	}

	return iphdr_csum ^ 0xffff, l4_csum ^ 0xffff
}

func (pb *PktBuf) write_v1_header(cmd byte, oid O32, mark M32) {

	pkt := pb.pkt[pb.iphdr:]

	if len(pkt) < V1_HDR_LEN {
		log.fatal("pkt: not enough space for v1 header")
	}

	pkt[V1_VER] = V1_SIG
	pkt[V1_CMD] = cmd
	pkt[V1_SRCQ] = 0
	pkt[V1_DSTQ] = 0
	be.PutUint32(pkt[V1_OID:V1_OID+4], uint32(oid))
	be.PutUint32(pkt[V1_MARK:V1_MARK+4], uint32(mark))
	pkt[V1_RESERVED] = 0
	pkt[V1_ITEM_TYPE] = V1_TYPE_NONE
	be.PutUint16(pkt[V1_NUM_ITEMS:V1_NUM_ITEMS+2], 0)
}

// Add buffer bytes to csum. Input csum and result are not inverted.
func csum_add(csum uint16, buf []byte) uint16 {

	sum := uint32(csum)

	for ix := 0; ix < len(buf); ix += 2 {
		sum += uint32(be.Uint16(buf[ix : ix+2]))
	}

	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	return uint16(sum)
}

// Subract buffer bytes from csum. Input csum and result are not inverted.
func csum_subtract(csum uint16, buf []byte) uint16 {

	sum := uint32(csum)

	for ix := 0; ix < len(buf); ix += 2 {
		sum -= uint32(be.Uint16(buf[ix : ix+2]))
	}

	for sum > 0xffff {
		sum = (sum & 0xffff) - (((sum ^ 0xffff0000) + 0x10000) >> 16)
	}

	return uint16(sum)
}

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

var be = binary.BigEndian

var getbuf chan (*PktBuf)
var retbuf chan (*PktBuf)

/* Buffer allocator

We use getbuf channel of length 1. As soon as it gets empty we try to put
a packet into it.  We try to get it from the retbuf but if not availale we
allocate a new one but no more than MAXBUF in total. If we exceed this
limit and no packets in retbuf, we wait until one is returned.
*/

func pkt_buffers() {

	var pb *PktBuf
	allocated := 0 // num of allocated buffers

	log.debug("pkt: packet buflen(%v)", cli.pktbuflen)

	for {

		if allocated < MAXBUF {
			select {
			case pb = <-retbuf:
			default:
				pb = &PktBuf{pkt: make([]byte, cli.pktbuflen, cli.pktbuflen)}
				allocated += 1
				log.debug("pkt: new PktBuf allocated, total(%v)", allocated)
				if allocated == MAXBUF*80/100 {
					log.info("pkt: close to reaching limit of buffer allocation: %v of %v", allocated, MAXBUF)
				}
				if allocated == MAXBUF {
					log.info("pkt: reached limit of buffer allocation: %v of %v", allocated, MAXBUF)
				}
			}
		} else {
			pb = <-retbuf
		}

		pb.clear()
		getbuf <- pb
	}
}
