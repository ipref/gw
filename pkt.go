/* Copyright (c) 2018-2021 Waldemar Augustyn */

package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	rff "github.com/ipref/ref"
	"net"
	"strings"
)

const ( // v1 constants

	V1_SIG      = 0x11 // v1 signature
	V1_HDR_LEN  = 8
	V1_AREC_LEN = 4 + 4 + 4 + 8 + 8     // ea + ip + gw + ref.h + ref.l
	V1_MARK_LEN = 4 + 4                 // oid + mark
	V1_SOFT_LEN = 4 + 2 + 2 + 1 + 1 + 2 // gw + mtu + port + ttl + hops + rsvd
	// v1 header offsets
	V1_VER      = 0
	V1_CMD      = 1
	V1_PKTID    = 2
	V1_RESERVED = 4
	V1_PKTLEN   = 6
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
	// v1 mark offsets
	V1_OID  = 0
	V1_MARK = 4
	// v1 host data offsets
	V1_HOST_DATA_BATCHID = 0
	V1_HOST_DATA_COUNT   = 0
	V1_HOST_DATA_HASH    = 4
	V1_HOST_DATA_SOURCE  = 12
)

const ( // v1 item types

	//V1_TYPE_NONE   = 0
	//V1_TYPE_AREC   = 1
	//V1_TYPE_SOFT   = 2
	//V1_TYPE_IPV4   = 3
	V1_TYPE_STRING = 4
)

const ( // v1 commands

	V1_NOOP           = 0
	V1_SET_AREC       = 1
	V1_SET_MARK       = 2
	V1_SET_SOFT       = 3
	V1_GET_REF        = 4
	V1_INDUCE_ARP     = 5
	V1_GET_EA         = 6
	V1_MC_GET_EA      = 7
	V1_SAVE_OID       = 8
	V1_SAVE_TIME_BASE = 9
	V1_RECOVER_EA     = 10
	V1_RECOVER_REF    = 11

	V1_MC_HOST_DATA      = 14
	V1_MC_HOST_DATA_HASH = 15
)

const ( // v1 command mode, top two bits

	V1_DATA = 0x00
	V1_REQ  = 0x40
	V1_ACK  = 0x80
	V1_NACK = 0xC0
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
	typ  byte // type is a reserved keyword so we use Polish spelling
	code byte
	mtu  uint16
}
type PktBuf struct {
	pkt   []byte
	data  int
	tail  int
	iphdr int
	peer  string         // peer or source name, human readable
	schan chan<- *PktBuf // send to or source channel
	icmp  IcmpReq
}

func (pb *PktBuf) clear() {

	pb.data = 0
	pb.tail = 0
	pb.iphdr = 0
	pb.peer = ""
	pb.schan = nil
	pb.icmp = IcmpReq{0, 0, 0}
}

func (pb *PktBuf) copy_from(pbo *PktBuf) {

	if len(pb.pkt) < int(pbo.tail) {
		log.fatal("pkt: buffer too small to copy from another pkt")
	}

	pb.data = pbo.data
	pb.tail = pbo.tail
	pb.iphdr = pbo.iphdr
	pb.icmp = pbo.icmp

	copy(pb.pkt[pb.data:pb.tail], pbo.pkt[pb.data:pb.tail])
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

func (pb *PktBuf) pp_pkt() (ss string) {

	// IP(udp)  192.168.84.97  192.168.84.98  len(60)  data/tail(0/60)
	// IPREF(udp)  192.168.84.97 + 8af2819566  192.168.84.98 + 31fba013c  len(60) data/tail(48/158)
	// V1 REQ GET_EA(6) 77.71.180.101 + 2bc-1859   vman.ipref.org
	// V1 ACK GET_EA(6) 77.71.180.101 + 2bc-1859 = 10.254.192.127
	// V1 SET_MARK(1)  mapper(1)  mark(12342)  data/tail(12/68)
	// PKT 0532ab04 data/tail(18/20)

	iphdr := pb.data // pb.iphdr may not be set, let's use pb.data instead
	if pb.iphdr-pb.data == ETHER_HDRLEN {
		iphdr = pb.iphdr // skip ether header
	} else if pb.iphdr-pb.data == TUN_HDR_LEN {
		iphdr = pb.iphdr // skip tun header
	}
	pkt := pb.pkt[iphdr:]

	// data too far into the buffer

	if len(pkt) < MIN_PKT_LEN {

		ss = fmt.Sprintf("PKT  short  data/tail(%v/%v)", pb.data, pb.tail)
		return
	}

	reflen := pb.reflen(iphdr)

	// IPREF packet

	if reflen != 0 {

		var sref rff.Ref
		var dref rff.Ref

		udp := int(pkt[IP_VER]&0xf) * 4
		encap := udp + 8
		opt := encap + 4

		if reflen == IPREF_OPT128_LEN {
			sref.H = be.Uint64(pkt[opt+OPT_SREF128 : opt+OPT_SREF128+8])
			sref.L = be.Uint64(pkt[opt+OPT_SREF128+8 : opt+OPT_SREF128+8+8])
			dref.H = be.Uint64(pkt[opt+OPT_DREF128 : opt+OPT_DREF128+8])
			dref.L = be.Uint64(pkt[opt+OPT_DREF128+8 : opt+OPT_DREF128+8+8])
		} else if reflen == IPREF_OPT64_LEN {
			sref.H = 0
			sref.L = be.Uint64(pkt[opt+OPT_SREF64 : opt+OPT_SREF64+8])
			dref.H = 0
			dref.L = be.Uint64(pkt[opt+OPT_DREF64 : opt+OPT_DREF64+8])
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

		pktlen := int(be.Uint16(pkt[V1_PKTLEN:V1_PKTLEN+2])) * 4
		off := V1_HDR_LEN

		var oid O32

		cmd := pkt[V1_CMD]
		switch cmd {
		case V1_NOOP:
			ss += fmt.Sprintf(" NOOP(%v)", cmd)
		case V1_SET_AREC:
			ss += fmt.Sprintf(" SET_AREC(%v)", cmd)
		case V1_SET_MARK:

			oid = O32(be.Uint32(pkt[off+V1_OID : off+V1_OID+4]))
			ss += fmt.Sprintf(" SET_MARK(%v) oid %v(%v) mark(%v)",
				cmd, owners.name(oid), oid, be.Uint32(pkt[off+V1_MARK:off+V1_MARK+4]))

		case V1_SET_SOFT:
			ss += fmt.Sprintf(" SET_SOFT(%v)", cmd)
		case V1_INDUCE_ARP:
			ss += fmt.Sprintf(" INDUCE_ARP(%v)", cmd)
		case V1_DATA | V1_GET_EA:
			ss += fmt.Sprintf(" DATA GET_EA(%v) invalid", cmd&0x3f)
		case V1_REQ | V1_GET_EA:

			// V1  REQ GET_EA(6) oid mapper(1) pktid[058f] 77.71.180.101 + 2bc-1859

			oid = O32(be.Uint32(pkt[off+V1_OID : off+V1_OID+4]))

			ss += fmt.Sprintf("  REQ GET_EA(%v) oid %v(%v) pktid[%04x]",
				cmd&0x3f, owners.name(oid), oid, be.Uint16(pkt[V1_PKTID:V1_PKTID+2]))

			off += V1_MARK_LEN

			if pktlen-off < V1_AREC_LEN {
				ss += fmt.Sprintf(" too short")
			} else {

				var ref rff.Ref
				ref.H = be.Uint64(pkt[off+V1_AREC_REFH : off+V1_AREC_REFH+8])
				ref.L = be.Uint64(pkt[off+V1_AREC_REFL : off+V1_AREC_REFL+8])
				ss += fmt.Sprintf(" %v + %v", net.IP(pkt[off+V1_AREC_GW:off+V1_AREC_GW+4]).To4(), &ref)
			}

		case V1_ACK | V1_GET_EA:

			// V1  ACK GET_EA(6) oid mapper(1) pktid[058f] 77.71.180.101 + 2bc-1859 = 10.254.11.8

			oid = O32(be.Uint32(pkt[off+V1_OID : off+V1_OID+4]))

			ss += fmt.Sprintf("  ACK GET_EA(%v) oid %v(%v) pktid[%04x]",
				cmd&0x3f, owners.name(oid), oid, be.Uint16(pkt[V1_PKTID:V1_PKTID+2]))

			off += V1_MARK_LEN

			if pktlen-off < V1_AREC_LEN {
				ss += fmt.Sprintf(" too short")
			} else {

				var ref rff.Ref
				ref.H = be.Uint64(pkt[off+V1_AREC_REFH : off+V1_AREC_REFH+8])
				ref.L = be.Uint64(pkt[off+V1_AREC_REFL : off+V1_AREC_REFL+8])
				ss += fmt.Sprintf(" %v + %v", net.IP(pkt[off+V1_AREC_GW:off+V1_AREC_GW+4]).To4(), &ref)
				ss += fmt.Sprintf(" = %v", net.IP(pkt[off+V1_AREC_EA:off+V1_AREC_EA+4]).To4())
			}

		case V1_NACK | V1_GET_EA:

			// V1 NACK GET_EA(6) oid mapper(1) pktid[058f]

			oid = O32(be.Uint32(pkt[off+V1_OID : off+V1_OID+4]))

			ss += fmt.Sprintf(" NACK GET_EA(%v) oid %v(%v) pktid[%04x]",
				cmd&0x3f, owners.name(oid), oid, be.Uint16(pkt[V1_PKTID:V1_PKTID+2]))

		case V1_DATA | V1_MC_GET_EA:
			ss += fmt.Sprintf(" DATA MC_GET_EA(%v) invalid", cmd&0x3f)
		case V1_REQ | V1_MC_GET_EA:

			// V1  REQ MC_GET_EA(6) pktid[058f] 77.71.180.101 + 2bc-1859   vman.ipref.org

			ss += fmt.Sprintf("  REQ MC_GET_EA(%v) pktid[%04x]",
				cmd&0x3f, be.Uint16(pkt[V1_PKTID:V1_PKTID+2]))

			if pktlen-off < V1_AREC_LEN {
				ss += fmt.Sprintf(" too short")
			} else {

				var ref rff.Ref
				ref.H = be.Uint64(pkt[off+V1_AREC_REFH : off+V1_AREC_REFH+8])
				ref.L = be.Uint64(pkt[off+V1_AREC_REFL : off+V1_AREC_REFL+8])
				ss += fmt.Sprintf(" %v + %v", net.IP(pkt[off+V1_AREC_GW:off+V1_AREC_GW+4]).To4(), &ref)

				off += V1_AREC_LEN
				if pktlen-off > 4 && pkt[off] == V1_TYPE_STRING && int(pkt[off+1]) <= pktlen-off-2 {
					ss += fmt.Sprintf("   %v", string(pkt[off+2:off+2+int(pkt[off+1])]))
				}
			}
		case V1_ACK | V1_MC_GET_EA:

			// V1  ACK MC_GET_EA(6) pktid[058f] 77.71.180.101 + 2bc-1859 = 10.254.11.8

			ss += fmt.Sprintf("  ACK MC_GET_EA(%v) pktid[%04x]",
				cmd&0x3f, be.Uint16(pkt[V1_PKTID:V1_PKTID+2]))

			if pktlen-off < V1_AREC_LEN {
				ss += fmt.Sprintf(" too short")
			} else {

				var ref rff.Ref
				ref.H = be.Uint64(pkt[off+V1_AREC_REFH : off+V1_AREC_REFH+8])
				ref.L = be.Uint64(pkt[off+V1_AREC_REFL : off+V1_AREC_REFL+8])
				ss += fmt.Sprintf(" %v + %v", net.IP(pkt[off+V1_AREC_GW:off+V1_AREC_GW+4]).To4(), &ref)
				ss += fmt.Sprintf(" = %v", net.IP(pkt[off+V1_AREC_EA:off+V1_AREC_EA+4]).To4())
			}

		case V1_NACK | V1_MC_GET_EA:

			// V1 NACK MC_GET_EA(6) pktid[058f]

			ss += fmt.Sprintf(" NACK MC_GET_EA(%v) pktid[%04x]",
				cmd&0x3f, be.Uint16(pkt[V1_PKTID:V1_PKTID+2]))

		default:
			ss += fmt.Sprintf(" cmd(%v)", cmd)
		}

		//oid := O32(be.Uint32(pkt[V1_OID : V1_OID+4]))
		//mark := M32(be.Uint32(pkt[V1_MARK : V1_MARK+4]))
		//ss += fmt.Sprintf("  %v(%v)  mark(%v)  data/tail(%v/%v)",
		//	owners.name(oid), oid, mark, pb.data, pb.tail)

		return
	}

	// unknown or invalid packet

	ss = fmt.Sprintf("PKT  %08x  data/tail(%v/%v)", be.Uint32(pkt[0:4]), pb.data, pb.tail)

	return
}

func (pb *PktBuf) pp_raw(pfx string) {

	// RAW  45 00 00 74 2e 52 40 00 40 11 d0 b6 0a fb 1b 6f c0 a8 54 5e 04 15 04 15 00 ..

	const max = 128 + 32
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

		var sref rff.Ref
		var dref rff.Ref

		udp := int(pkt[IP_VER]&0xf) * 4
		encap := udp + 8
		opt := encap + 4

		if reflen == IPREF_OPT128_LEN {
			sref.H = be.Uint64(pkt[opt+OPT_SREF128 : opt+OPT_SREF128+8])
			sref.L = be.Uint64(pkt[opt+OPT_SREF128+8 : opt+OPT_SREF128+8+8])
			dref.H = be.Uint64(pkt[opt+OPT_DREF128 : opt+OPT_DREF128+8])
			dref.L = be.Uint64(pkt[opt+OPT_DREF128+8 : opt+OPT_DREF128+8+8])
		} else if reflen == IPREF_OPT64_LEN {
			sref.H = 0
			sref.L = be.Uint64(pkt[opt+OPT_SREF64 : opt+OPT_SREF64+8])
			dref.H = 0
			dref.L = be.Uint64(pkt[opt+OPT_DREF64 : opt+OPT_DREF64+8])
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

func (pb *PktBuf) write_v1_header(cmd byte, pktid uint16) {

	pkt := pb.pkt[pb.iphdr:]

	if len(pkt) < V1_HDR_LEN {
		log.fatal("pkt: not enough space for v1 header")
	}

	pkt[V1_VER] = V1_SIG
	pkt[V1_CMD] = cmd
	be.PutUint16(pkt[V1_PKTID:V1_PKTID+2], pktid)
	copy(pkt[V1_RESERVED:V1_RESERVED+2], []byte{0, 0})
	copy(pkt[V1_PKTLEN:V1_PKTLEN+2], []byte{0, 2})
}

func (pb *PktBuf) validate_v1_header(rlen int) error {

	pb.tail = pb.iphdr + rlen
	pkt := pb.pkt[pb.iphdr:pb.tail]

	if len(pkt) < V1_HDR_LEN {
		return fmt.Errorf("pkt too short: %v bytes", rlen)
	}

	if pkt[V1_VER] != V1_SIG {
		return fmt.Errorf("invalid signature: 0x%02x", pkt[V1_VER])
	}

	lenfield := int(be.Uint16(pkt[V1_PKTLEN : V1_PKTLEN+2]))
	if len(pkt) != lenfield*4 {
		return fmt.Errorf("pkt length(%v) does not match length field(%v)",
			len(pkt), lenfield*4)
	}

	if pkt[V1_RESERVED] != 0 || pkt[V1_RESERVED+1] != 0 {
		return fmt.Errorf("non-zero reserved field")
	}

	return nil
}

var be = binary.BigEndian

var getbuf chan (*PktBuf)
var retbuf chan (*PktBuf)

/* Buffer allocator

We use getbuf channel of length 1. As soon as it gets empty we try to put
a packet into it.  We try to get it from the retbuf but if not availale we
allocate a new one but no more than maxbuf in total. If we exceed this
limit and no packets in retbuf, we wait until one is returned.
*/

func pkt_buffers() {

	var pb *PktBuf
	allocated := 0 // num of allocated buffers

	log.debug("pkt: packet buflen(%v)", cli.pktbuflen)

	for {

		if allocated < cli.maxbuf {
			select {
			case pb = <-retbuf:
				pb.pkt[pb.iphdr] = 0xbd // corrupt IP header to detect reuse of freed pkt
			default:
				pb = &PktBuf{pkt: make([]byte, cli.pktbuflen, cli.pktbuflen)}
				allocated += 1
				log.debug("pkt: new PktBuf allocated, total(%v)", allocated)
				if allocated%10 == 0 {
					log.info("pkt: buffer allocation: %v of %v", allocated, cli.maxbuf)
				}
			}
		} else {
			log.fatal("pkt: out of buffers, max buffers allocated: %v of %v", allocated, cli.maxbuf)
		}

		pb.clear()
		getbuf <- pb
	}
}
