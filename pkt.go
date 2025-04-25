/* Copyright (c) 2018-2021 Waldemar Augustyn */

package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	. "github.com/ipref/common"
	rff "github.com/ipref/ref"
	"net"
	"strings"
)

const ( // packet handling verdicts

	ACCEPT = iota + 1
	DROP
	STOLEN
	ENCAP_ICMPv6_FIRST
)

const (
	MIN_PKT_LEN       = V1_HDR_LEN
	ICMP              = 1 // Same protocol number used by IPv4 and IPREF
	TCP               = 6
	UDP               = 17
	ECHO              = 7
	DISCARD           = 9
	IPv6_HOP_OPT      = 0 // IPv6 hop-by-hop options extension header
	IPv6_FRAG_EXT     = 44 // IPv6 fragment extension header
	ICMPv6            = 58
	IPv6_NO_NEXT      = 59
	IPREF_PORT        = 1045
	IPREF_HDR_MIN_LEN = 4 +     4  + 4  + 4  + 4
	IPREF_HDR_MAX_LEN = 4 + 8 + 16 + 16 + 16 + 16
	PKTQLEN           = 2
	// IPv4 header offests
	IP_VER           = 0
	IPv4_DSCP        = 1
	IPv4_LEN         = 2
	IPv4_ID          = 4
	IPv4_FRAG        = 6
	IPv4_TTL         = 8
	IPv4_PROTO       = 9
	IPv4_CSUM        = 10
	IPv4_SRC         = 12
	IPv4_DST         = 16
	IPv4_HDR_MIN_LEN = 20
	// IPv6 header offsets
	IPv6_PLD_LEN     = 4
	IPv6_NEXT        = 6
	IPv6_TTL         = 7
	IPv6_SRC         = 8
	IPv6_DST         = 24
	IPv6_HDR_MIN_LEN = 40
	// IPv6 fragment extension header offsets
	IPv6_FRAG_NEXT    = 0
	IPv6_FRAG_RES1    = 1
	IPv6_FRAG_OFF     = 2
	IPv6_FRAG_IDENT   = 4
	IPv6_FRAG_HDR_LEN = 8
	// UDP offsets
	UDP_SPORT   = 0
	UDP_DPORT   = 2
	UDP_LEN     = 4
	UDP_CSUM    = 6
	UDP_HDR_LEN = 8
	// TCP offsets
	TCP_SPORT = 0
	TCP_DPORT = 2
	TCP_CSUM  = 16
	// ICMP offsets
	ICMP_TYPE = 0
	ICMP_CODE = 1
	ICMP_CSUM = 2
	ICMP_BODY = 4
	ICMP_MTU  = 6
	ICMP_DATA = 8
)

const (
	PKT_IPREF = iota + 1
	PKT_IPv4
	PKT_IPv6
	PKT_V1
)
type IcmpReq struct { // params for icmp requests
	typ  byte // type is a reserved keyword so we use Polish spelling
	code byte
	mtu  uint16
	ours bool // packet originated from local network
}
type PktBuf struct {
	pkt   []byte
	typ   int // PKT_IPREF, PKT_V1, ...
	data  int // the beginning of the packet data; all data before should be ignored
	tail  int // the end of the packet data; all data after should be ignored
	peer  string         // peer or source name, human readable
	schan chan<- *PktBuf // send to or source channel
	// the ICMP type/code should be for the ICMP version that matches the packet
	// type (eg. PKT_IPv6 -> ICMPv6)
	icmp  IcmpReq
	df    bool // only used for PKT_IPv6 on send_tun
	// In some cases, we may not know the gateway's public IP in general, and
	// the gateway may in fact have multiple public IPs (eg. if it is connected
	// to multiple networks). However, the destination context IP in packets
	// received over the tunnel provides a hint about the gateway's public IP
	// which we can use for mapping. We pass it as part of the packet buffer to
	// avoid making this mechanism stateful - we only use this hint when mapping
	// addresses for this packet.
	gw_hint  IP
	// Same as gw_hint, but for the remote gateway.
	rgw_hint IP
}

func (pb *PktBuf) len() int {
	return pb.tail - pb.data
}

func (pb *PktBuf) clear() {
	*pb = PktBuf{pkt: pb.pkt}
}

func (pb *PktBuf) copy_from(pbo *PktBuf) {

	if len(pb.pkt) < int(pbo.tail) {
		log.fatal("pkt: buffer too small to copy from another pkt")
	}

	pb.typ = pbo.typ
	pb.data = pbo.data
	pb.tail = pbo.tail
	pb.peer = pbo.peer
	pb.schan = pbo.schan
	pb.icmp = pbo.icmp

	copy(pb.pkt[pb.data:pb.tail], pbo.pkt[pb.data:pb.tail])
}

func ip_proto_name(proto byte) string {

	switch proto {
	case TCP:
		return "TCP"
	case UDP:
		return "UDP"
	case ICMP:
		return "ICMP"
	case IPv6_HOP_OPT:
		return "IPv6-Hop-Opt"
	case IPv6_FRAG_EXT:
		return "IPv6-Frag"
	case ICMPv6:
		return "ICMPv6"
	case IPv6_NO_NEXT:
		return "IPv6-No-Next"
	}
	return fmt.Sprintf("%v", proto)
}

func (pb *PktBuf) pp_pkt() (ss string) {

	// IPv4(udp)  192.168.84.97  192.168.84.98  len(60)  data/tail(0/60)
	// IPREF(udp)  192.168.84.97 + 8af2819566  192.168.84.98 + 31fba013c  len(60) data/tail(48/158)
	// V1 REQ GET_EA(6) 77.71.180.101 + 2bc-1859   vman.ipref.org
	// V1 ACK GET_EA(6) 77.71.180.101 + 2bc-1859 = 10.254.192.127
	// V1 SET_MARK(1)  mapper(1)  mark(12342)  data/tail(12/68)
	// PKT 0532ab04 data/tail(18/20)

	pkt := pb.pkt[pb.data:pb.tail]

	// data too far into the buffer

	if len(pkt) < MIN_PKT_LEN {

		ss = fmt.Sprintf("PKT  short  data/tail(%v/%v)", pb.data, pb.tail)
		return
	}

	switch pb.typ {

	case PKT_IPREF:

		if !pb.ipref_ok() {
			break
		}
		flags := ""
		if pb.ipref_if() {
			flags += " IF"
		}
		if pb.ipref_df() {
			flags += " DF"
		}
		proto := pb.ipref_proto()
		src := pb.ipref_src()
		dst := pb.ipref_dst()

		ss = fmt.Sprintf("IPREF(%v)%v  %v  %v  len(%v)  data/tail(%v/%v)",
			ip_proto_name(proto),
			flags,
			src,
			dst,
			len(pkt),
			pb.data, pb.tail)

		return

	case PKT_IPv4:

		if len(pkt) < 20 || pkt[IP_VER]&0xf0 != 0x40 {
			break
		}
		flags := ""
		frag_field := be.Uint16(pkt[IPv4_FRAG:IPv4_FRAG+2])
		if frag_field & 0x3fff != 0 {
			flags += " IF"
		}
		if (frag_field >> 14) & 1 != 0 {
			flags += " DF"
		}
		ss = fmt.Sprintf("IPv4(%v)%v  %v  %v  len(%v)  data/tail(%v/%v)",
			ip_proto_name(pkt[IPv4_PROTO]),
			flags,
			net.IP(pkt[IPv4_SRC:IPv4_SRC+4]),
			net.IP(pkt[IPv4_DST:IPv4_DST+4]),
			be.Uint16(pkt[IPv4_LEN:IPv4_LEN+2]),
			pb.data, pb.tail)

		return

	case PKT_IPv6:

		if len(pkt) < IPv6_HDR_MIN_LEN || pkt[IP_VER]&0xf0 != 0x60 {
			break
		}
		src_ip := IPFromSlice(pkt[IPv6_SRC:IPv6_SRC+16])
		dst_ip := IPFromSlice(pkt[IPv6_DST:IPv6_DST+16])
		ss = fmt.Sprintf("IPv6(%v)  %v  %v  len(%v)  data/tail(%v/%v)",
			ip_proto_name(pkt[IPv6_NEXT]),
			src_ip,
			dst_ip,
			be.Uint16(pkt[IPv6_PLD_LEN:IPv6_PLD_LEN+2]),
			pb.data, pb.tail)

		return

	case PKT_V1:

		if len(pkt) < V1_HDR_LEN || pkt[V1_VER] != V1_SIG {
			break
		}

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

		case V1_DATA | V1_GET_EA:
			ss += fmt.Sprintf(" DATA GET_EA(%v) invalid", cmd&0x3f)
		case V1_REQ | V1_GET_EA:

			// V1  REQ GET_EA(6) oid mapper(1) pktid[058f] 77.71.180.101 + 2bc-1859

			oid = O32(be.Uint32(pkt[off+V1_OID : off+V1_OID+4]))

			ss += fmt.Sprintf("  REQ GET_EA(%v) oid %v(%v) pktid[%04x]",
				cmd&0x3f, owners.name(oid), oid, be.Uint16(pkt[V1_PKTID:V1_PKTID+2]))

			off += V1_MARK_LEN

			if pktlen-off < v1_arec_len {
				ss += fmt.Sprintf(" too short")
			} else {
				arec := AddrRecDecode(ea_iplen, gw_iplen, pkt[off:])
				ss += fmt.Sprintf(" %v + %v", arec.GW, &arec.Ref)
			}

		case V1_ACK | V1_GET_EA:

			// V1  ACK GET_EA(6) oid mapper(1) pktid[058f] 77.71.180.101 + 2bc-1859 = 10.254.11.8

			oid = O32(be.Uint32(pkt[off+V1_OID : off+V1_OID+4]))

			ss += fmt.Sprintf("  ACK GET_EA(%v) oid %v(%v) pktid[%04x]",
				cmd&0x3f, owners.name(oid), oid, be.Uint16(pkt[V1_PKTID:V1_PKTID+2]))

			off += V1_MARK_LEN

			if pktlen-off < v1_arec_len {
				ss += fmt.Sprintf(" too short")
			} else {
				arec := AddrRecDecode(ea_iplen, gw_iplen, pkt[off:])
				ss += fmt.Sprintf(" %v + %v = %v", arec.GW, &arec.Ref, arec.EA)
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

			if pktlen-off < v1_arec_len {
				ss += fmt.Sprintf(" too short")
			} else {
				arec := AddrRecDecode(ea_iplen, gw_iplen, pkt[off:])
				ss += fmt.Sprintf(" %v + %v", arec.GW, &arec.Ref)

				off += v1_arec_len
				if pktlen-off > 4 && pkt[off] == V1_TYPE_STRING && int(pkt[off+1]) <= pktlen-off-2 {
					ss += fmt.Sprintf("   %v", string(pkt[off+2:off+2+int(pkt[off+1])]))
				}
			}
		case V1_ACK | V1_MC_GET_EA:

			// V1  ACK MC_GET_EA(6) pktid[058f] 77.71.180.101 + 2bc-1859 = 10.254.11.8

			ss += fmt.Sprintf("  ACK MC_GET_EA(%v) pktid[%04x]",
				cmd&0x3f, be.Uint16(pkt[V1_PKTID:V1_PKTID+2]))

			if pktlen-off < v1_arec_len {
				ss += fmt.Sprintf(" too short")
			} else {
				arec := AddrRecDecode(ea_iplen, gw_iplen, pkt[off:])
				ss += fmt.Sprintf(" %v + %v = %v", arec.GW, &arec.Ref, arec.EA)
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

	ss = fmt.Sprintf("PKT  type(%02x)  %08x  data/tail(%v/%v)", pb.typ, be.Uint32(pkt[0:4]), pb.data, pb.tail)
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

	// IPv4(udp) 4500  192.168.84.93  10.254.22.202  len(64) id(1) ttl(64) csum:0000
	// IPREF(udp) 4500  192.168.84.93 + 8af2819566  10.254.22.202 + 31fba013c  len(64) ttl(64)

	pkt := pb.pkt[pb.data:pb.tail]

	switch pb.typ {

	case PKT_IPREF:

		if !pb.ipref_ok() {
			break
		}
		flags := ""
		if pb.ipref_if() {
			flags += " IF"
		}
		if pb.ipref_df() {
			flags += " DF"
		}
		ttl := pb.ipref_ttl()
		proto := pb.ipref_proto()
		src := pb.ipref_src()
		dst := pb.ipref_dst()

		log.trace("%vIPREF(%v)%v  %v  %v  len(%v) ttl(%v)",
			pfx,
			ip_proto_name(proto),
			flags,
			src,
			dst,
			len(pkt),
			ttl)
		return

	case PKT_IPv4:

		if len(pkt) < 20 || pkt[IP_VER]&0xf0 != 0x40 {
			break
		}

		flags := ""
		frag_field := be.Uint16(pkt[IPv4_FRAG:IPv4_FRAG+2])
		if frag_field & 0x3fff != 0 {
			flags += " IF"
		}
		if (frag_field >> 14) & 1 != 0 {
			flags += " DF"
		}
		log.trace("%vIPv4(%v)%v  %v  %v  len(%v) id(%v) ttl(%v) csum: %04x",
			pfx,
			ip_proto_name(pkt[IPv4_PROTO]),
			flags,
			IPFromSlice(pkt[IPv4_SRC:IPv4_SRC+4]),
			IPFromSlice(pkt[IPv4_DST:IPv4_DST+4]),
			be.Uint16(pkt[IPv4_LEN:IPv4_LEN+2]),
			be.Uint16(pkt[IPv4_ID:IPv4_ID+2]),
			pkt[IPv4_TTL],
			be.Uint16(pkt[IPv4_CSUM:IPv4_CSUM+2]))
		return

	case PKT_IPv6:

		if len(pkt) < IPv6_HDR_MIN_LEN || pkt[IP_VER]&0xf0 != 0x60 {
			break
		}

		src_ip := IPFromSlice(pkt[IPv6_SRC:IPv6_SRC+16])
		dst_ip := IPFromSlice(pkt[IPv6_DST:IPv6_DST+16])
		log.trace("%vIPv6(%v)  %v  %v  len(%v) ttl(%v)",
			pfx,
			ip_proto_name(pkt[IPv6_NEXT]),
			src_ip,
			dst_ip,
			be.Uint16(pkt[IPv6_PLD_LEN:IPv6_PLD_LEN+2]),
			pkt[IPv6_TTL])
		return
	}

	log.trace(pfx + pb.pp_pkt())
}

func (pb *PktBuf) pp_tran(pfx string) {

	pkt := pb.pkt[pb.data:pb.tail]
	var proto byte

	switch pb.typ {

	case PKT_IPREF:

		if !pb.ipref_ok() {
			return
		}
		proto = pb.ipref_proto()
		pkt = pkt[pb.ipref_hdr_len():]

	case PKT_IPv4:

		if len(pkt) < 20 || pkt[IP_VER]&0xf0 != 0x40 || pkt[IP_VER]&0x0f != 5 {
			return
		}
		proto = pkt[IPv4_PROTO]
		pkt = pkt[20:]

	case PKT_IPv6:

		if len(pkt) < IPv6_HDR_MIN_LEN || pkt[IP_VER]&0xf0 != 0x60 {
			return
		}
		proto = pkt[IPv6_NEXT]
		pkt = pkt[IPv6_HDR_MIN_LEN:]

	default:
		return
	}

	switch proto {
	case TCP:
	case UDP:

		// UDP  1045  1045  len(96) csum 0

		if len(pkt) < UDP_HDR_LEN {
			return
		}
		log.trace("%vUDP  %v  %v  len(%v) csum: %04x",
			pfx,
			be.Uint16(pkt[UDP_SPORT:UDP_SPORT+2]),
			be.Uint16(pkt[UDP_DPORT:UDP_DPORT+2]),
			be.Uint16(pkt[UDP_LEN:UDP_LEN+2]),
			be.Uint16(pkt[UDP_CSUM:UDP_CSUM+2]))

	case ICMP:
	}
}

// TODO Move to ipref/ref
func ref_asslice(ref rff.Ref) (refb []byte) {
	refb = make([]byte, 16)
	be.PutUint64(refb[:8], ref.H)
	be.PutUint64(refb[8:], ref.L)
	return
}

// TODO Move to ipref/ref
func ref_fromslice(refb []byte) (ref rff.Ref) {
	ref.H = be.Uint64(refb[:8])
	ref.L = be.Uint64(refb[8:])
	return
}

func ref_secondbyte(ref rff.Ref) byte {
	return byte(ref.L >> 8)
}

// Don't call until you've checked that the packet size is at least 1 or
// ipref_ok().
func (pb *PktBuf) ipref_ver_ok() bool {
	return pb.pkt[pb.data] >> 4 == 0x1
}

// Don't call until you've checked that the packet size is at least 1 or
// ipref_ok().
func (pb *PktBuf) ipref_reflen() int {

	switch (pb.pkt[pb.data] >> 2) & 0x3 {
	case 0:
		return 4
	case 1:
		return 8
	case 2:
		return 16
	default:
		return 0
	}
}

func ipref_encode_reflen(reflen int) byte {

	switch reflen {
	case 4:
		return 0
	case 8:
		return 1
	case 16:
		return 2
	default:
		return 0
	}
}

// Don't call until you've checked that the packet size is at least 1 or
// ipref_ok().
func (pb *PktBuf) ipref_if() bool {
	return (pb.pkt[pb.data] >> 1) & 1 != 0
}

// Don't call until you've checked that the packet size is at least 1 or
// ipref_ok().
func (pb *PktBuf) ipref_df() bool {
	return pb.pkt[pb.data] & 1 != 0
}

// Don't call until you've checked that the packet size is at least 2.
func (pb *PktBuf) ipref_ipver() byte {
	return pb.pkt[pb.data + 1] >> 4
}

// Don't call until you've checked ipref_ok().
func (pb *PktBuf) ipref_iplen() int {
	switch pb.ipref_ipver() {
	case 4:
		return 4
	case 6:
		return 16
	}
	panic("invalid ip ver")
}

// Don't call until you've checked that the packet size is at least 3 or
// ipref_ok().
func (pb *PktBuf) ipref_ttl() byte {
	return pb.pkt[pb.data + 2]
}

// Don't call until you've checked that the packet size is at least 4 or
// ipref_ok().
func (pb *PktBuf) ipref_proto() byte {
	return pb.pkt[pb.data + 3]
}

// Don't call until you've checked ipref_ok().
func (pb *PktBuf) ipref_frag() (frag_if bool, frag_off int, frag_mf bool, ident uint32) {

	frag_if = pb.ipref_if()
	if frag_if {
		frag_field := be.Uint16(pb.pkt[pb.data+6:pb.data+8])
		frag_off = int(frag_field &^ 7)
		frag_mf = frag_field & 1 != 0
		ident = be.Uint32(pb.pkt[pb.data+8:pb.data+12])
	}
	return
}

// Don't call until you've checked ipref_ok().
func (pb *PktBuf) ipref_hdr_len() int {

	if pb.tail - pb.data == 0 {
		return 0
	}
	n := 4
	if pb.ipref_if() {
		n += 8
	}
	n += pb.ipref_iplen() * 2
	n += pb.ipref_reflen() * 2
	return n
}

func (pb *PktBuf) ipref_ok() bool {

	if pb.tail - pb.data < IPREF_HDR_MIN_LEN {
		return false
	}
	if !pb.ipref_ver_ok() || pb.ipref_reflen() == 0 || pb.pkt[pb.data + 1] & 0xf != 0 {
		return false
	}
	ip_ver := pb.pkt[pb.data + 1] >> 4
	if ip_ver != 4 && ip_ver != 6 {
		return false
	}
	if pb.tail - pb.data < pb.ipref_hdr_len() {
		return false
	}
	if pb.ipref_if() {
		if pb.pkt[pb.data + 4] != 0 || pb.pkt[pb.data + 5] != 0 {
			return false
		}
		if pb.pkt[pb.data + 7] & 6 != 0 {
			return false
		}
	}
	return true
}

// Don't call until you've checked ipref_ok(). Slice refers to pb.pkt.
func (pb *PktBuf) ipref_sref_ip() []byte {

	i := pb.data + 4
	if pb.ipref_if() {
		i += 8
	}
	return pb.pkt[i : i + pb.ipref_iplen()]
}

// Don't call until you've checked ipref_ok(). Slice refers to pb.pkt.
func (pb *PktBuf) ipref_dref_ip() []byte {

	i := pb.data + 4
	if pb.ipref_if() {
		i += 8
	}
	iplen := pb.ipref_iplen()
	i += iplen
	return pb.pkt[i : i + iplen]
}

// Don't call until you've checked ipref_ok().
func (pb *PktBuf) ipref_sref() rff.Ref {

	reflen := pb.ipref_reflen()
	i := pb.data + 4 + pb.ipref_iplen() * 2
	if pb.ipref_if() {
		i += 8
	}
	return ipref_decode_ref(pb.pkt[i : i + reflen])
}

// Don't call until you've checked ipref_ok().
func (pb *PktBuf) ipref_dref() rff.Ref {

	reflen := pb.ipref_reflen()
	i := pb.data + 4 + pb.ipref_iplen() * 2 + reflen
	if pb.ipref_if() {
		i += 8
	}
	return ipref_decode_ref(pb.pkt[i : i + reflen])
}

// Don't call until you've checked ipref_ok().
func (pb *PktBuf) ipref_src() IpRef {
	src_ip := IPFromSlice(pb.ipref_sref_ip())
	return IpRef{src_ip, pb.ipref_sref()}
}

// Don't call until you've checked ipref_ok().
func (pb *PktBuf) ipref_dst() IpRef {
	dst_ip := IPFromSlice(pb.ipref_dref_ip())
	return IpRef{dst_ip, pb.ipref_dref()}
}

func (pb *PktBuf) ipref_swap_srcdst() {

	frag_if := pb.ipref_if()
	iplen := pb.ipref_iplen()
	reflen := pb.ipref_reflen()
	i := pb.data + 4
	if frag_if {
		i += 8
	}
	var temp [16]byte
	// swap IPs
	copy(temp[:iplen], pb.pkt[i:])
	copy(pb.pkt[i : i + iplen], pb.pkt[i + iplen:])
	copy(pb.pkt[i + iplen:], temp[:iplen])
	// swap refs
	i += iplen * 2
	copy(temp[:reflen], pb.pkt[i:])
	copy(pb.pkt[i : i + reflen], pb.pkt[i + reflen:])
	copy(pb.pkt[i + reflen:], temp[:reflen])
}

func min_reflen(ref rff.Ref) int {

	if ref.H == 0 {
		if ref.L >> 32 == 0 {
			return 4
		} else {
			return 8
		}
	} else {
		return 16
	}
}

func ipref_encode_ref(bs []byte, ref rff.Ref) {

	switch len(bs) {
	case 4:
		be.PutUint32(bs, uint32(ref.L))
	case 8:
		be.PutUint64(bs, ref.L)
	case 16:
		be.PutUint64(bs[:8], ref.H)
		be.PutUint64(bs[8:], ref.L)
	default:
		panic("invalid")
	}
}

func ipref_decode_ref(bs []byte) (ref rff.Ref) {

	switch len(bs) {
	case 4:
		ref.L = uint64(be.Uint32(bs))
	case 8:
		ref.L = be.Uint64(bs)
	case 16:
		ref.H = be.Uint64(bs[:8])
		ref.L = be.Uint64(bs[8:])
	default:
		panic("invalid")
	}
	return ref
}

func (pb *PktBuf) ip_hdr_len() int {

	switch pb.typ {

	case PKT_IPv4:

		if pb.len() < IPv4_HDR_MIN_LEN {
			return pb.len()
		}
		return min(int(pb.pkt[pb.data] & 0xf) * 4, pb.len())

	case PKT_IPv6:

		if pb.len() < IPv6_HDR_MIN_LEN {
			return pb.len()
		}
		if pb.pkt[IPv6_NEXT] == IPv6_FRAG_EXT {
			return min(IPv6_HDR_MIN_LEN + IPv6_FRAG_HDR_LEN, pb.len())
		}
		return IPv6_HDR_MIN_LEN
	}

	panic("unexpected")
}

func (pb *PktBuf) ip_proto() byte {

	switch pb.typ {

	case PKT_IPv4:

		if pb.len() < IPv4_PROTO + 1 {
			return 0
		}
		return pb.pkt[pb.data + IPv4_PROTO]

	case PKT_IPv6:

		if pb.len() < IPv6_NEXT + 1 {
			return 0
		}
		proto := pb.pkt[pb.data + IPv6_NEXT]
		if proto == IPv6_FRAG_EXT {
			if pb.len() < IPv4_HDR_MIN_LEN + IPv6_FRAG_NEXT + 1 {
				return 0
			}
			return pb.pkt[pb.data + IPv4_HDR_MIN_LEN + IPv6_FRAG_NEXT]
		}
		return proto
	}

	panic("unexpected")
}

func (pb *PktBuf) verify_csum() bool {

	pkt := pb.pkt[pb.data:pb.tail]
	var proto byte

	switch pb.typ {

	case PKT_IPREF:

		if !pb.ipref_ok() {
			return false
		}
		proto = pb.ipref_proto()
		pkt = pkt[pb.ipref_hdr_len():]

	case PKT_IPv4:

		if len(pkt) < 20 || pkt[IP_VER]&0xf0 != 0x40 || pkt[IP_VER]&0x0f != 5 {
			return false
		}
		proto = pkt[IPv4_PROTO]
		ip_csum := csum_add(0, pkt[:IPv4_HDR_MIN_LEN])
		if be.Uint16(pkt[IPv4_CSUM:IPv4_CSUM+2]) != ip_csum^0xffff {
			return false
		}
		pkt = pkt[20:]

	default:
		return true
	}

	switch proto {
	case TCP: // TODO
	case UDP:

		if len(pkt) < UDP_HDR_LEN {
			return false
		}
		udp_csum := csum_add(0, []byte{0, proto})
		udp_csum = csum_add(0, pkt[UDP_LEN:UDP_LEN+2])
		udp_csum = csum_add(0, pkt)
		if be.Uint16(pkt[UDP_CSUM:UDP_CSUM+2]) != udp_csum^0xffff {
			return false
		}

	case ICMP:

		if len(pkt) < 8 {
			return false
		}
		icmp_csum := csum_add(0, pkt)
		if be.Uint16(pkt[ICMP_CSUM:ICMP_CSUM+2]) != icmp_csum^0xffff {
			return false
		}
	}

	return true
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

	pb.typ = PKT_V1
	pkt := pb.pkt[pb.data:]

	if len(pkt) < V1_HDR_LEN {
		log.fatal("pkt: not enough space for v1 header")
	}

	pkt[V1_VER] = V1_SIG
	pkt[V1_CMD] = cmd
	be.PutUint16(pkt[V1_PKTID:V1_PKTID+2], pktid)
	pkt[V1_IPVER] = (byte(cli.ea_ip.Ver()) << 4) | byte(cli.gw_bind_ip.Ver())
	pkt[V1_RESERVED] = 0
	copy(pkt[V1_PKTLEN:V1_PKTLEN+2], []byte{0, 2})
}

func (pb *PktBuf) validate_v1_header(rlen int) error {

	pb.tail = pb.data + rlen
	pkt := pb.pkt[pb.data:pb.tail]

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

	if pkt[V1_IPVER] >> 4 != byte(cli.ea_ip.Ver()) {
		return fmt.Errorf("ea ip version mismatch: sent(%v) != expected(%v)",
			pkt[V1_IPVER] >> 4, cli.ea_ip.Ver())
	}
	if pkt[V1_IPVER] & 0xf != byte(cli.gw_bind_ip.Ver()) {
		return fmt.Errorf("gw ip version mismatch: sent(%v) != expected(%v)",
			pkt[V1_IPVER] & 0xf, cli.gw_bind_ip.Ver())
	}

	if pkt[V1_RESERVED] != 0 {
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
allocate a new one but no more than maxbuf in total.
*/

func pkt_buffers() {

	var pb *PktBuf
	allocated := 0 // num of allocated buffers

	log.debug("pkt: packet buflen(%v)", cli.pktbuflen)

	for {

		if allocated < cli.maxbuf {
			select {
			case pb = <-retbuf:
				pb.clear()
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

		pb.pkt[pb.data] = 0xbd // corrupt IP header to detect reuse of freed pkt
		getbuf <- pb
	}
}
