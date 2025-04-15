/* Copyright (c) 2018-2021 Waldemar Augustyn */

package main

import (
	"crypto/rand"
	"net/netip"
	. "github.com/ipref/common"
	rff "github.com/ipref/ref"
	"strings"
)

/* IPREF Tunnel Protocol */

const (
	ICMP_DROP = iota
	ICMP_NO_ENCAP
	ICMP_ENCAP

	ICMP_ENCAP_MAX_LEN = 576 // must be at least IPREF_HDR_MAX_LEN
	ICMP_ENCAP_MAX_DEPTH = 3

	ENCAP_MAP_SUCCESS = 0
	ENCAP_MAP_UNKNOWN_SRC = 2 // You can swap src/dst with ^1
	ENCAP_MAP_UNKNOWN_DST = 3
)

// Convert an ICMPv4/ICMPv6 message into an IPREF_ICMP message.
func icmp_encap(pkt_typ int, typ byte, code byte) (byte, byte, int) {

	switch pkt_typ {

	case PKT_IPv4:
		switch typ {
		case ICMPv4_ECHO_REPLY:
			if code == 0 {
				return IPREF_ICMP_ECHO_REPLY, 0, ICMP_NO_ENCAP
			}
		case ICMPv4_DEST_UNREACH:
			switch code {
			case ICMPv4_NET_UNREACH:
				return IPREF_ICMP_DEST_UNREACH, IPREF_ICMP_NET_UNREACH, ICMP_ENCAP
			case ICMPv4_HOST_UNREACH:
				return IPREF_ICMP_DEST_UNREACH, IPREF_ICMP_HOST_UNREACH, ICMP_ENCAP
			case ICMPv4_PORT_UNREACH:
				return IPREF_ICMP_DEST_UNREACH, IPREF_ICMP_PORT_UNREACH, ICMP_ENCAP
			case ICMPv4_FRAG_NEEDED:
				return IPREF_ICMP_DEST_UNREACH, IPREF_ICMP_FRAG_NEEDED, ICMP_ENCAP
			case ICMPv4_ADMIN_PROHIB:
				return IPREF_ICMP_DEST_UNREACH, IPREF_ICMP_ADMIN_PROHIB, ICMP_ENCAP
			}
		case ICMPv4_ECHO_REQUEST:
			if code == 0 {
				return IPREF_ICMP_ECHO_REQUEST, 0, ICMP_NO_ENCAP
			}
		case ICMPv4_TIME_EXCEEDED:
			switch code {
			case ICMPv4_EXC_TTL:
				return IPREF_ICMP_TIME_EXCEEDED, IPREF_ICMP_EXC_TTL, ICMP_ENCAP
			case ICMPv4_EXC_FRAG:
				return IPREF_ICMP_TIME_EXCEEDED, IPREF_ICMP_EXC_FRAG, ICMP_ENCAP
			}
		}

	case PKT_IPv6:
		switch typ {
		case ICMPv6_DEST_UNREACH:
			switch code {
			case ICMPv6_NET_UNREACH:
				return IPREF_ICMP_DEST_UNREACH, IPREF_ICMP_NET_UNREACH, ICMP_ENCAP
			case ICMPv6_ADMIN_PROHIB:
				return IPREF_ICMP_DEST_UNREACH, IPREF_ICMP_ADMIN_PROHIB, ICMP_ENCAP
			case ICMPv6_HOST_UNREACH:
				return IPREF_ICMP_DEST_UNREACH, IPREF_ICMP_HOST_UNREACH, ICMP_ENCAP
			case ICMPv6_PORT_UNREACH:
				return IPREF_ICMP_DEST_UNREACH, IPREF_ICMP_PORT_UNREACH, ICMP_ENCAP
			}
		case ICMPv6_PACKET_TOO_BIG:
			if code == 0 {
				return IPREF_ICMP_DEST_UNREACH, IPREF_ICMP_FRAG_NEEDED, ICMP_ENCAP
			}
		case ICMPv6_TIME_EXCEEDED:
			switch code {
			case ICMPv6_EXC_TTL:
				return IPREF_ICMP_TIME_EXCEEDED, IPREF_ICMP_EXC_TTL, ICMP_ENCAP
			case ICMPv6_EXC_FRAG:
				return IPREF_ICMP_TIME_EXCEEDED, IPREF_ICMP_EXC_FRAG, ICMP_ENCAP
			}
		case ICMPv6_ECHO_REQUEST:
			if code == 0 {
				return IPREF_ICMP_ECHO_REQUEST, 0, ICMP_NO_ENCAP
			}
		case ICMPv6_ECHO_REPLY:
			if code == 0 {
				return IPREF_ICMP_ECHO_REPLY, 0, ICMP_NO_ENCAP
			}
		}
	}

	return 0, 0, ICMP_DROP
}

// Convert an IPREF_ICMP message into an ICMPv4/ICMPv6 message.
func icmp_deencap(pkt_typ int, typ byte, code byte) (byte, byte, int) {

	switch pkt_typ {

	case PKT_IPv4:
		switch typ {
		case IPREF_ICMP_ECHO_REPLY:
			if code == 0 {
				return ICMPv4_ECHO_REPLY, 0, ICMP_NO_ENCAP
			}
		case IPREF_ICMP_DEST_UNREACH:
			switch code {
			case IPREF_ICMP_NET_UNREACH:
				return ICMPv4_DEST_UNREACH, ICMPv4_NET_UNREACH, ICMP_ENCAP
			case IPREF_ICMP_HOST_UNREACH:
				return ICMPv4_DEST_UNREACH, ICMPv4_HOST_UNREACH, ICMP_ENCAP
			case IPREF_ICMP_PORT_UNREACH:
				return ICMPv4_DEST_UNREACH, ICMPv4_PORT_UNREACH, ICMP_ENCAP
			case IPREF_ICMP_FRAG_NEEDED:
				return ICMPv4_DEST_UNREACH, ICMPv4_FRAG_NEEDED, ICMP_ENCAP
			case IPREF_ICMP_ADMIN_PROHIB:
				return ICMPv4_DEST_UNREACH, ICMPv4_ADMIN_PROHIB, ICMP_ENCAP
			}
		case IPREF_ICMP_ECHO_REQUEST:
			if code == 0 {
				return ICMPv4_ECHO_REQUEST, 0, ICMP_NO_ENCAP
			}
		case IPREF_ICMP_TIME_EXCEEDED:
			switch code {
			case IPREF_ICMP_EXC_TTL:
				return ICMPv4_TIME_EXCEEDED, ICMPv4_EXC_TTL, ICMP_ENCAP
			case IPREF_ICMP_EXC_FRAG:
				return ICMPv4_TIME_EXCEEDED, ICMPv4_EXC_FRAG, ICMP_ENCAP
			}
		}

	case PKT_IPv6:
		switch typ {
		case IPREF_ICMP_ECHO_REPLY:
			if code == 0 {
				return ICMPv6_ECHO_REPLY, 0, ICMP_NO_ENCAP
			}
		case IPREF_ICMP_DEST_UNREACH:
			switch code {
			case IPREF_ICMP_NET_UNREACH:
				return ICMPv6_DEST_UNREACH, ICMPv6_NET_UNREACH, ICMP_ENCAP
			case IPREF_ICMP_HOST_UNREACH:
				return ICMPv6_DEST_UNREACH, ICMPv6_HOST_UNREACH, ICMP_ENCAP
			case IPREF_ICMP_PORT_UNREACH:
				return ICMPv6_DEST_UNREACH, ICMPv6_PORT_UNREACH, ICMP_ENCAP
			case IPREF_ICMP_FRAG_NEEDED:
				return ICMPv6_PACKET_TOO_BIG, 0, ICMP_ENCAP
			case IPREF_ICMP_ADMIN_PROHIB:
				return ICMPv6_DEST_UNREACH, ICMPv6_ADMIN_PROHIB, ICMP_ENCAP
			}
		case IPREF_ICMP_ECHO_REQUEST:
			if code == 0 {
				return ICMPv6_ECHO_REQUEST, 0, ICMP_NO_ENCAP
			}
		case IPREF_ICMP_TIME_EXCEEDED:
			switch code {
			case IPREF_ICMP_EXC_TTL:
				return ICMPv6_TIME_EXCEEDED, ICMPv6_EXC_TTL, ICMP_ENCAP
			case IPREF_ICMP_EXC_FRAG:
				return ICMPv6_TIME_EXCEEDED, ICMPv6_EXC_FRAG, ICMP_ENCAP
			}
		}
	}

	return 0, 0, ICMP_DROP
}

func MustParseRef(str string) rff.Ref {
	str = strings.TrimSpace(str)
	ref, err := rff.Parse(str)
	if err != nil {
		log.fatal("invalid ref: %v", err)
	}
	return ref
}

func MustParseIpRef(str string) (ipref IpRef) {
	str = strings.TrimSpace(str)
	ip, ref, found := strings.Cut(str, "+")
	if !found {
		log.fatal("invalid ipref: %v", str)
	}
	ipref.ip = MustParseIP(strings.TrimSpace(ip))
	ipref.ref = MustParseRef(strings.TrimSpace(ref))
	return
}

func (mgw *MapGw) get_src_ipref(ip IP) (IpRef, bool) {

	if ip == cli.ea_gwip || ip == cli.ea_ip {
		return IpRef{cli.gw_ip, cli.gw_ref}, true
	}
	if ip.IsLinkLocal() {
		return IpRef{}, false // drop silently
	}
	if cli.ea_net.Contains(netip.Addr(ip)) {
		log.err("encap:   source (%v) IP is in encoded address space, dropping", ip)
		return IpRef{}, false
	}
	if !netip.Addr(ip).IsGlobalUnicast() {
		log.err("encap:   source (%v) IP isn't valid unicast, dropping", ip)
		return IpRef{}, false
	}
	if rec, found := mgw.get_src_iprec(ip); found {
		return rec.IpRef, true
	}
	log.err("encap:   unknown src address: %v, dropping", ip)
	return IpRef{}, false
}

func (mgw *MapGw) get_dst_ipref(ip IP) (IpRef, bool) {

	if ip == cli.ea_gwip || ip == cli.ea_ip {
		return IpRef{cli.gw_ip, cli.gw_ref}, true
	}
	if !cli.ea_net.Contains(netip.Addr(ip)) {
		log.err("encap:   destination (%v) IP isn't in encoded address space, dropping", ip)
		return IpRef{}, false
	}
	if rec, found := mgw.get_dst_iprec(ip); found {
		return rec.IpRef, true
	}
	log.err("encap:   unknown dst address: %v, dropping", ip)
	return IpRef{}, false
}

func (mgw *MapGw) get_srcdst_ipref_rev(src, dst IP, rev bool) (
	iprefsrc, iprefdst IpRef, status int) {

	if rev {
		src, dst = dst, src
	}
	var ok bool
	if iprefsrc, ok = mgw.get_src_ipref(src); !ok {
		status = ENCAP_MAP_UNKNOWN_SRC
		goto fail
	}
	if iprefdst, ok = mgw.get_dst_ipref(dst); !ok {
		status = ENCAP_MAP_UNKNOWN_DST
		goto fail
	}
	if rev {
		iprefsrc, iprefdst = iprefdst, iprefsrc
	}
	status = ENCAP_MAP_SUCCESS
	return
fail:
	iprefsrc, iprefdst = IpRef{}, IpRef{}
	if rev {
		status ^= 1 // swap src/dst
	}
	return
}

// Encapsulate an IP packet, replacing the IP header with an IPREF header.
// Returns ACCEPT (on success), DROP (on error), or STOLEN (unless steal is
// false). If steal is true, then an ICMP response may be returned to the sender
// if the destination is unreachable.
func ipref_encap(pb *PktBuf, rev_srcdst bool, icmp_depth int, dec_ttl, steal bool) int {

	pkt_typ := pb.typ
	pkt := pb.pkt

	if (ea_iplen == 4 && pkt_typ != PKT_IPv4) || (ea_iplen == 16 && pkt_typ != PKT_IPv6) {
		log.debug("encap:   packet IP version doesn't match local network, dropping")
		return DROP
	}

	// decode IP header

	var ident uint32
	var frag_if, frag_df, frag_mf bool
	var frag_off int
	var ttl, proto byte
	var local_srcdst []byte
	var local_src, local_dst IP
	var l4 int
	var l4_pkt_len int
	var frag_end int // the position of the end of the packet in the l4 datagram

	switch pkt_typ {

	case PKT_IPv4:

		if pb.len() < IPv4_HDR_MIN_LEN {
			log.err("encap:   invalid packet (too small), dropping")
			return DROP
		}
		if (pkt[pb.data+IP_VER] & 0xf0 != 0x40) {
			log.err("encap:   packet is not IPv4, dropping")
			return DROP
		}
		if (pkt[pb.data+IP_VER] & 0x0f != 5) {
			log.err("encap:   packet has options, dropping")
			return DROP
		}
		ip_pkt_len := int(be.Uint16(pkt[pb.data+IPv4_LEN:pb.data+IPv4_LEN+2]))
		// We will still encapsulate packets which have been truncated, because that
		// can happen with packets inside ICMP.
		if ip_pkt_len < pb.len() {
			log.err("encap:   invalid packet (bad length field), dropping")
			return DROP
		}
		ident = uint32(be.Uint16(pkt[pb.data+IPv4_ID:pb.data+IPv4_ID+2]))
		frag_field := be.Uint16(pkt[pb.data+IPv4_FRAG:pb.data+IPv4_FRAG+2])
		frag_df = frag_field & 0x4000 != 0
		frag_mf = frag_field & 0x2000 != 0
		frag_off = int((frag_field & 0x1fff) << 3)
		frag_if = frag_off != 0 || frag_mf
		ttl = pkt[pb.data+IPv4_TTL]
		proto = pkt[pb.data+IPv4_PROTO]
		var srcdstb [8]byte
		copy(srcdstb[:], pkt[pb.data+IPv4_SRC:])
		local_srcdst = srcdstb[:]
		local_src = IPFromSlice(pkt[pb.data+IPv4_SRC : pb.data+IPv4_SRC+4])
		local_dst = IPFromSlice(pkt[pb.data+IPv4_DST : pb.data+IPv4_DST+4])
		l4 = pb.data + IPv4_HDR_MIN_LEN
		l4_pkt_len = pb.tail - l4
		frag_end = frag_off + l4_pkt_len

	case PKT_IPv6:

		if pb.len() < IPv6_HDR_MIN_LEN {
			log.err("encap:   invalid packet (too small), dropping")
			return DROP
		}
		if (pkt[pb.data+IP_VER] & 0xf0 != 0x60) {
			log.err("encap:   packet is not IPv6, dropping")
			return DROP
		}
		ip_pld_len := int(be.Uint16(pkt[pb.data+IPv6_PLD_LEN:pb.data+IPv6_PLD_LEN+2]))
		if (ip_pld_len == 0) {
			log.err("encap:   IPv6 jumbogram, dropping")
			return DROP
		}
		// We will still encapsulate packets which have been truncated, because that
		// can happen with packets inside ICMP.
		if IPv6_HDR_MIN_LEN + ip_pld_len < pb.len() {
			log.err("encap:   invalid packet (bad length field), dropping")
			return DROP
		}
		proto = pkt[pb.data+IPv6_NEXT]
		ttl = pkt[pb.data+IPv6_TTL]
		var srcdstb [32]byte
		copy(srcdstb[:], pkt[pb.data+IPv6_SRC:])
		local_srcdst = srcdstb[:]
		local_src = IPFromSlice(pkt[pb.data+IPv6_SRC : pb.data+IPv6_SRC+16])
		local_dst = IPFromSlice(pkt[pb.data+IPv6_DST : pb.data+IPv6_DST+16])
		if proto == IPv6_FRAG_EXT {
			i := pb.data + IPv6_HDR_MIN_LEN
			l4 = i + IPv6_FRAG_HDR_LEN
			l4_pkt_len = pb.tail - l4
			if l4_pkt_len < 0 {
				log.err("encap:   invalid IPv6 fragment extension header (truncated), dropping")
				return DROP
			}
			proto = pkt[i+IPv6_FRAG_NEXT]
			frag_field := be.Uint16(pkt[i+IPv6_FRAG_OFF:i+IPv6_FRAG_OFF+2])
			if pkt[i+IPv6_FRAG_RES1] != 0 || frag_field & 6 != 0 {
				log.err("encap:   IPv6 fragment extension header reserved field is non-zero, dropping")
				return DROP
			}
			frag_if = true
			frag_df = true
			frag_mf = frag_field & 1 != 0
			frag_off = int(frag_field &^ 7)
			frag_end = frag_off + l4_pkt_len
			ident = be.Uint32(pkt[i+IPv6_FRAG_IDENT:i+IPv6_FRAG_IDENT+4])
		} else {
			ident = 0
			frag_if = false
			frag_df = true
			frag_mf = false
			frag_off = 0
			l4 = pb.data + IPv6_HDR_MIN_LEN
			l4_pkt_len = pb.tail - l4
			frag_end = l4_pkt_len
		}
		if proto == IPv6_FRAG_EXT {
			log.err("encap:   invalid IPv6 packet (fragment within fragment), dropping")
			return DROP
		}

	default:

		log.fatal("encap:   unknown packet type: %v", pkt_typ)
	}
	if frag_if && (l4_pkt_len & 0x7 != 0 && frag_mf) {
		log.err("encap:   invalid packet (fragmentation), dropping")
		return DROP
	}

	// decrement ttl

	if dec_ttl {
		if ttl > 0 {
			ttl -= 1
		}
		if ttl <= 0 {
			log.trace("encap:   ttl reached zero:  %v  %v", local_src, local_dst)
			if steal {
				if pkt_typ == PKT_IPv4 {
					pb.icmp.typ = ICMPv4_TIME_EXCEEDED
					pb.icmp.code = ICMPv4_EXC_TTL
				} else {
					pb.icmp.typ = ICMPv6_TIME_EXCEEDED
					pb.icmp.code = ICMPv6_EXC_TTL
				}
				pb.icmp.mtu = 0
				pb.icmp.ours = true
				icmpreq <- pb
				return STOLEN
			}
			return DROP
		}
	}

	// map addresses

	iprefsrc, iprefdst, map_status := map_gw.get_srcdst_ipref_rev(local_src, local_dst, rev_srcdst)
	switch {
	case map_status == ENCAP_MAP_SUCCESS:
	case map_status == ENCAP_MAP_UNKNOWN_SRC:
		return DROP
	case map_status == ENCAP_MAP_UNKNOWN_DST:
		if steal {
			if pkt_typ == PKT_IPv4 {
				pb.icmp.typ = ICMPv4_DEST_UNREACH
				pb.icmp.code = ICMPv4_NET_UNREACH
			} else {
				pb.icmp.typ = ICMPv6_DEST_UNREACH
				pb.icmp.code = ICMPv6_NET_UNREACH
			}
			pb.icmp.mtu = 0
			pb.icmp.ours = true
			icmpreq <- pb
			return STOLEN
		}
		return DROP
	default:
		panic("unexpected")
	}
	var ipver, iplen int
	switch {
	case iprefsrc.ip.Is4() && iprefdst.ip.Is4():
		ipver = 4
		iplen = 4
	case iprefsrc.ip.Is6() && iprefdst.ip.Is6():
		ipver = 6
		iplen = 16
	default:
		panic("unexpected")
	}

	// translate layer 4 packet

	pb.data, pb.tail = l4, l4 + l4_pkt_len
	if !ipref_encap_l4(pb, local_srcdst, &proto,
		frag_if, frag_df, frag_mf,
		frag_off, frag_end,
		icmp_depth) {

		return DROP
	}
	l4, l4_pkt_len = pb.data, pb.len()

	// replace IP header with IPREF header

	reflen := max(min_reflen(iprefsrc.ref), min_reflen(iprefdst.ref))
	ipref_hdr_len := 4 + iplen * 2 + reflen * 2
	if frag_if {
		ipref_hdr_len += 8
	}
	if l4 < ipref_hdr_len {
		if len(pkt) < ipref_hdr_len + l4_pkt_len {
			log.err("encap:   not enough space in buffer for ipref header, dropping")
			return DROP
		}
		// This should only happen for packets inside ICMP, which should be pretty small.
		copy(pkt[ipref_hdr_len:], pkt[l4:pb.tail])
		l4 = ipref_hdr_len
	}
	pb.data = l4 - ipref_hdr_len
	pb.typ = PKT_IPREF

	pkt[pb.data] = (0x1 << 4) | ipref_encode_reflen(reflen) << 2
	if frag_if {
		pkt[pb.data] |= 1 << 1
	}
	if frag_df {
		pkt[pb.data] |= 1 << 0
	}
	pkt[pb.data+1] = uint8(ipver) << 4
	pkt[pb.data+2] = ttl
	pkt[pb.data+3] = proto
	i := pb.data + 4
	if frag_if {
		pkt[i] = 0
		pkt[i+1] = 0
		frag_field := uint16(frag_off)
		if frag_mf {
			frag_field |= 1
		}
		be.PutUint16(pkt[i+2:i+4], frag_field)
		be.PutUint32(pkt[i+4:i+8], ident)
		i += 8
	}

	copy(pkt[i:i+iplen], iprefsrc.ip.AsSlice())
	i += iplen
	copy(pkt[i:i+iplen], iprefdst.ip.AsSlice())
	i += iplen
	ipref_encode_ref(pkt[i:i+reflen], iprefsrc.ref)
	i += reflen
	ipref_encode_ref(pkt[i:i+reflen], iprefdst.ref)
	i += reflen

	return ACCEPT
}

// pb contains a layer 4 datagram (or a fragment thereof). pb.typ is the
// original layer 3 protocol: PKT_IPv4 or PKT_IPv6. Returns false (to drop) or
// true (on success).
func ipref_encap_l4(pb *PktBuf,
	local_srcdst []byte, // Not modified; used for adjusting checksum
	proto *byte,
	frag_if, frag_df, frag_mf bool,
	frag_off, frag_end int,
	icmp_depth int) bool {

	pkt := pb.pkt

	var ipver int
	switch pb.typ {
	case PKT_IPv4:
		ipver = 4
	case PKT_IPv6:
		ipver = 6
	default:
		panic("unexpected")
	}

	switch *proto {

	case TCP: // subtract ip src/dst addresses from csum

		if frag_off >= TCP_CSUM+2 || frag_end < TCP_CSUM {
			break
		}
		if frag_end < TCP_CSUM+2 {
			log.err("encap:   invalid tcp packet, dropping")
			return false
		}

		tcp_csum := be.Uint16(pkt[pb.data+TCP_CSUM-frag_off : pb.data+TCP_CSUM-frag_off+2])

		if tcp_csum != 0 {
			tcp_csum = csum_subtract(tcp_csum^0xffff, local_srcdst[:])
			be.PutUint16(pkt[pb.data+TCP_CSUM-frag_off:pb.data+TCP_CSUM-frag_off+2], tcp_csum^0xffff)
		}

	case UDP: // subtract ip src/dst addresses from csum

		if frag_off != 0 {
			break
		}
		if frag_end < UDP_HDR_LEN {
			log.err("encap:   invalid udp packet, dropping")
			return false
		}

		udp_csum := be.Uint16(pkt[pb.data+UDP_CSUM : pb.data+UDP_CSUM+2])

		if udp_csum != 0 {
			if udp_csum == 0xffff {
				udp_csum = 0
			}
			udp_csum = csum_subtract(udp_csum^0xffff, local_srcdst[:])
			udp_csum ^= 0xffff
			if udp_csum == 0 {
				udp_csum = 0xffff
			}
			be.PutUint16(pkt[pb.data+UDP_CSUM:pb.data+UDP_CSUM+2], udp_csum)
		}

	case ICMP, ICMPv6: // convert type/code and replace inner IP packet with IPREF packet

		if (pb.typ == PKT_IPv4) != (*proto == ICMP) {
			log.err("encap:   icmp version (%v) does not match IP version (IPv%v), dropping",
				ip_proto_name(*proto), ipver)
			return false
		}
		*proto = ICMP

		if icmp_depth <= 0 {
			log.err("encap:   icmp depth limit reached, dropping")
			return false
		}
		if frag_off != 0 {
			// TODO This will let non-initial fragments of ICMP_ENCAP packets through.
			break
		}
		if pb.len() < ICMP_DATA {
			log.err("encap:   invalid icmp packet, dropping")
			return false
		}

		typ, code, action := icmp_encap(pb.typ, pkt[pb.data+ICMP_TYPE], pkt[pb.data+ICMP_CODE])
		switch action {

		case ICMP_DROP:

			log.err("encap:   unsupported icmp type/code (%v/%v/%v), dropping",
				pb.typ,
				pkt[pb.data+ICMP_TYPE],
				pkt[pb.data+ICMP_CODE])
			return false

		case ICMP_NO_ENCAP:

			icmp_csum := be.Uint16(pkt[pb.data+ICMP_CSUM:pb.data+ICMP_CSUM+2]) ^ 0xffff
			icmp_csum = csum_subtract(icmp_csum, pkt[pb.data+ICMP_TYPE:pb.data+ICMP_CODE+1])
			pkt[pb.data+ICMP_TYPE] = typ
			pkt[pb.data+ICMP_CODE] = code
			icmp_csum = csum_add(icmp_csum, pkt[pb.data+ICMP_TYPE:pb.data+ICMP_CODE+1])
			if pb.typ == PKT_IPv6 {
				if frag_if {
					log.err("encap:   can't calculate checksum for ICMPv6 packet (fragment), dropping")
					return false
				}
				if pb.len() >> 16 != 0  {
					log.err("encap:   can't calculate checksum for ICMPv6 packet (too big), dropping")
					return false
				}
				icmp_csum = csum_subtract(icmp_csum, local_srcdst)
				var pseudo [4]byte
				be.PutUint16(pseudo[:2], uint16(pb.len()))
				pseudo[3] = ICMPv6
				icmp_csum = csum_subtract(icmp_csum, pseudo[:])
			}
			be.PutUint16(pkt[pb.data+ICMP_CSUM:pb.data+ICMP_CSUM+2], icmp_csum^0xffff)

		case ICMP_ENCAP:

			// encap inner packet
			if frag_if {
				log.err("encap:   fragmented icmp packet that needs inner encap, dropping")
				return false
			}
			inner_pb := PktBuf{
				pkt: pkt[pb.data+ICMP_DATA:],
				typ: pb.typ,
				data: 0,
				tail: min(pb.len() - ICMP_DATA, ICMP_ENCAP_MAX_LEN)}
			if ipref_encap(&inner_pb, true, icmp_depth - 1, false, false) != ACCEPT {
				log.err("encap:   dropping icmp due to invalid inner packet")
				return false
			}
			if inner_pb.data != 0 {
				copy(pkt[pb.data+ICMP_DATA:], inner_pb.pkt[inner_pb.data:inner_pb.tail])
			}
			pb.tail = inner_pb.tail - inner_pb.data + pb.data + ICMP_DATA

			// adjust mtu
			if code == IPREF_ICMP_FRAG_NEEDED {
				if pb.typ == PKT_IPv6 {
					upper_mtu := be.Uint16(pkt[pb.data+ICMP_BODY:pb.data+ICMP_BODY+2])
					if upper_mtu != 0 {
						// The standard does actually allow 32-bit mtu, but we don't support it.
						log.err("encap:   bad MTU in ICMPv6 Packet Too Big, dropping")
						return false
					}
				}
				mtu := int(be.Uint16(pkt[pb.data+ICMP_MTU:pb.data+ICMP_MTU+2]))
				if ipver == PKT_IPv4 {
					mtu -= IPv4_HDR_MIN_LEN
				} else {
					mtu -= IPv6_HDR_MIN_LEN + IPv6_FRAG_HDR_LEN
				}
				mtu += IPREF_HDR_MIN_LEN
				if mtu <= 0 || mtu >> 16 != 0 {
					log.err("encap:   bad mtu in icmp dest unreach, dropping")
					return false
				}
				be.PutUint16(pkt[pb.data+ICMP_MTU:pb.data+ICMP_MTU+2], uint16(mtu))
			}

			// adjust type/code and recalculate checksum
			pkt[pb.data+ICMP_TYPE] = typ
			pkt[pb.data+ICMP_CODE] = code
			be.PutUint16(pkt[pb.data+ICMP_CSUM:pb.data+ICMP_CSUM+2], 0)
			icmp_csum := csum_add(0, pkt[pb.data:pb.tail])
			be.PutUint16(pkt[pb.data+ICMP_CSUM:pb.data+ICMP_CSUM+2], icmp_csum^0xffff)

		default:

			panic("unexpected")
		}

	default:

		log.err("encap:   unsupported layer 4 protocol (%v) in IPv%v, dropping",
			ip_proto_name(*proto), ipver)
	}

	return true
}

func (mtun *MapTun) get_src_addr(src IpRef) (IP, bool) {

	if src.ip == cli.gw_ip && src.ref == cli.gw_ref {
		return cli.ea_gwip, true // TODO TEMP
	}
	if !netip.Addr(src.ip).IsGlobalUnicast() {
		log.err("deencap: source (%v) IP isn't valid unicast, dropping", src)
		return IP{}, false
	}
	if rec, found := mtun.get_src_iprec(src.ip, src.ref); found {
		return rec.ip, true
	}
	log.err("deencap: unknown src ipref address  %v, dropping", src)
	return IP{}, false
}

func (mtun *MapTun) get_dst_addr(dst IpRef) (IP, bool) {

	if dst.ip == cli.gw_ip && dst.ref == cli.gw_ref {
		return cli.ea_gwip, true
	}
	if !netip.Addr(dst.ip).IsGlobalUnicast() {
		log.err("deencap: destination (%v) IP isn't valid unicast, dropping", dst)
		return IP{}, false
	}
	if rec, found := mtun.get_dst_ip(dst.ip, dst.ref); found {
		return rec, true
	}
	log.err("deencap: unknown local destination  %v, dropping", dst)
	return IP{}, false
}

func (mtun *MapTun) get_srcdst_ip_rev(src, dst IpRef, rev bool) (
	src_ea, dst_ip IP, status int) {

	if rev {
		src, dst = dst, src
	}
	var ok bool
	if src_ea, ok = mtun.get_src_addr(src); !ok {
		status = ENCAP_MAP_UNKNOWN_SRC
		goto fail
	}
	if dst_ip, ok = mtun.get_dst_addr(dst); !ok {
		status = ENCAP_MAP_UNKNOWN_DST
		goto fail
	}
	if rev {
		src_ea, dst_ip = dst_ip, src_ea
	}
	status = ENCAP_MAP_SUCCESS
	return
fail:
	src_ea, dst_ip = IP{}, IP{}
	if rev {
		status ^= 1 // swap src/dst
	}
	return
}

// De-encapsulate an IPREF packet, replacing the IPREF header with an IP header.
// Returns ACCEPT (on success), DROP (on error), or STOLEN (unless steal is
// false). If steal is true, then an ICMP response may be returned to the sender
// if the destination is unreachable.
func ipref_deencap(pb *PktBuf, rev_srcdst bool, icmp_depth int, dec_ttl, steal bool) int {

	if pb.typ != PKT_IPREF {
		log.fatal("deencap: not an ipref packet")
	}
	pkt := pb.pkt

	// decode IPREF header

	if !pb.ipref_ok() {
		log.err("deencap: invalid ipref packet, dropping")
		return DROP
	}
	frag_if := pb.ipref_if()
	frag_df := pb.ipref_df()
	var frag_off int
	var frag_mf bool
	var ident uint32
	if frag_if {
		frag_field := be.Uint16(pkt[pb.data+6:pb.data+8])
		if pkt[pb.data+4] != 0 || pkt[pb.data+5] != 0 || frag_field & 0x6 != 0 {
			log.err("deencap: invalid ipref packet, dropping")
			return DROP
		}
		frag_off = int(frag_field &^ 1)
		frag_mf = frag_field & 1 != 0
		ident = be.Uint32(pkt[pb.data+8:pb.data+12])
	}
	ttl := pb.ipref_ttl()
	proto := pb.ipref_proto()
	src := pb.ipref_src()
	dst := pb.ipref_dst()
	l4 := pb.data + pb.ipref_hdr_len()
	l4_pkt_len := pb.tail - l4
	frag_end := frag_off + l4_pkt_len // the position of the end of the packet in the l4 datagram
	// We don't enforce this, because we still want to de-encapsulate packets
	// which have been truncated, which might happen with packets inside ICMP.
	// if frag_if && (l4_pkt_len & 0x7 != 0 && frag_mf) {
	// 	log.err("deencap: invalid packet (fragmentation), dropping")
	// 	return DROP
	// }

	// decrement ttl

	if dec_ttl {
		if ttl > 0 {
			ttl -= 1
		}
		if ttl <= 0 {
			log.trace("encap:   ttl reached zero:  %v  %v", src, dst)
			if steal {
				pb.icmp.typ = IPREF_ICMP_TIME_EXCEEDED
				pb.icmp.code = IPREF_ICMP_EXC_TTL
				pb.icmp.mtu = 0
				pb.icmp.ours = false
				icmpreq <- pb
				return STOLEN
			}
			return DROP
		}
	}

	// map addresses

	src_ea, dst_ip, map_status := map_tun.get_srcdst_ip_rev(src, dst, rev_srcdst)
	switch {
	case map_status == ENCAP_MAP_SUCCESS:
	case map_status == ENCAP_MAP_UNKNOWN_SRC:
		return DROP
	case map_status == ENCAP_MAP_UNKNOWN_DST:
		if steal {
			pb.icmp.typ = IPREF_ICMP_DEST_UNREACH
			pb.icmp.code = IPREF_ICMP_NET_UNREACH
			pb.icmp.mtu = 0
			pb.icmp.ours = false
			icmpreq <- pb
			return STOLEN
		}
		return DROP
	default:
		panic("unexpected")
	}
	var iplen int
	switch {
	case src_ea.Is4() && dst_ip.Is4():
		pb.typ = PKT_IPv4
		iplen = 4
	case src_ea.Is6() && dst_ip.Is6():
		pb.typ = PKT_IPv6
		iplen = 16
	default:
		panic("unexpected")
	}
	local_srcdst := make([]byte, iplen * 2)
	copy(local_srcdst[:iplen], src_ea.AsSlice())
	copy(local_srcdst[iplen:], dst_ip.AsSlice())

	// translate layer 4 packet

	pb.data, pb.tail = l4, l4 + l4_pkt_len
	if !ipref_deencap_l4(pb, local_srcdst, &proto,
		frag_if, frag_df, frag_mf, frag_off, frag_end,
		icmp_depth) {

		return DROP
	}
	l4, l4_pkt_len = pb.data, pb.len()

	// replace IPREF header with IP header

	switch pb.typ {

	case PKT_IPv4:

		if pb.data < IPv4_HDR_MIN_LEN {
			if len(pkt) < IPv4_HDR_MIN_LEN + pb.len() {
				log.err("deencap: not enough space in buffer for ip header, dropping")
				return DROP
			}
			// This should only happen for packets inside ICMP, which should be pretty small.
			copy(pb.pkt[IPv4_HDR_MIN_LEN:], pb.pkt[pb.data:pb.tail])
			pb.data, pb.tail = IPv4_HDR_MIN_LEN, pb.len()
		}
		pb.data -= IPv4_HDR_MIN_LEN

		pkt[pb.data+IP_VER] = 0x45
		pkt[pb.data+IPv4_DSCP] = 0
		if pb.len() >> 16 != 0 {
			log.err("deencap: packet too big, dropping")
			return DROP
		}
		be.PutUint16(pkt[pb.data+IPv4_LEN:pb.data+IPv4_LEN+2], uint16(pb.len()))
		be.PutUint16(pkt[pb.data+IPv4_ID:pb.data+IPv4_ID+2], uint16(ident))
		{
			frag_field := uint16(frag_off) >> 3
			if frag_df {
				frag_field |= 1 << 14
			}
			if frag_if && frag_mf {
				frag_field |= 1 << 13
			}
			be.PutUint16(pkt[pb.data+IPv4_FRAG:pb.data+IPv4_FRAG+2], frag_field)
		}
		pkt[pb.data+IPv4_TTL] = ttl
		pkt[pb.data+IPv4_PROTO] = proto
		be.PutUint16(pkt[pb.data+IPv4_CSUM:pb.data+IPv4_CSUM+2], 0)
		copy(pkt[pb.data+IPv4_SRC:pb.data+IPv4_DST+4], local_srcdst)

		// compute IP checksum
		ip_csum := csum_add(0, pkt[pb.data:pb.data+IPv4_HDR_MIN_LEN])
		be.PutUint16(pkt[pb.data+IPv4_CSUM:pb.data+IPv4_CSUM+2], ip_csum^0xffff)

	case PKT_IPv6:

		ip_hdr_len := IPv6_HDR_MIN_LEN
		if frag_if {
			ip_hdr_len += IPv6_FRAG_HDR_LEN
		}
		if pb.data < ip_hdr_len {
			if len(pkt) < ip_hdr_len + pb.len() {
				log.err("deencap: not enough space in buffer for ip header, dropping",
					pb.data, ip_hdr_len)
				return DROP
			}
			// This should only happen for packets inside ICMP, which should be pretty small.
			copy(pb.pkt[ip_hdr_len:], pb.pkt[pb.data:pb.tail])
			pb.data, pb.tail = ip_hdr_len, pb.len()
		}
		pb.data -= ip_hdr_len

		pkt[pb.data+IP_VER] = 0x60
		pkt[pb.data+1] = 0 // TODO Flow label?
		pkt[pb.data+2] = 0
		pkt[pb.data+3] = 0
		first_pld_len := l4_pkt_len
		if frag_if {
			first_pld_len += IPv6_FRAG_HDR_LEN
		}
		if first_pld_len >> 16 != 0 {
			log.err("deencap: packet too big, dropping")
			return DROP
		}
		be.PutUint16(pkt[pb.data+IPv6_PLD_LEN:pb.data+IPv6_PLD_LEN+2], uint16(first_pld_len))
		pkt[pb.data+IPv6_TTL] = ttl
		copy(pkt[pb.data+IPv6_SRC:pb.data+IPv6_DST+16], local_srcdst)
		if !frag_if {
			pkt[pb.data+IPv6_NEXT] = proto
		} else {
			pkt[pb.data+IPv6_NEXT] = IPv6_FRAG_EXT
			i := pb.data+IPv6_HDR_MIN_LEN
			pkt[i+IPv6_FRAG_NEXT] = proto
			pkt[i+IPv6_FRAG_RES1] = 0
			frag_field := uint16(frag_off) &^ 7
			if frag_mf {
				frag_field |= 1
			}
			be.PutUint16(pkt[i+IPv6_FRAG_OFF:i+IPv6_FRAG_OFF+2], frag_field)
			be.PutUint32(pkt[i+IPv6_FRAG_IDENT:i+IPv6_FRAG_IDENT+4], ident)
		}

	default:

		panic("unexpected")
	}

	return ACCEPT
}

// pb contains a layer 4 datagram (or a fragment thereof). pb.typ is the target
// layer 3 protocol: PKT_IPv4 or PKT_IPv6. Returns false (to drop) or true (on
// success).
func ipref_deencap_l4(pb *PktBuf,
	local_srcdst []byte, // Not modified; used for adjusting checksum
	proto *byte,
	frag_if, frag_df, frag_mf bool,
	frag_off, frag_end int,
	icmp_depth int) bool {

	pkt := pb.pkt

	switch *proto {

	case TCP: // add ip src/dst addresses to csum

		if frag_off >= TCP_CSUM+2 || frag_end < TCP_CSUM {
			break
		}
		if frag_end < TCP_CSUM {
			log.err("deencap: invalid tcp packet, dropping")
			return false
		}

		tcp_csum := be.Uint16(pkt[pb.data+TCP_CSUM-frag_off : pb.data+TCP_CSUM-frag_off+2])

		if tcp_csum != 0 {
			tcp_csum = csum_add(tcp_csum^0xffff, local_srcdst)
			be.PutUint16(pkt[pb.data+TCP_CSUM-frag_off:pb.data+TCP_CSUM-frag_off+2], tcp_csum^0xffff)
		}

	case UDP: // add ip src/dst addresses to csum

		if frag_off != 0 {
			break
		}
		if frag_end < UDP_HDR_LEN {
			log.err("deencap: invalid udp packet, dropping")
			return false
		}

		udp_csum := be.Uint16(pkt[pb.data+UDP_CSUM : pb.data+UDP_CSUM+2])

		if udp_csum != 0 {
			if udp_csum == 0xffff {
				udp_csum = 0
			}
			udp_csum = csum_add(udp_csum^0xffff, local_srcdst)
			udp_csum ^= 0xffff
			if udp_csum == 0 {
				udp_csum = 0xffff
			}
			be.PutUint16(pkt[pb.data+UDP_CSUM:pb.data+UDP_CSUM+2], udp_csum)
		}

	case ICMP: // convert type/code and replace inner IPREF packet with IP packet

		if pb.typ == PKT_IPv6 {
			*proto = ICMPv6
		}
		if icmp_depth <= 0 {
			log.err("deencap: icmp depth limit reached, dropping")
			return false
		}
		if frag_off != 0 {
			// TODO This will let non-initial fragments of ICMP_ENCAP packets through.
			break
		}
		if pb.len() < ICMP_DATA {
			log.err("deencap: invalid icmp packet, dropping")
			return false
		}

		typ, code, action := icmp_deencap(pb.typ, pkt[pb.data+ICMP_TYPE], pkt[pb.data+ICMP_CODE])
		switch action {

		case ICMP_DROP:

			log.err("deencap: unsupported icmp type/code (%v/%v/%v), dropping",
				pb.typ,
				pkt[pb.data+ICMP_TYPE],
				pkt[pb.data+ICMP_CODE])
			return false

		case ICMP_NO_ENCAP:

			icmp_csum := be.Uint16(pkt[pb.data+ICMP_CSUM:pb.data+ICMP_CSUM+2]) ^ 0xffff
			icmp_csum = csum_subtract(icmp_csum, pkt[pb.data+ICMP_TYPE:pb.data+ICMP_CODE+1])
			pkt[pb.data+ICMP_TYPE] = typ
			pkt[pb.data+ICMP_CODE] = code
			icmp_csum = csum_add(icmp_csum, pkt[pb.data+ICMP_TYPE:pb.data+ICMP_CODE+1])
			if pb.typ == PKT_IPv6 {
				if frag_if  {
					log.err("deencap: can't calculate checksum for ICMPv6 packet (fragment), dropping")
					return false
				}
				if pb.len() >> 16 != 0  {
					log.err("deencap: can't calculate checksum for ICMPv6 packet (too big), dropping")
					return false
				}
				icmp_csum = csum_add(icmp_csum, local_srcdst)
				var pseudo [4]byte
				be.PutUint16(pseudo[:2], uint16(pb.len()))
				pseudo[3] = ICMPv6
				icmp_csum = csum_add(icmp_csum, pseudo[:])
			}
			be.PutUint16(pkt[pb.data+ICMP_CSUM:pb.data+ICMP_CSUM+2], icmp_csum^0xffff)

		case ICMP_ENCAP:

			// deencap inner packet
			if frag_if {
				log.err("deencap: fragmented icmp packet that needs inner deencap, dropping")
				return false
			}
			inner_pb := PktBuf{
				pkt: pkt[pb.data+ICMP_DATA:],
				typ: PKT_IPREF,
				data: 0,
				tail: min(pb.len() - ICMP_DATA, ICMP_ENCAP_MAX_LEN)}
			if ipref_deencap(&inner_pb, true, icmp_depth - 1, false, false) != ACCEPT {
				log.err("deencap: dropping icmp due to invalid inner packet")
				return false
			}
			if inner_pb.data != 0 {
				copy(pkt[pb.data+ICMP_DATA:], inner_pb.pkt[inner_pb.data:inner_pb.tail])
			}
			pb.tail = inner_pb.tail - inner_pb.data + pb.data + ICMP_DATA

			// adjust mtu
			if pkt[pb.data+ICMP_CODE] == IPREF_ICMP_FRAG_NEEDED {
				mtu := int(be.Uint16(pkt[pb.data+ICMP_MTU:pb.data+ICMP_MTU+2]))
				mtu -= IPREF_HDR_MAX_LEN
				if pb.typ == PKT_IPv4 {
					mtu += IPv4_HDR_MIN_LEN
				} else {
					mtu += IPv6_HDR_MIN_LEN
				}
				if mtu <= 0 || mtu >> 16 != 0 {
					log.err("deencap: bad mtu in icmp dest unreach, dropping")
					return false
				}
				be.PutUint16(pkt[pb.data+ICMP_MTU:pb.data+ICMP_MTU+2], uint16(mtu))
			}

			// adjust type/code and recalculate checksum
			pkt[pb.data+ICMP_TYPE] = typ
			pkt[pb.data+ICMP_CODE] = code
			be.PutUint16(pkt[pb.data+ICMP_CSUM:pb.data+ICMP_CSUM+2], 0)
			var icmp_csum uint16
			switch pb.typ {
			case PKT_IPv4:
				icmp_csum = csum_add(0, pkt[pb.data:pb.tail])
			case PKT_IPv6:
				icmp_csum = csum_add(0, local_srcdst)
				var pseudo [4]byte
				if pb.len() >> 16 != 0 {
					log.err("deencap: can't calculate checksum for IPv6 packet (too big), dropping")
					return false
				}
				be.PutUint16(pseudo[:2], uint16(pb.len()))
				pseudo[3] = ICMPv6
				icmp_csum = csum_add(icmp_csum, pseudo[:])
				icmp_csum = csum_add(icmp_csum, pkt[pb.data:pb.tail])
			default:
				panic("unexpected")
			}
			be.PutUint16(pkt[pb.data+ICMP_CSUM:pb.data+ICMP_CSUM+2], icmp_csum^0xffff)

		default:

			panic("unexpected")
		}

	default:

		log.err("deencap: unsupported IPREF layer 4 protocol (%v), dropping", ip_proto_name(*proto))
		return false
	}

	return true
}

type IPREFFragInPlaceStatus int

const (
	IPREF_FRAG_IN_PLACE_NOT_NEEDED = IPREFFragInPlaceStatus(iota)
	IPREF_FRAG_IN_PLACE_SUCCESS    = IPREFFragInPlaceStatus(iota) // fragmented
	IPREF_FRAG_IN_PLACE_DF         = IPREFFragInPlaceStatus(iota) // DF bit set
	IPREF_FRAG_IN_PLACE_SPACE      = IPREFFragInPlaceStatus(iota) // not enough space
)

// mtu is the layer 5 mtu (the space we have for the IPREF packet, excluding
// IP/UDP header)
func ipref_frag_in_place(pb *PktBuf, mtu int) (
	sent int, trimmed int, orig_mf bool, status IPREFFragInPlaceStatus) {

	if pb.len() <= mtu {
		status = IPREF_FRAG_IN_PLACE_NOT_NEEDED
		return
	}

	if pb.ipref_df() {
		status = IPREF_FRAG_IN_PLACE_DF
		return
	}

	// Calculate sizes
	ipref_hdr_len := pb.ipref_hdr_len()
	l5_size := pb.len() - ipref_hdr_len
	sent = ((l5_size + 1) / 2 + 7) / 8 * 8
	if !pb.ipref_if() {
		ipref_hdr_len += 8 // we're going to need that space to add Fragment Info
	}
	if sent + ipref_hdr_len > mtu {
		sent = (mtu - ipref_hdr_len) / 8 * 8
	}
	trimmed = l5_size - sent
	if sent <= 0 || trimmed <= 0 {
		status = IPREF_FRAG_IN_PLACE_SPACE
		return
	}
	pb.tail -= trimmed

	frag_if, frag_off, frag_mf, ident := pb.ipref_frag()
	if !frag_if {
		orig_mf = false
		// Add Fragment Info.
		if pb.data < 8 {
			status = IPREF_FRAG_IN_PLACE_SPACE
			return
		}
		pb.pkt[pb.data] |= 2 // set IF
		pb.data -= 8
		copy(pb.pkt[pb.data:pb.data+4], pb.pkt[pb.data+8:])
		frag_if = true
		frag_off = 0
		frag_mf = true
		var identb [4]byte
		rand.Read(identb[:])
		ident = be.Uint32(identb[:])
	} else {
		orig_mf = frag_mf
		frag_mf = true
	}

	// Write Fragment Info.
	pb.pkt[pb.data+4] = 0
	pb.pkt[pb.data+5] = 0
	frag_field := uint16(frag_off)
	if frag_mf {
		frag_field |= 1
	}
	be.PutUint16(pb.pkt[pb.data+6:pb.data+8], frag_field)
	be.PutUint32(pb.pkt[pb.data+8:pb.data+12], uint32(ident))

	status = IPREF_FRAG_IN_PLACE_SUCCESS
	return
}

func ipref_undo_frag_in_place(pb *PktBuf, trimmed int, orig_mf bool) {

	if trimmed == 0 {
		return
	}
	pb.tail += trimmed
	_, frag_off, _, _ := pb.ipref_frag()
	if !orig_mf {
		pb.pkt[pb.data+7] &^= 1 // unset MF
		if frag_off == 0 {
			// Remove Fragment Info.
			copy(pb.pkt[pb.data+8:], pb.pkt[pb.data:pb.data+4])
			pb.data += 8
			pb.pkt[pb.data] &^= 2 // unset IF
		}
	}
}

func ipref_next_frag_in_place(pb *PktBuf, trimmed int, orig_mf bool) int {

	ipref_hdr_len := pb.ipref_hdr_len()
	sent := pb.len() - ipref_hdr_len
	if sent == 0 || sent & 7 != 0 {
		panic("sanity check failed")
	}

	// Move the header to just before the data that was trimmed/not yet sent.
	copy(pb.pkt[pb.tail-ipref_hdr_len:], pb.pkt[pb.data:pb.data+ipref_hdr_len])
	pb.data = pb.tail - ipref_hdr_len
	pb.tail += trimmed

	// Adjust Fragment Info.
	_, frag_off, _, _ := pb.ipref_frag()
	frag_off += sent
	frag_field := uint16(frag_off)
	if orig_mf {
		frag_field |= 1
	}
	be.PutUint16(pb.pkt[pb.data+6:pb.data+8], frag_field)

	return frag_off
}
