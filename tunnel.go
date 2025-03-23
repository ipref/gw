/* Copyright (c) 2018-2021 Waldemar Augustyn */

package main

import (
	"crypto/rand"
	rff "github.com/ipref/ref"
)

/* IPREF Tunnel Protocol */

const (
	ICMP_NO_ENCAP = iota
	ICMP_ENCAP
	ICMP_DROP

	ICMP_ENCAP_MAX_LEN = 576 // must be at least IPREF_HDR_MAX_LEN
	ICMP_ENCAP_MAX_DEPTH = 3

	ENCAP_MAP_SUCCESS = iota
	ENCAP_MAP_UNKNOWN_SRC
	ENCAP_MAP_UNKNOWN_DST
)

func icmpv4_action(icmp_type byte) int {
	// TODO Add more
	switch icmp_type {
	case ICMPv4_DEST_UNREACH, ICMPv4_TIME_EXCEEDED, ICMPv4_REDIRECT, ICMPv4_SOURCE_QUENCH:
		return ICMP_ENCAP
	case ICMPv4_ECHO_REPLY, ICMPv4_ECHO_REQUEST:
		return ICMP_NO_ENCAP
	default:
		return ICMP_DROP
	}
}

func (mgw *MapGw) get_srcdst_ipref(src, dst IP32) (
		iprefsrc, iprefdst IpRefRec, status int) {

	iprefsrc = mgw.get_src_ipref(src)
	if iprefsrc.ip == 0 {
		log.err("encap:   unknown src address: %v %v, dropping", src, dst)
		status = ENCAP_MAP_UNKNOWN_SRC
		return
	}

	iprefdst = mgw.get_dst_ipref(dst)
	if iprefdst.ip == 0 {
		log.err("encap:   unknown dst address: %v %v, sending icmp", src, dst)
		status = ENCAP_MAP_UNKNOWN_DST
		return
	}

	status = ENCAP_MAP_SUCCESS
	return
}

func (mgw *MapGw) get_srcdst_ipref_rev(src, dst IP32, rev bool) (
		iprefsrc, iprefdst IpRefRec, status int) {

	if rev {
		iprefdst, iprefsrc, status = mgw.get_srcdst_ipref(dst, src)
	} else {
		iprefsrc, iprefdst, status = mgw.get_srcdst_ipref(src, dst)
	}
	return
}

// Encapsulate an IP packet, replacing the IP header with an IPREF header.
// Returns ACCEPT (on success), DROP (on error), or STOLEN (unless steal is
// false). If steal is true, then an ICMP response may be returned to the sender
// if the destination is unreachable.
func ipref_encap(pb *PktBuf, rev_srcdst bool, icmp_depth int, steal bool) int {

	if pb.typ != PKT_IPv4 {
		log.fatal("encap:   not an IPv4 packet")
	}
	pkt := pb.pkt

	if pb.tail - pb.data < IPv4_HDR_MIN_LEN {
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
	if ip_pkt_len < pb.tail - pb.data {
		log.err("encap:   invalid packet (bad length field), dropping")
		return DROP
	}
	ident := be.Uint16(pkt[pb.data+IPv4_ID:pb.data+IPv4_ID+2])
	frag_field := be.Uint16(pkt[pb.data+IPv4_FRAG:pb.data+IPv4_FRAG+2])
	frag_df := frag_field & 0x4000 != 0
	frag_mf := frag_field & 0x2000 != 0
	frag_off := int((frag_field & 0x1fff) << 3)
	frag_if := frag_off != 0 || frag_mf
	ttl := pkt[pb.data+IPv4_TTL]
	proto := pkt[pb.data+IPv4_PROTO]
	var srcdst [8]byte
	copy(srcdst[:], pkt[pb.data+IPv4_SRC:])
	src := IP32(be.Uint32(pkt[pb.data+IPv4_SRC : pb.data+IPv4_SRC+4]))
	dst := IP32(be.Uint32(pkt[pb.data+IPv4_DST : pb.data+IPv4_DST+4]))
	l4 := pb.data + IPv4_HDR_MIN_LEN
	l4_pkt_len := pb.tail - l4
	frag_end := frag_off + l4_pkt_len // the position of the end of the packet in the l4 datagram
	if l4_pkt_len & 0x7 != 0 && frag_mf {
		log.err("encap:   invalid packet (fragmentation), dropping")
		return DROP
	}

	iprefsrc, iprefdst, map_status := map_gw.get_srcdst_ipref_rev(src, dst, rev_srcdst)
	switch {
	case map_status == ENCAP_MAP_SUCCESS:
	case map_status == ENCAP_MAP_UNKNOWN_DST && steal:
		pb.icmp.typ = ICMPv4_DEST_UNREACH
		pb.icmp.code = ICMPv4_NET_UNREACH
		pb.icmp.mtu = 0
		pb.icmp.ours = true
		icmpreq <- pb
		return STOLEN
	default:
		return DROP
	}

	// get soft state and set pb src/dst

	soft, ok := map_gw.soft[iprefdst.ip]
	if !ok {
		soft.init(iprefdst.ip) // missing soft state, use defaults
	}
	pb.src = iprefsrc.ip
	pb.dst = iprefdst.ip
	pb.sport = soft.port
	pb.dport = IPREF_PORT // TODO

	// replace IP header with IPREF header

	reflen := max(min_reflen(iprefsrc.ref), min_reflen(iprefdst.ref))
	ipref_hdr_len := 12 + reflen * 2
	if frag_if {
		ipref_hdr_len += 8
	}
	if l4 < ipref_hdr_len {
		if len(pkt) < ipref_hdr_len + l4_pkt_len {
			log.err("encap:   not enough space for ipref header, dropping")
			return DROP
		} else {
			// This should only happen for packets inside ICMP, which should be pretty small.
			copy(pkt[ipref_hdr_len:], pkt[l4:pb.tail])
			l4 = ipref_hdr_len
		}
	}
	pb.data = l4 - ipref_hdr_len
	pb.typ = PKT_IPREF

	pkt[pb.data] = (0x1 << 4) | encode_reflen(reflen) << 2
	if frag_if {
		pkt[pb.data] |= 1 << 1
	}
	if frag_df {
		pkt[pb.data] |= 1 << 0
	}
	pkt[pb.data+1] = 0
	pkt[pb.data+2] = ttl
	pkt[pb.data+3] = proto
	i := pb.data + 4
	if frag_if {
		pkt[i] = 0
		pkt[i+1] = 0
		frag_field = uint16(frag_off)
		if frag_mf {
			frag_field |= 1
		}
		be.PutUint16(pkt[i+2:i+4], frag_field)
		be.PutUint32(pkt[i+4:i+8], uint32(ident))
		i += 8
	}

	be.PutUint32(pkt[i:i+4], uint32(iprefsrc.ip))
	i += 4
	be.PutUint32(pkt[i:i+4], uint32(iprefdst.ip))
	i += 4
	encode_ref(pkt[i:i+reflen], iprefsrc.ref)
	i += reflen
	encode_ref(pkt[i:i+reflen], iprefdst.ref)

	// adjust layer 4 headers

	switch proto {

	case TCP: // subtract ip src/dst addresses from csum

		if frag_off >= TCP_CSUM+2 || frag_end < TCP_CSUM {
			break
		}
		if frag_end < TCP_CSUM+2 {
			log.err("encap:   invalid tcp packet, dropping")
			return DROP
		}

		tcp_csum := be.Uint16(pkt[l4+TCP_CSUM-frag_off : l4+TCP_CSUM-frag_off+2])

		if tcp_csum != 0 {
			tcp_csum = csum_subtract(tcp_csum^0xffff, srcdst[:])
			be.PutUint16(pkt[l4+TCP_CSUM-frag_off:l4+TCP_CSUM-frag_off+2], tcp_csum^0xffff)
		}

	case UDP: // subtract ip src/dst addresses from csum

		if frag_off != 0 {
			break
		}
		if frag_end < UDP_HDR_LEN {
			log.err("encap:   invalid udp packet, dropping")
			return DROP
		}

		udp_csum := be.Uint16(pkt[l4+UDP_CSUM : l4+UDP_CSUM+2])

		if udp_csum != 0 {
			udp_csum = csum_subtract(udp_csum^0xffff, srcdst[:])
			be.PutUint16(pkt[l4+UDP_CSUM:l4+UDP_CSUM+2], udp_csum^0xffff)
		}

	case ICMP: // replace inner ip packet with ipref packet

		if icmp_depth <= 0 {
			log.err("encap:   icmp depth limit reached, dropping")
			return DROP
		}
		if frag_off != 0 {
			// TODO This will let non-initial fragments of ICMP_ENCAP packets through.
			break
		}
		if l4_pkt_len < ICMP_DATA {
			log.err("encap:   invalid icmp packet, dropping")
			return DROP
		}

		switch icmpv4_action(pkt[l4+ICMP_TYPE]) {

		case ICMP_DROP:

			log.err("encap:   unrecognized icmp type (%v)", pkt[l4+ICMP_TYPE])
			return DROP

		case ICMP_ENCAP:

			if frag_if {
				log.err("encap:   fragmented icmp packet that needs inner encap, dropping")
				return DROP
			}
			inner_pb := PktBuf{
				pkt: pkt[l4+ICMP_DATA:],
				typ: PKT_IPv4,
				data: 0,
				tail: min(l4_pkt_len - ICMP_DATA, ICMP_ENCAP_MAX_LEN)}
			if ipref_encap(&inner_pb, true, icmp_depth - 1, false) != ACCEPT {
				log.err("encap:   dropping icmp due to invalid inner packet")
				return DROP
			}
			if inner_pb.data != 0 {
				copy(pkt[l4+ICMP_DATA:], inner_pb.pkt[inner_pb.data:inner_pb.tail])
			}
			pb.tail = inner_pb.tail - inner_pb.data + l4 + ICMP_DATA
			pkt[l4+ICMP_CSUM] = 0
			pkt[l4+ICMP_CSUM+1] = 0
			icmp_csum := csum_add(0, pkt[l4:pb.tail])
			be.PutUint16(pkt[l4+ICMP_CSUM:l4+ICMP_CSUM+2], icmp_csum^0xffff)
		}
	}

	return ACCEPT
}

func (mtun *MapTun) get_srcdst_ip(sref_ip IP32, sref rff.Ref,
		dref_ip IP32, dref rff.Ref) (src_ea, dst_ip IP32, status int) {

	src_ea = IP32(0)
	if iprec := mtun.get_src_iprec(sref_ip, sref); iprec != nil {
		src_ea = iprec.ip
	}
	if src_ea == 0 {
		log.err("deencap: unknown src ipref address  %v + %v, dropping",
			sref_ip, sref)
		status = ENCAP_MAP_UNKNOWN_SRC
		return // couldn't assign ea for some reason
	}

	dst_ip = mtun.get_dst_ip(dref_ip, dref)
	if dst_ip == 0 {
		log.err("deencap: unknown local destination  %v + %v, sending icmp",
			dref_ip, &dref)
		status = ENCAP_MAP_UNKNOWN_DST
		return
	}

	status = ENCAP_MAP_SUCCESS
	return
}

func (mtun *MapTun) get_srcdst_ip_rev(sref_ip IP32, sref rff.Ref,
		dref_ip IP32, dref rff.Ref, rev bool) (src_ea, dst_ip IP32, status int) {

	if rev {
		dst_ip, src_ea, status = mtun.get_srcdst_ip(dref_ip, dref, sref_ip, sref)
	} else {
		src_ea, dst_ip, status = mtun.get_srcdst_ip(sref_ip, sref, dref_ip, dref)
	}
	return
}

// De-encapsulate an IPREF packet, replacing the IPREF header with an IP header.
// Returns ACCEPT (on success), DROP (on error), or STOLEN (unless steal is
// false). If steal is true, then an ICMP response may be returned to the sender
// if the destination is unreachable.
func ipref_deencap(pb *PktBuf, update_soft bool, rev_srcdst bool,
	icmp_depth int, steal bool) int {

	if pb.typ != PKT_IPREF {
		log.fatal("deencap: not an ipref packet")
	}
	pkt := pb.pkt

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
	sref_ip := IP32(be.Uint32(pb.ipref_sref_ip()))
	dref_ip := IP32(be.Uint32(pb.ipref_dref_ip()))
	sref := pb.ipref_sref()
	dref := pb.ipref_dref()
	l4 := pb.data + pb.ipref_hdr_len()
	l4_pkt_len := pb.tail - l4
	frag_end := frag_off + l4_pkt_len // the position of the end of the packet in the l4 datagram
	if l4_pkt_len & 0x7 != 0 && frag_mf {
		log.err("deencap: invalid packet (fragmentation), dropping")
		return DROP
	}

	// map addresses

	src_ea, dst_ip, map_status := map_tun.get_srcdst_ip_rev(sref_ip, sref, dref_ip, dref, rev_srcdst)
	switch {
	case map_status == ENCAP_MAP_SUCCESS:
	case map_status == ENCAP_MAP_UNKNOWN_DST && steal:
		pb.icmp.typ = ICMPv4_DEST_UNREACH
		pb.icmp.code = ICMPv4_NET_UNREACH
		pb.icmp.mtu = 0
		pb.icmp.ours = false
		icmpreq <- pb
		return STOLEN
	default:
		return DROP
	}

	// update soft state and tell the other forwarder if changed

	if update_soft {

		soft, ok := map_tun.soft[pb.src]
		if !ok {
			soft.init(pb.src)
			soft.port = 0 // force change
		}

		if soft.gw != pb.src {
			log.err("deencap: soft record gw %v does not match src %v, resetting", soft.gw, pb.src)
			soft.init(pb.src)
			soft.port = 0 // force change
		}

		if soft.port != pb.sport {
			soft.port = pb.sport
			map_tun.set_soft(pb.src, soft)
		}
	}

	// replace IPREF header with IP header

	if l4 < IPv4_HDR_MIN_LEN { // this should be impossible
		log.err("deencap: not enough space for ip header, dropping")
		return DROP
	}
	pb.data = l4 - IPv4_HDR_MIN_LEN
	pb.typ = PKT_IPv4

	pkt[pb.data+IP_VER] = 0x45
	pkt[pb.data+IPv4_DSCP] = 0
	if (pb.tail - pb.data) >> 16 != 0 {
		log.err("deencap: packet too large")
		return DROP
	}
	be.PutUint16(pkt[pb.data+IPv4_LEN:pb.data+IPv4_LEN+2], uint16(pb.tail - pb.data))
	be.PutUint16(pkt[pb.data+IPv4_ID:pb.data+IPv4_ID+2], uint16(ident))
	{
		frag_field := uint16(frag_off) >> 3
		if frag_df {
			frag_field |= 1 << 14
		}
		if frag_mf {
			frag_field |= 1 << 13
		}
		be.PutUint16(pkt[pb.data+IPv4_FRAG:pb.data+IPv4_FRAG+2], frag_field)
	}
	pkt[pb.data+IPv4_TTL] = ttl
	pkt[pb.data+IPv4_PROTO] = proto
	be.PutUint16(pkt[pb.data+IPv4_CSUM:pb.data+IPv4_CSUM+2], 0)
	be.PutUint32(pkt[pb.data+IPv4_SRC:pb.data+IPv4_SRC+4], uint32(src_ea))
	be.PutUint32(pkt[pb.data+IPv4_DST:pb.data+IPv4_DST+4], uint32(dst_ip))

	// compute IP checksum
	ip_csum := csum_add(0, pkt[pb.data:pb.data+IPv4_HDR_MIN_LEN])
	be.PutUint16(pkt[pb.data+IPv4_CSUM:pb.data+IPv4_CSUM+2], ip_csum^0xffff)

	// adjust layer 4 headers

	switch proto {

	case TCP: // add ip src/dst addresses to csum

		if frag_off >= TCP_CSUM+2 || frag_end < TCP_CSUM {
			break
		}
		if frag_end < TCP_CSUM {
			log.err("deencap: invalid tcp packet, dropping")
			return DROP
		}

		tcp_csum := be.Uint16(pkt[l4+TCP_CSUM-frag_off : l4+TCP_CSUM-frag_off+2])

		if tcp_csum != 0 {
			tcp_csum = csum_add(tcp_csum^0xffff, pkt[pb.data+IPv4_SRC:pb.data+IPv4_DST+4])
			be.PutUint16(pkt[l4+TCP_CSUM-frag_off:l4+TCP_CSUM-frag_off+2], tcp_csum^0xffff)
		}

	case UDP: // add ip src/dst addresses to csum

		if frag_off != 0 {
			break
		}
		if frag_end < UDP_HDR_LEN {
			log.err("deencap: invalid udp packet, dropping")
			return DROP
		}

		udp_csum := be.Uint16(pkt[l4+UDP_CSUM : l4+UDP_CSUM+2])

		if udp_csum != 0 {
			udp_csum = csum_add(udp_csum^0xffff, pkt[pb.data+IPv4_SRC:pb.data+IPv4_DST+4])
			be.PutUint16(pkt[l4+UDP_CSUM:l4+UDP_CSUM+2], udp_csum^0xffff)
		}

	case ICMP: // replace inner ipref packet with ip packet

		if icmp_depth <= 0 {
			log.err("deencap: icmp depth limit reached, dropping")
			return DROP
		}
		if frag_off != 0 {
			// TODO This will let non-initial fragments of ICMP_ENCAP packets through.
			break
		}
		if l4_pkt_len < ICMP_DATA {
			log.err("deencap: invalid icmp packet, dropping")
			return DROP
		}

		switch icmpv4_action(pkt[l4+ICMP_TYPE]) {

		case ICMP_DROP:

			log.err("deencap: unrecognized icmp type (%v)", pkt[l4+ICMP_TYPE])
			return DROP

		case ICMP_ENCAP:

			if frag_if {
				log.err("deencap: fragmented icmp packet that needs inner deencap, dropping")
				return DROP
			}
			inner_pb := PktBuf{
				pkt: pkt[l4+ICMP_DATA:],
				typ: PKT_IPREF,
				data: 0,
				tail: min(l4_pkt_len - ICMP_DATA, ICMP_ENCAP_MAX_LEN)}
			if ipref_deencap(&inner_pb, false, true, icmp_depth - 1, false) != ACCEPT {
				log.err("deencap: dropping icmp due to invalid inner packet")
				return DROP
			}
			if inner_pb.data != 0 {
				copy(pkt[l4+ICMP_DATA:], inner_pb.pkt[inner_pb.data:inner_pb.tail])
			}
			pb.tail = inner_pb.tail - inner_pb.data + l4 + ICMP_DATA
			pkt[l4+ICMP_CSUM] = 0
			pkt[l4+ICMP_CSUM+1] = 0
			icmp_csum := csum_add(0, pkt[l4:pb.tail])
			be.PutUint16(pkt[l4+ICMP_CSUM:l4+ICMP_CSUM+2], icmp_csum^0xffff)
		}
	}

	return ACCEPT
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
