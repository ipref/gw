/* Copyright (c) 2018-2021 Waldemar Augustyn */

package main

import rff "github.com/ipref/ref"

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

const (
	ICMP_NO_ENCAP = iota
	ICMP_ENCAP
	ICMP_DROP
)

func icmp_action(icmp_type byte) int {
	// TODO Add more
	switch icmp_type {
	case ICMP_DEST_UNREACH, ICMP_TIME_EXCEEDED, ICMP_REDIRECT, ICMP_SOURCE_QUENCH:
		return ICMP_ENCAP
	case ICMP_ECHO_REPLY, ICMP_ECHO_REQUEST:
		return ICMP_NO_ENCAP
	default:
		return ICMP_DROP
	}
}

func (mgw *MapGw) get_srcdst_ipref(src, dst IP32) (
		iprefsrc, iprefdst IpRefRec, ok bool) {

	iprefsrc = mgw.get_src_ipref(src)
	if iprefsrc.ip == 0 {
		log.err("encap:   unknown src address: %v %v, dropping", src, dst)
		return
	}

	iprefdst = mgw.get_dst_ipref(dst)
	if iprefdst.ip == 0 {
		log.err("encap:   unknown dst address: %v %v, sending icmp", src, dst)
		// TODO
		return
		// pb.icmp.typ = ICMP_DEST_UNREACH
		// pb.icmp.code = ICMP_NET_UNREACH
		// pb.icmp.mtu = 0
		// icmpreq <- pb
	}

	ok = true
	return
}

func (mgw *MapGw) get_srcdst_ipref_rev(src, dst IP32, rev bool) (
		iprefsrc, iprefdst IpRefRec, ok bool) {

	if rev {
		iprefdst, iprefsrc, ok = mgw.get_srcdst_ipref(dst, src)
	} else {
		iprefsrc, iprefdst, ok = mgw.get_srcdst_ipref(src, dst)
	}
	return
}

// Encapsulate an IP packet, replacing the IP header with an IPREF header.
func ipref_encap(pb *PktBuf, rev_srcdst bool, icmp_depth int) bool {

	if pb.typ != PKT_IP {
		log.fatal("encap:   not an ip packet")
	}
	pkt := pb.pkt

	if pb.tail - pb.data < IP_HDR_MIN_LEN {
		log.err("encap:   invalid packet (too small), dropping")
		return false
	}
	if (pkt[pb.data+IP_VER] & 0xf0 != 0x40) {
		log.err("encap:   packet is not IPv4, dropping")
		return false
	}
	if (pkt[pb.data+IP_VER] & 0x0f != 5) {
		log.err("encap:   packet has options, dropping")
		return false
	}
	ip_pkt_len := int(be.Uint16(pkt[pb.data+IP_LEN:pb.data+IP_LEN+2]))
	if ip_pkt_len != pb.tail - pb.data {
		log.err("encap:   invalid packet (bad length field), dropping")
		return false
	}
	ident := be.Uint16(pkt[pb.data+IP_ID:pb.data+IP_ID+2])
	frag_field := be.Uint16(pkt[pb.data+IP_FRAG:pb.data+IP_FRAG+2])
	frag_df := frag_field & 0x4000 != 0
	frag_mf := frag_field & 0x2000 != 0
	frag_off := int((frag_field & 0x1fff) << 3)
	frag_if := frag_off != 0 || frag_mf
	ttl := pkt[pb.data+IP_TTL]
	proto := pkt[pb.data+IP_PROTO]
	var srcdst [8]byte
	copy(srcdst[:], pkt[pb.data+IP_SRC:])
	src := IP32(be.Uint32(pkt[pb.data+IP_SRC : pb.data+IP_SRC+4]))
	dst := IP32(be.Uint32(pkt[pb.data+IP_DST : pb.data+IP_DST+4]))
	l4 := pb.data + IP_HDR_MIN_LEN
	l4_pkt_len := pb.tail - l4
	frag_end := frag_off + l4_pkt_len // the position of the end of the packet in the l4 datagram
	if l4_pkt_len & 0x7 != 0 && frag_mf {
		log.err("encap:   invalid packet (fragmentation), dropping")
		return false
	}

	iprefsrc, iprefdst, ok := map_gw.get_srcdst_ipref_rev(src, dst, rev_srcdst)
	if !ok {
		return false
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
			return false
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
			return false
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
			return false
		}

		udp_csum := be.Uint16(pkt[l4+UDP_CSUM : l4+UDP_CSUM+2])

		if udp_csum != 0 {
			udp_csum = csum_subtract(udp_csum^0xffff, srcdst[:])
			be.PutUint16(pkt[l4+UDP_CSUM:l4+UDP_CSUM+2], udp_csum^0xffff)
		}

	case ICMP: // replace inner ip packet with ipref packet

		if icmp_depth <= 0 {
			log.err("encap:   icmp depth limit reached, dropping")
			return false
		}
		if frag_off != 0 {
			// TODO This will let non-initial fragments of ICMP_ENCAP packets through.
			break
		}
		if l4_pkt_len < ICMP_DATA {
			log.err("encap:   invalid icmp packet, dropping")
			return false
		}

		switch icmp_action(pkt[l4+ICMP_TYPE]) {

		case ICMP_DROP:

			log.err("encap:   unrecognized icmp type (%v)", pkt[l4+ICMP_TYPE])
			return false

		case ICMP_ENCAP:

			if frag_if {
				log.err("encap:   fragmented icmp packet that needs inner encap, dropping")
				return false
			}
			inner_pb := PktBuf{
				pkt: pkt[l4+ICMP_DATA:],
				typ: PKT_IP,
				data: 0,
				tail: min(l4_pkt_len - ICMP_DATA, 576)}
			if !ipref_encap(&inner_pb, true, icmp_depth - 1) {
				log.err("encap:   dropping icmp due to invalid inner packet")
				return false
			}
			if inner_pb.data != 0 {
				copy(pkt[l4+ICMP_DATA:], inner_pb.pkt[inner_pb.data:inner_pb.tail])
			}
			pb.tail = inner_pb.tail - inner_pb.data + l4 + ICMP_DATA
		}
	}

	return true
}

func (mtun *MapTun) get_srcdst_ip(sref_ip IP32, sref rff.Ref,
		dref_ip IP32, dref rff.Ref) (src_ea, dst_ip IP32, ok bool) {

	src_ea = IP32(0)
	if iprec := mtun.get_src_iprec(sref_ip, sref); iprec != nil {
		src_ea = iprec.ip
	}
	if src_ea == 0 {
		log.err("deencap: unknown src ipref address  %v + %v, dropping",
			sref_ip, sref)
		return // couldn't assign ea for some reason
	}

	dst_ip = mtun.get_dst_ip(dref_ip, dref)
	if dst_ip == 0 {
		log.err("deencap: unknown local destination  %v + %v, dropping",
			dref_ip, &dref)
		return
	}

	ok = true
	return
}

func (mtun *MapTun) get_srcdst_ip_rev(sref_ip IP32, sref rff.Ref,
		dref_ip IP32, dref rff.Ref, rev bool) (src_ea, dst_ip IP32, ok bool) {

	if rev {
		dst_ip, src_ea, ok = mtun.get_srcdst_ip(dref_ip, dref, sref_ip, sref)
	} else {
		src_ea, dst_ip, ok = mtun.get_srcdst_ip(sref_ip, sref, dref_ip, dref)
	}
	return
}

// De-encapsulate an IPREF packet, replacing the IPREF header with an IP header.
func ipref_deencap(pb *PktBuf, update_soft bool, rev_srcdst bool, icmp_depth int) bool {

	if pb.typ != PKT_IPREF {
		log.fatal("deencap: not an ipref packet")
	}
	pkt := pb.pkt

	if !pb.ipref_ok() {
		log.err("deencap: invalid ipref packet, dropping")
		return false
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
			return false
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
		return false
	}

	// map addresses

	src_ea, dst_ip, ok := map_tun.get_srcdst_ip_rev(sref_ip, sref, dref_ip, dref, rev_srcdst)
	if !ok {
		return false
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

	if l4 < IP_HDR_MIN_LEN { // this should be impossible
		log.err("deencap: not enough space for ip header, dropping")
		return false
	}
	pb.data = l4 - IP_HDR_MIN_LEN
	pb.typ = PKT_IP

	pkt[pb.data+IP_VER] = 0x45
	pkt[pb.data+IP_DSCP] = 0
	if (pb.tail - pb.data) >> 16 != 0 {
		log.err("deencap: packet too large")
		return false
	}
	be.PutUint16(pkt[pb.data+IP_LEN:pb.data+IP_LEN+2], uint16(pb.tail - pb.data))
	be.PutUint16(pkt[pb.data+IP_ID:pb.data+IP_ID+2], uint16(ident))
	{
		frag_field := uint16(frag_off) >> 3
		if frag_df {
			frag_field |= 1 << 14
		}
		if frag_mf {
			frag_field |= 1 << 13
		}
		be.PutUint16(pkt[pb.data+IP_FRAG:pb.data+IP_FRAG+2], frag_field)
	}
	pkt[pb.data+IP_TTL] = ttl
	pkt[pb.data+IP_PROTO] = proto
	be.PutUint16(pkt[pb.data+IP_CSUM:pb.data+IP_CSUM+2], 0)
	be.PutUint32(pkt[pb.data+IP_SRC:pb.data+IP_SRC+4], uint32(src_ea))
	be.PutUint32(pkt[pb.data+IP_DST:pb.data+IP_DST+4], uint32(dst_ip))

	// compute IP checksum
	ip_csum := csum_add(0, pkt[pb.data:pb.data+IP_HDR_MIN_LEN])
	be.PutUint16(pkt[pb.data+IP_CSUM:pb.data+IP_CSUM+2], ip_csum^0xffff)

	// adjust layer 4 headers

	switch proto {

	case TCP: // add ip src/dst addresses to csum

		if frag_off >= TCP_CSUM+2 || frag_end < TCP_CSUM {
			break
		}
		if frag_end < TCP_CSUM {
			log.err("deencap: invalid tcp packet, dropping")
			return false
		}

		tcp_csum := be.Uint16(pkt[l4+TCP_CSUM-frag_off : l4+TCP_CSUM-frag_off+2])

		if tcp_csum != 0 {
			tcp_csum = csum_add(tcp_csum^0xffff, pkt[pb.data+IP_SRC:pb.data+IP_DST+4])
			be.PutUint16(pkt[l4+TCP_CSUM-frag_off:l4+TCP_CSUM-frag_off+2], tcp_csum^0xffff)
		}

	case UDP: // add ip src/dst addresses to csum

		if frag_off != 0 {
			break
		}
		if frag_end < UDP_HDR_LEN {
			log.err("deencap: invalid udp packet, dropping")
			return false
		}

		udp_csum := be.Uint16(pkt[l4+UDP_CSUM : l4+UDP_CSUM+2])

		if udp_csum != 0 {
			udp_csum = csum_add(udp_csum^0xffff, pkt[pb.data+IP_SRC:pb.data+IP_DST+4])
			be.PutUint16(pkt[l4+UDP_CSUM:l4+UDP_CSUM+2], udp_csum^0xffff)
		}

	case ICMP: // replace inner ipref packet with ip packet

		if icmp_depth <= 0 {
			log.err("deencap: icmp depth limit reached, dropping")
			return false
		}
		if frag_off != 0 {
			// TODO This will let non-initial fragments of ICMP_ENCAP packets through.
			break
		}
		if l4_pkt_len < ICMP_DATA {
			log.err("deencap: invalid icmp packet, dropping")
			return false
		}

		switch icmp_action(pkt[l4+ICMP_TYPE]) {

		case ICMP_DROP:

			log.err("deencap: unrecognized icmp type (%v)", pkt[l4+ICMP_TYPE])
			return false

		case ICMP_ENCAP:

			if frag_if {
				log.err("deencap: fragmented icmp packet that needs inner deencap, dropping")
				return false
			}
			inner_pb := PktBuf{
				pkt: pkt[l4+ICMP_DATA:],
				typ: PKT_IPREF,
				data: 0,
				tail: min(l4_pkt_len - ICMP_DATA, 576)}
			if !ipref_deencap(&inner_pb, false, true, icmp_depth - 1) {
				log.err("deencap: dropping icmp due to invalid inner packet")
				return false
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

	return true
}

func fwd_to_gw() {

	for pb := range recv_tun {

		verdict := DROP

		switch pb.typ {

		case PKT_IP:

			if ipref_encap(pb, false, 1) {
				verdict = ACCEPT
				send_gw <- pb
			}

		case PKT_V1:

			if err := pb.validate_v1_header(pb.len()); err != nil {

				log.err("fwd_to_gw: invalid v1 packet from %v:  %v", pb.peer, err)

			} else {

				switch pb.pkt[pb.data+V1_CMD] {
				case V1_SET_AREC:
					verdict = map_gw.set_new_address_records(pb)
				case V1_REQ | V1_GET_REF:
					verdict = map_gw.get_ref(pb)
				case V1_SET_MARK:
					verdict = map_gw.set_new_mark(pb)
				case V1_SET_SOFT:
					verdict = map_gw.update_soft(pb)
				case V1_DATA | V1_RECOVER_EA:
					verdict = map_gw.remove_expired_eas(pb)
				case V1_DATA | V1_RECOVER_REF:
					verdict = map_gw.query_expired_refs(pb)
				default:
					log.err("fwd_to_gw: unknown address records command: %v, ignoring", pb.pkt[pb.data+V1_CMD])
				}
			}

		default:
			log.fatal("fwd_to_gw: unknown packet type: %v", pb.typ)
		}

		if verdict == DROP {
			retbuf <- pb
		}
	}
}

func fwd_to_tun() {

	for pb := range recv_gw {

		verdict := DROP

		switch pb.typ {

		case PKT_IPREF:

			if ipref_deencap(pb, true, false, 1) {
				verdict = ACCEPT
				send_tun <- pb
			}

		case PKT_V1:

			if err := pb.validate_v1_header(pb.len()); err != nil {

				log.err("fwd_to_tun: invalid v1 packet from %v:  %v", pb.peer, err)

			} else {

				switch pb.pkt[pb.data+V1_CMD] {
				case V1_SET_AREC:
					verdict = map_tun.set_new_address_records(pb)
				case V1_REQ | V1_GET_EA:
					verdict = map_tun.get_ea(pb)
				case V1_SET_MARK:
					verdict = map_tun.set_new_mark(pb)
				case V1_DATA | V1_RECOVER_REF:
					verdict = map_tun.remove_expired_refs(pb)
				case V1_DATA | V1_RECOVER_EA:
					verdict = map_tun.query_expired_eas(pb)
				default:
					log.err("fwd_to_tun: unknown address records command: %v, ignoring", pb.pkt[pb.data+V1_CMD])
				}
			}

		default:
			log.fatal("fwd_to_tun: unknown packet type: %v", pb.typ)
		}

		if verdict == DROP {
			retbuf <- pb
		}
	}
}
