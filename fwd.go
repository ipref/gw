/* Copyright (c) 2018 Waldemar Augustyn */

package main

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
		log.err("inserting opt: unknown dst address: %v %v , sending icmp", src, dst)
		pb.icmp.typ = ICMP_DEST_UNREACH
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

	var csum uint16
	var optlen int

	iphdrlen := pb.iphdr_len()

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
	pkt[opt+OPT_LEN] = byte(optlen)
	if optlen == IPREF_OPT128_LEN {
		be.PutUint64(pkt[opt+OPT_SREF128:opt+OPT_SREF128+8], iprefsrc.ref.h)
		be.PutUint64(pkt[opt+OPT_SREF128+8:opt+OPT_SREF128+16], iprefsrc.ref.l)
		be.PutUint64(pkt[opt+OPT_DREF128:opt+OPT_DREF128+8], iprefdst.ref.h)
		be.PutUint64(pkt[opt+OPT_DREF128+8:opt+OPT_DREF128+16], iprefdst.ref.l)
	} else {
		be.PutUint64(pkt[opt+OPT_SREF64:opt+OPT_SREF64+8], iprefsrc.ref.l)
		be.PutUint64(pkt[opt+OPT_DREF64:opt+OPT_DREF64+8], iprefdst.ref.l)
	}

	// adjust layer 4 headers

	l4 := opt + optlen

	switch pkt[encap+ENCAP_PROTO] {

	case TCP: // subtract ip src/dst addresses from csum

		csum = be.Uint16(pkt[l4+TCP_CSUM : l4+TCP_CSUM+2])

		if csum != 0 {
			csum = csum_subtract(csum^0xffff, pkt[pb.iphdr+IP_SRC:pb.iphdr+IP_DST+4])
			be.PutUint16(pkt[l4+TCP_CSUM:l4+TCP_CSUM+2], csum^0xffff)
		}

	case UDP: // subtract ip src/dst addresses from csum

		csum = be.Uint16(pkt[l4+UDP_CSUM : l4+UDP_CSUM+2])

		if csum != 0 {
			csum = csum_subtract(csum^0xffff, pkt[pb.iphdr+IP_SRC:pb.iphdr+IP_DST+4])
			be.PutUint16(pkt[l4+UDP_CSUM:l4+UDP_CSUM+2], csum^0xffff)
		}

	case ICMP: // replace inner ip addresses with their ipref equivalents

		if pkt[l4+ICMP_TYPE] != ICMP_DEST_UNREACH &&
			pkt[l4+ICMP_TYPE] != ICMP_TIME_EXCEEDED &&
			pkt[l4+ICMP_TYPE] != ICMP_REDIRECT &&
			pkt[l4+ICMP_TYPE] != ICMP_SOURCE_QUENCH {
			break
		}

		inner := l4 + ICMP_DATA

		inner_src := IP32(be.Uint32(pkt[inner+IP_SRC : inner+IP_SRC+4]))
		inner_dst := IP32(be.Uint32(pkt[inner+IP_DST : inner+IP_DST+4]))

		if (pkt[inner+IP_VER] & 0x0f) != 5 {
			log.err("inserting opt: icmp inner header has options  %v  %v, leaving as is", src, dst)
			break
		}

		inner_dstipref := map_gw.get_dst_ipref(inner_src)

		if inner_dstipref.ip == 0 {
			log.err("inserting opt:  cannot find ipref addr for icmp inner src %v  %v, leaving as is", src, dst)
			break
		}

		inner_srcipref := map_gw.get_src_ipref(inner_dst)

		if inner_srcipref.ip == 0 {
			log.err("inserting opt:  cannot find ipref addr for icmp inner dst %v  %v, leaving as is", src, dst)
			break
		}

		var inner_optlen int

		if inner_srcipref.ref.h == 0 && inner_dstipref.ref.h == 0 {
			inner_optlen = IPREF_OPT64_LEN
		} else {
			inner_optlen = IPREF_OPT128_LEN
		}

		if len(pkt)-pb.tail < inner_optlen {
			log.err("inserting opt:  not enough room to expand inner header %v  %v, leaving as is", src, dst)
			break
		}

		// insert inner ipref option

		inner_opt := inner + 5*4

		copy(pkt[inner_opt+inner_optlen:], pkt[inner_opt:pb.tail])
		pb.tail += inner_optlen

		pkt[inner_opt+OPT_OPT] = IPREF_OPT
		pkt[inner_opt+OPT_LEN] = byte(inner_optlen)
		be.PutUint16(pkt[inner_opt+OPT_RSVD:inner_opt+OPT_RSVD+2], 0)
		if inner_optlen == IPREF_OPT128_LEN {
			be.PutUint64(pkt[inner_opt+OPT_SREF128:inner_opt+OPT_SREF128+8], inner_srcipref.ref.h)
			be.PutUint64(pkt[inner_opt+OPT_SREF128+8:inner_opt+OPT_SREF128+16], inner_srcipref.ref.l)
			be.PutUint64(pkt[inner_opt+OPT_DREF128:inner_opt+OPT_DREF128+8], inner_dstipref.ref.h)
			be.PutUint64(pkt[inner_opt+OPT_DREF128+8:inner_opt+OPT_DREF128+16], inner_dstipref.ref.l)
		} else {
			be.PutUint64(pkt[inner_opt+OPT_SREF64:inner_opt+OPT_SREF64+8], inner_srcipref.ref.l)
			be.PutUint64(pkt[inner_opt+OPT_DREF64:inner_opt+OPT_DREF64+8], inner_dstipref.ref.l)
		}

		// adjust csum, in calculations ignore option because it will be removed

		var inner_csum uint16

		inner_csum = be.Uint16(pkt[inner+IP_CSUM:inner+IP_CSUM+2]) ^ 0xffff
		inner_csum = csum_subtract(inner_csum, pkt[inner+IP_VER:inner+IP_VER+2])
		inner_csum = csum_subtract(inner_csum, pkt[inner+IP_SRC:inner+IP_DST+4])

		csum = be.Uint16(pkt[l4+ICMP_CSUM:l4+ICMP_CSUM+2]) ^ 0xffff
		csum = csum_subtract(csum, pkt[inner+IP_VER:inner+IP_VER+2])
		csum = csum_subtract(csum, pkt[inner+IP_CSUM:inner+IP_CSUM+2])
		csum = csum_subtract(csum, pkt[inner+IP_SRC:inner+IP_DST+4])

		pkt[inner+IP_VER] += byte(inner_optlen / 4)
		be.PutUint32(pkt[inner+IP_SRC:inner+IP_SRC+4], uint32(inner_srcipref.ip))
		be.PutUint32(pkt[inner+IP_DST:inner+IP_DST+4], uint32(inner_dstipref.ip))
		inner_csum = csum_add(inner_csum, pkt[inner+IP_VER:inner+IP_VER+2])
		inner_csum = csum_add(inner_csum, pkt[inner+IP_SRC:inner+IP_DST+4])

		be.PutUint16(pkt[inner+IP_CSUM:inner+IP_CSUM+2], inner_csum^0xffff)

		csum = csum_add(csum, pkt[inner+IP_VER:inner+IP_VER+2])
		csum = csum_add(csum, pkt[inner+IP_CSUM:inner+IP_CSUM+2])
		csum = csum_add(csum, pkt[inner+IP_SRC:inner+IP_DST+4])

		be.PutUint16(pkt[l4+ICMP_CSUM:l4+ICMP_CSUM+2], csum^0xffff)
	}

	// adjust ip header

	be.PutUint16(pkt[pb.iphdr+IP_LEN:pb.iphdr+IP_LEN+2], uint16(pb.len()))
	pkt[pb.iphdr+IP_PROTO] = UDP
	be.PutUint16(pkt[pb.iphdr+IP_CSUM:pb.iphdr+IP_CSUM+2], 0)
	be.PutUint32(pkt[pb.iphdr+IP_SRC:pb.iphdr+IP_SRC+4], uint32(iprefsrc.ip))
	be.PutUint32(pkt[pb.iphdr+IP_DST:pb.iphdr+IP_DST+4], uint32(iprefdst.ip))

	csum = csum_add(0, pkt[pb.iphdr:pb.iphdr+iphdrlen])
	be.PutUint16(pkt[pb.iphdr+IP_CSUM:pb.iphdr+IP_CSUM+2], csum^0xffff)

	if cli.debug["fwd"] || cli.debug["all"] {
		log.debug("inserting opt: %v", pb.pp_pkt())
	}

	return ACCEPT
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
	} else {
		log.err("removing opt: invalid ipref option length: %v, dropping", reflen)
		return DROP
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
		log.err("removing opt:  soft record gw %v does not match src %v, resetting", soft.gw, src)
		soft.init(src)
		soft.port = 0 // force change
	}

	if soft.ttl != pkt[encap+ENCAP_HOPS] ||
		soft.hops != pkt[encap+ENCAP_TTL] ||
		soft.port != be.Uint16(pkt[udp+UDP_SPORT:udp+UDP_SPORT+2]) {

		soft.ttl = pkt[encap+ENCAP_HOPS]
		soft.hops = pkt[encap+ENCAP_TTL]
		soft.port = be.Uint16(pkt[udp+UDP_SPORT : udp+UDP_SPORT+2])

		map_tun.set_soft(src, soft)
	}

	// adjust ip header

	pktlen := be.Uint16(pkt[IP_LEN : IP_LEN+2])
	pktlen -= 8 + 4 + uint16(reflen)

	be.PutUint16(pkt[IP_LEN:IP_LEN+2], pktlen)
	pkt[IP_PROTO] = pkt[encap+ENCAP_PROTO]
	be.PutUint32(pkt[IP_SRC:IP_SRC+4], uint32(src_ea))
	be.PutUint32(pkt[IP_DST:IP_DST+4], uint32(dst_ip))

	// strip option

	iphdrlen := pb.iphdr_len()
	pb.iphdr += 8 + 4 + reflen // udp header + encap + opt
	copy(pb.pkt[pb.iphdr:pb.iphdr+iphdrlen], pb.pkt[pb.data:pb.data+iphdrlen])
	pb.data = pb.iphdr

	// adjust layer 4 headers

	pkt = pb.pkt[pb.iphdr:pb.tail]
	l4 := pb.iphdr_len()

	var csum uint16

	switch pkt[IP_PROTO] {

	case TCP: // add ip src/dst addresses to csum

		csum = be.Uint16(pkt[l4+TCP_CSUM : l4+TCP_CSUM+2])

		if csum != 0 {
			csum = csum_add(csum^0xffff, pkt[IP_SRC:IP_DST+4])
			be.PutUint16(pkt[l4+TCP_CSUM:l4+TCP_CSUM+2], csum^0xffff)
		}

	case UDP: // add ip src/dst addresses to csum

		csum = be.Uint16(pkt[l4+UDP_CSUM : l4+UDP_CSUM+2])

		if csum != 0 {
			csum = csum_add(csum^0xffff, pkt[IP_SRC:IP_DST+4])
			be.PutUint16(pkt[l4+UDP_CSUM:l4+UDP_CSUM+2], csum^0xffff)
		}

	case ICMP: // replace inner ipref addresses with their ea/ip equivalents

		if pkt[l4+ICMP_TYPE] != ICMP_DEST_UNREACH &&
			pkt[l4+ICMP_TYPE] != ICMP_TIME_EXCEEDED &&
			pkt[l4+ICMP_TYPE] != ICMP_REDIRECT &&
			pkt[l4+ICMP_TYPE] != ICMP_SOURCE_QUENCH {
			break
		}

		inner := l4 + ICMP_DATA

		if (pkt[inner+IP_VER] & 0x0f) == 5 {
			log.err("removing opt: icmp inner header has no options  %v %v, leaving as is", src, dst)
			break
		}

		inner_opt := inner + 5*4

		if pkt[inner_opt+OPT_OPT] != IPREF_OPT {
			log.err("removing opt: icmp inner header option is not ipref  %v %v, leaving as is", src, dst)
			break
		}

		var inner_srcipref IpRefRec
		var inner_dstipref IpRefRec

		inner_srcipref.ip = IP32(be.Uint32(pkt[inner+IP_SRC : inner+IP_SRC+4]))
		inner_dstipref.ip = IP32(be.Uint32(pkt[inner+IP_DST : inner+IP_DST+4]))

		inner_optlen := int(pkt[inner_opt+OPT_LEN])

		if inner_optlen == IPREF_OPT128_LEN {
			inner_srcipref.ref.h = be.Uint64(pkt[inner_opt+OPT_SREF128 : inner_opt+OPT_SREF128+8])
			inner_srcipref.ref.l = be.Uint64(pkt[inner_opt+OPT_SREF128+8 : inner_opt+OPT_SREF128+16])
			inner_dstipref.ref.h = be.Uint64(pkt[inner_opt+OPT_DREF128 : inner_opt+OPT_DREF128+8])
			inner_dstipref.ref.l = be.Uint64(pkt[inner_opt+OPT_DREF128+8 : inner_opt+OPT_DREF128+16])
		} else if inner_optlen == IPREF_OPT64_LEN {
			inner_srcipref.ref.h = 0
			inner_srcipref.ref.l = be.Uint64(pkt[inner_opt+OPT_SREF64 : inner_opt+OPT_SREF64+8])
			inner_dstipref.ref.h = 0
			inner_dstipref.ref.l = be.Uint64(pkt[inner_opt+OPT_DREF64 : inner_opt+OPT_DREF64+8])
		} else {
			log.err("removing opt: invalid inner ipref option length: %v, dropping", inner_optlen)
			return DROP
		}

		// remove inner ipref option

		copy(pkt[inner:], pkt[inner_opt+inner_optlen:])
		pb.tail -= inner_optlen
		pkt = pb.pkt[pb.iphdr:pb.tail]

		// get addresses

		inner_dst := map_tun.get_src_ea(inner_srcipref.ip, inner_srcipref.ref)
		if inner_dst == 0 {
			log.err("removing opt: cannot find ea for icmp inner src ipref: %v + %v, leaving as is",
				inner_srcipref.ip, &inner_srcipref.ref)
			break
		}
		inner_src := map_tun.get_dst_ip(inner_dstipref.ip, inner_dstipref.ref)
		if inner_src == 0 {
			log.err("removing opt: cannot find ip for icmp inner dst ipref: %v + %v, leaving as is",
				inner_dstipref.ip, &inner_dstipref.ref)
			break
		}

		// adjust csum

		var inner_csum uint16

		inner_csum = be.Uint16(pkt[inner+IP_CSUM:inner+IP_CSUM+2]) ^ 0xffff
		inner_csum = csum_subtract(inner_csum, pkt[inner+IP_VER:inner+IP_VER+2])
		inner_csum = csum_subtract(inner_csum, pkt[inner+IP_SRC:inner+IP_DST+4])

		csum = be.Uint16(pkt[l4+ICMP_CSUM:l4+ICMP_CSUM+2]) ^ 0xffff
		csum = csum_subtract(csum, pkt[inner+IP_VER:inner+IP_VER+2])
		csum = csum_subtract(csum, pkt[inner+IP_CSUM:inner+IP_CSUM+2])
		csum = csum_subtract(csum, pkt[inner+IP_SRC:inner+IP_DST+4])

		pkt[inner+IP_VER] -= byte(inner_optlen / 4)
		be.PutUint32(pkt[inner+IP_SRC:inner+IP_SRC+4], uint32(inner_src))
		be.PutUint32(pkt[inner+IP_DST:inner+IP_DST+4], uint32(inner_dst))
		inner_csum = csum_add(inner_csum, pkt[inner+IP_VER:inner+IP_VER+2])
		inner_csum = csum_add(inner_csum, pkt[inner+IP_SRC:inner+IP_DST+4])

		be.PutUint16(pkt[inner+IP_CSUM:inner+IP_CSUM+2], inner_csum^0xffff)

		csum = csum_add(csum, pkt[inner+IP_VER:inner+IP_VER+2])
		csum = csum_add(csum, pkt[inner+IP_CSUM:inner+IP_CSUM+2])
		csum = csum_add(csum, pkt[inner+IP_SRC:inner+IP_DST+4])

		be.PutUint16(pkt[l4+ICMP_CSUM:l4+ICMP_CSUM+2], csum^0xffff)
	}

	// adjust ip header csum

	be.PutUint16(pkt[IP_CSUM:IP_CSUM+2], 0)
	csum = csum_add(0, pkt[:iphdrlen])
	be.PutUint16(pkt[IP_CSUM:IP_CSUM+2], csum^0xffff)

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
			case V1_PURGE:
				verdict = map_gw.timer(pb)
			default:
				log.err("fwd_to_gw: unknown address records command: %v, ignoring", pb.pkt[pb.v1hdr+V1_CMD])
			}

		default:
			log.err("fwd_to_gw: unknown packet signature: 0x%02x, dropping", pb.pkt[pb.data])
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
			case V1_PURGE:
				verdict = map_tun.timer(pb)
			default:
				log.err("fwd_to_tun: unknown address records command: %v, ignoring", pb.pkt[pb.v1hdr+V1_CMD])
			}

		default:
			log.err("fwd_to_tun: unknown packet signature: 0x%02x, dropping", pb.pkt[pb.data])
		}

		if verdict == DROP {
			retbuf <- pb
		}
	}
}
