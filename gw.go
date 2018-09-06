/* Copyright (c) 2018 Waldemar Augustyn */

package main

var recv_gw chan *PktBuf
var send_gw chan *PktBuf
var echo chan *PktBuf // for development only

func echo_discard(pb *PktBuf) int {

	if len(pb.pkt)-int(pb.data) < MIN_PKT_LEN {

		log.err("gw echo: short packet data/end(%v/%v), dropping", pb.data, len(pb.pkt))
		return DROP
	}

	pb.set_iphdr()
	pkt := pb.pkt[pb.iphdr:pb.tail]

	udp := uint((pkt[IP_VER] & 0xf) * 4)
	encap := udp + 8
	opt := encap + 4

	reflen := pb.reflen(pb.iphdr)

	if reflen == 0 {
		log.err("gw echo: not an ipref packet data/end(%v/%v), dropping", pb.data, len(pb.pkt))
		return DROP
	}

	payudp := int(opt) + reflen

	if len(pkt) < int(payudp+8) {
		log.err("gw echo: short ipref packet data/end(%v/%v), dropping", pb.data, len(pb.pkt))
	}

	if pkt[encap+ENCAP_PROTO] != UDP {
		log.err("gw echo: not a dev ipref packet, dropping")
		return DROP
	}

	ip_len := int(be.Uint16(pkt[IP_LEN : IP_LEN+2]))
	if ip_len != len(pkt) {
		log.err("gw echo: ip len(%v) does not match pktlen(%v), dropping", ip_len, len(pkt))
		return DROP
	}

	udp_len := int(be.Uint16(pkt[udp+UDP_LEN : udp+UDP_LEN+2]))
	udp_payload_len := len(pkt) - int(udp)
	if udp_len != udp_payload_len {
		log.err("gw echo: udp len(%v) does not match udp payload len(%v), dropping",
			udp_len, udp_payload_len)
		return DROP
	}

	dport := be.Uint16(pkt[payudp+UDP_DPORT : payudp+UDP_DPORT+2])

	// ipref discard

	if dport == DISCARD {
		return DROP
	}

	if dport != ECHO {
		log.err("gw echo: not a dev ipref echo/discard packet, dropping")
		return DROP
	}

	// ipref echo

	ip := []byte{0, 0, 0, 0}
	optport := []byte{0, 0}
	ttl := byte(0)
	ref_l := []byte{0, 0, 0, 0, 0, 0, 0, 0}
	ref_h := []byte{0, 0, 0, 0, 0, 0, 0, 0}
	payport := []byte{0, 0}

	copy(ip, pkt[IP_SRC:IP_SRC+4])
	copy(optport, pkt[udp+UDP_SPORT:udp+UDP_SPORT+2])
	ttl = pkt[encap+ENCAP_TTL]
	if reflen == IPREF_OPT64_LEN {
		copy(ref_l, pkt[opt+OPT_SREF64:opt+OPT_SREF64+8])
	} else {
		copy(ref_h, pkt[opt+OPT_SREF128:opt+OPT_SREF128+8])
		copy(ref_l, pkt[opt+OPT_SREF128+8:opt+OPT_SREF128+16])
	}
	copy(payport, pkt[payudp+UDP_SPORT:payudp+UDP_SPORT+2])

	copy(pkt[IP_SRC:IP_SRC+4], pkt[IP_DST:IP_DST+4])
	copy(pkt[udp+UDP_SPORT:udp+UDP_SPORT+2], pkt[udp+UDP_DPORT:udp+UDP_DPORT+2])
	pkt[encap+ENCAP_TTL] = pkt[encap+ENCAP_HOPS]
	if reflen == IPREF_OPT64_LEN {
		copy(pkt[opt+OPT_SREF64:opt+OPT_SREF64+8], pkt[opt+OPT_DREF64:opt+OPT_DREF64+8])
	} else {
		copy(pkt[opt+OPT_SREF128:opt+OPT_SREF128+8], pkt[opt+OPT_DREF128:opt+OPT_DREF128+8])
		copy(pkt[opt+OPT_SREF128+8:opt+OPT_SREF128+16], pkt[opt+OPT_DREF128+8:opt+OPT_DREF128+16])

		// modify some srefs to make them not appear in dns

		if ref_l[6] >= SECOND_BYTE {

			csum_diff := csum_add(uint16(pkt[opt+OPT_SREF128+7]), pkt[opt+OPT_SREF128+8:opt+OPT_SREF128+10])
			pkt[opt+OPT_SREF128+7] = 0
			pkt[opt+OPT_SREF128+8] = 0
			pkt[opt+OPT_SREF128+9] = 0

			var csum uint32

			csum = uint32(be.Uint16(pkt[udp+UDP_CSUM:udp+UDP_CSUM+2]) ^ 0xffff)
			csum -= uint32(csum_diff)
			for csum > 0xffff {
				csum = (csum & 0xffff) - (((csum ^ 0xffff0000) + 0x10000) >> 16)
			}
			be.PutUint16(pkt[udp+UDP_CSUM:udp+UDP_CSUM+2], uint16(csum)^0xffff)
		}
	}
	copy(pkt[payudp+UDP_SPORT:payudp+UDP_SPORT+2], pkt[payudp+UDP_DPORT:payudp+UDP_DPORT+2])

	copy(pkt[IP_DST:IP_DST+4], ip)
	copy(pkt[udp+UDP_DPORT:udp+UDP_DPORT+2], optport)
	pkt[encap+ENCAP_HOPS] = ttl
	if reflen == IPREF_OPT64_LEN {
		copy(pkt[opt+OPT_DREF64:opt+OPT_DREF64+8], ref_l)
	} else {
		copy(pkt[opt+OPT_DREF128:opt+OPT_DREF128+8], ref_h)
		copy(pkt[opt+OPT_DREF128+8:opt+OPT_DREF128+16], ref_l)
	}
	copy(pkt[payudp+UDP_DPORT:payudp+UDP_DPORT+2], payport)

	return ACCEPT
}

func gw_sender() {

	for pb := range send_gw {

		if len(pb.pkt)-int(pb.data) < MIN_PKT_LEN {

			log.err("gw out:  short packet data/end(%v/%v), dropping", pb.data, len(pb.pkt))
			retbuf <- pb
			continue
		}

		if cli.debug["gw"] || cli.debug["all"] {
			log.debug("gw out:  %v", pb.pp_pkt())
		}

		if log.level <= TRACE {
			pb.pp_net("gw out:  ")
			pb.pp_tran("gw out:  ")
			pb.pp_raw("gw out:  ")
		}

		if DEVEL_ECHO {
			echo <- pb
			continue
		}

		// for now just drop it

		retbuf <- pb
	}
}

func gw_receiver() {

	for pb := range echo {

		verdict := echo_discard(pb)

		if verdict != ACCEPT {
			if verdict == DROP {
				retbuf <- pb
			}
			continue
		}

		if len(pb.pkt)-int(pb.data) < MIN_PKT_LEN {

			log.err("gw in:   short packet data/end(%v/%v), dropping", pb.data, len(pb.pkt))
			retbuf <- pb
			continue
		}

		if cli.debug["gw"] || cli.debug["all"] {
			log.debug("gw in:   %v", pb.pp_pkt())
		}

		if log.level <= TRACE {
			pb.pp_net("gw in:   ")
			pb.pp_tran("gw in:   ")
			pb.pp_raw("gw in:   ")
		}

		recv_gw <- pb
	}
}
