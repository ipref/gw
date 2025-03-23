/* Copyright (c) 2018-2020 Waldemar Augustyn */

package main

import (
	"crypto/rand"
	"net"
)

var icmpreq chan (*PktBuf)

const (
	// icmp types
	ICMP_ECHO_REPLY    = 0
	ICMP_DEST_UNREACH  = 3
	ICMP_SOURCE_QUENCH = 4
	ICMP_REDIRECT      = 5
	ICMP_ECHO_REQUEST  = 8
	ICMP_TIME_EXCEEDED = 11

	// icmp codes for ICMP_DEST_UNREACH
	ICMP_NET_UNREACH  = 0
	ICMP_HOST_UNREACH = 1
	ICMP_PROT_UNREACH = 2
	ICMP_PORT_UNREACH = 3
	ICMP_FRAG_NEEDED  = 4
	ICMP_NET_UNKNOWN  = 6
	ICMP_HOST_UNKNOWN = 7

	// icmp codes for ICMP_TIME_EXCEEDED
	ICMP_EXC_TTL = 0

	ICMP_SEND_TTL = 64
)

// TODO Add a limit to prevent ICMP flooding.

func icmp() {

	for pb := range icmpreq {

		switch {

		case pb.icmp.typ == ICMP_DEST_UNREACH && pb.icmp.ours && pb.typ == PKT_IP:

			src := IP32(be.Uint32(pb.pkt[pb.data+IP_SRC : pb.data+IP_SRC+4]))
			dst := IP32(be.Uint32(pb.pkt[pb.data+IP_DST : pb.data+IP_DST+4]))
			log.trace("icmp: dest unreach (ours)  %v  %v", src, dst)

			if pb.ipref_proto() == ICMP {
				icmp_hdr := pb.data + pb.ip_hdr_len()
				if pb.tail < icmp_hdr + ICMP_DATA {
					log.trace("icmp: invalid layer 4, dropping")
					retbuf <- pb
					continue
				}
				typ := pb.pkt[icmp_hdr + ICMP_TYPE]
				if typ != ICMP_ECHO_REPLY && typ != ICMP_ECHO_REQUEST { // TODO What else to allow?
					log.trace("icmp: dropping type %v (don't respond to icmp with icmp)", typ)
					retbuf <- pb
					continue
				}
			}
			frag_field := be.Uint16(pb.pkt[pb.data + IP_FRAG : pb.data + IP_FRAG + 2])
			if frag_field & 0x1fff != 0 {
				log.trace("icmp: not first fragment, dropping")
				retbuf <- pb
				continue
			}

			if pb.len() > ICMP_ENCAP_MAX_LEN {
				pb.tail = pb.data + ICMP_ENCAP_MAX_LEN
			}
			new_hdrs_len := IP_HDR_MIN_LEN + ICMP_DATA
			if space_needed := new_hdrs_len - pb.data; space_needed > 0 {
				if len(pb.pkt) - pb.tail < space_needed {
					log.err("icmp: not enough space in buffer for header, dropping")
					retbuf <- pb
					continue
				}
				copy(pb.pkt[new_hdrs_len:], pb.pkt[pb.data:pb.tail])
			}
			inner_ip_hdr := pb.data
			outer_ip_hdr := inner_ip_hdr - new_hdrs_len
			icmp_hdr := inner_ip_hdr - ICMP_DATA
			pb.data -= new_hdrs_len

			// build outer IP header
			pb.pkt[outer_ip_hdr + IP_VER] = 0x45
			pb.pkt[outer_ip_hdr + IP_DSCP] = 0
			if (pb.tail - outer_ip_hdr) >> 16 != 0 {
				log.err("icmp: packet too large, dropping")
				retbuf <- pb
				continue
			}
			be.PutUint16(pb.pkt[outer_ip_hdr + IP_LEN : outer_ip_hdr + IP_LEN + 2], uint16(pb.tail - outer_ip_hdr))
			var identb [2]byte
			rand.Read(identb[:])
			be.PutUint16(pb.pkt[outer_ip_hdr + IP_ID : outer_ip_hdr + IP_ID + 2], be.Uint16(identb[:]))
			be.PutUint16(pb.pkt[outer_ip_hdr + IP_FRAG : outer_ip_hdr + IP_FRAG + 2], 0)
			pb.pkt[outer_ip_hdr + IP_TTL] = ICMP_SEND_TTL
			pb.pkt[outer_ip_hdr + IP_PROTO] = ICMP
			be.PutUint16(pb.pkt[outer_ip_hdr + IP_CSUM : outer_ip_hdr + IP_CSUM + 2], 0)
			be.PutUint32(pb.pkt[outer_ip_hdr + IP_SRC:], uint32(dst)) // swap src/dst
			be.PutUint32(pb.pkt[outer_ip_hdr + IP_DST:], uint32(src))
			ip_csum := csum_add(0, pb.pkt[outer_ip_hdr : outer_ip_hdr + IP_HDR_MIN_LEN])
			be.PutUint16(pb.pkt[outer_ip_hdr + IP_CSUM : outer_ip_hdr + IP_CSUM + 2], ip_csum^0xffff)

			// build ICMP header
			pb.pkt[icmp_hdr + ICMP_TYPE] = ICMP_DEST_UNREACH
			pb.pkt[icmp_hdr + ICMP_CODE] = pb.icmp.code
			be.PutUint16(pb.pkt[icmp_hdr + ICMP_CSUM : icmp_hdr + ICMP_CSUM + 2], 0)
			be.PutUint16(pb.pkt[icmp_hdr + ICMP_CSUM + 2 : icmp_hdr + ICMP_CSUM + 4], 0)
			be.PutUint16(pb.pkt[icmp_hdr + ICMP_MTU : icmp_hdr + ICMP_MTU + 2], pb.icmp.mtu)
			icmp_csum := csum_add(0, pb.pkt[icmp_hdr:pb.tail])
			be.PutUint16(pb.pkt[icmp_hdr + ICMP_CSUM : icmp_hdr + ICMP_CSUM + 2], icmp_csum^0xffff)

			send_tun <- pb
			continue

		case pb.icmp.typ == ICMP_DEST_UNREACH && pb.typ == PKT_IPREF:

			var ours_str string
			if pb.icmp.ours {
				ours_str = "ours"
			} else {
				ours_str = "theirs"
			}
			log.trace("icmp: dest unreach (%v)  %v + %v  %v + %v",
				ours_str,
				net.IP(pb.ipref_sref_ip()),
				pb.ipref_sref(),
				net.IP(pb.ipref_dref_ip()),
				pb.ipref_dref())

			if pb.ipref_proto() == ICMP {
				icmp_hdr := pb.data + pb.ipref_hdr_len()
				if pb.tail < icmp_hdr + ICMP_DATA {
					log.trace("icmp: invalid layer 4, dropping")
					retbuf <- pb
					continue
				}
				typ := pb.pkt[icmp_hdr + ICMP_TYPE]
				if typ != ICMP_ECHO_REPLY && typ != ICMP_ECHO_REQUEST { // TODO What else to allow?
					log.trace("icmp: dropping type %v (don't respond to icmp with icmp)", typ)
					retbuf <- pb
					continue
				}
			}
			if frag_if, frag_off, _, _ := pb.ipref_frag(); frag_if && frag_off != 0 {
				log.trace("icmp: not first fragment, dropping")
				retbuf <- pb
				continue
			}

			if pb.len() > ICMP_ENCAP_MAX_LEN {
				pb.tail = pb.data + ICMP_ENCAP_MAX_LEN
			}
			reflen := pb.ipref_reflen()
			new_hdrs_len := 12 + reflen * 2 + ICMP_DATA
			if space_needed := new_hdrs_len - pb.data; space_needed > 0 {
				if len(pb.pkt) - pb.tail < space_needed {
					log.err("icmp: not enough space in buffer for header, dropping")
					retbuf <- pb
					continue
				}
				copy(pb.pkt[new_hdrs_len:], pb.pkt[pb.data:pb.tail])
			}
			inner_ipref_hdr := pb.data
			inner_ipref_srcdst := inner_ipref_hdr + 4
			if pb.ipref_if() {
				inner_ipref_srcdst += 8
			}
			outer_ipref_hdr := inner_ipref_hdr - new_hdrs_len
			icmp_hdr := inner_ipref_hdr - ICMP_DATA
			pb.data -= new_hdrs_len

			// build outer IPREF header
			pb.pkt[outer_ipref_hdr] = (0x1 << 4) | (encode_reflen(reflen) << 2)
			pb.pkt[outer_ipref_hdr + 1] = 0
			pb.pkt[outer_ipref_hdr + 2] = ICMP_SEND_TTL
			pb.pkt[outer_ipref_hdr + 3] = ICMP
			copy(pb.pkt[outer_ipref_hdr + 4 : icmp_hdr], pb.pkt[inner_ipref_srcdst:]) // copy in src/dst
			pb.ipref_swap_srcdst()

			// build ICMP header
			pb.pkt[icmp_hdr + ICMP_TYPE] = ICMP_DEST_UNREACH
			pb.pkt[icmp_hdr + ICMP_CODE] = pb.icmp.code
			be.PutUint16(pb.pkt[icmp_hdr + ICMP_CSUM : icmp_hdr + ICMP_CSUM + 2], 0)
			be.PutUint16(pb.pkt[icmp_hdr + ICMP_CSUM + 2 : icmp_hdr + ICMP_CSUM + 4], 0)
			be.PutUint16(pb.pkt[icmp_hdr + ICMP_MTU : icmp_hdr + ICMP_MTU + 2], pb.icmp.mtu)
			icmp_csum := csum_add(0, pb.pkt[icmp_hdr:pb.tail])
			be.PutUint16(pb.pkt[icmp_hdr + ICMP_CSUM : icmp_hdr + ICMP_CSUM + 2], icmp_csum^0xffff)

			if pb.icmp.ours {
				recv_gw <- pb
			} else {
				pb.src = cli.gw_ip
				pb.sport = IPREF_PORT
				pb.dst = IP32(be.Uint32(pb.ipref_dref_ip()))
				pb.dport = IPREF_PORT
				send_gw <- pb
			}
			continue
		}

		log.info("icmp: received icmp request (%v %v %v %v), dropping for now",
			pb.icmp.typ, pb.icmp.code, pb.icmp.mtu, pb.icmp.ours)
		retbuf <- pb
	}
}
