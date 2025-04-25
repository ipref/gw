/* Copyright (c) 2018-2020 Waldemar Augustyn */

package main

import (
	. "github.com/ipref/common"
	"crypto/rand"
)

var icmpreq chan (*PktBuf)

const (
	// ICMPv4 types
	ICMPv4_ECHO_REPLY    = 0
	ICMPv4_DEST_UNREACH  = 3
	ICMPv4_SOURCE_QUENCH = 4
	ICMPv4_REDIRECT      = 5
	ICMPv4_ECHO_REQUEST  = 8
	ICMPv4_TIME_EXCEEDED = 11

	// ICMPv4 codes for ICMPv4_DEST_UNREACH
	ICMPv4_NET_UNREACH  = 0
	ICMPv4_HOST_UNREACH = 1
	ICMPv4_PROT_UNREACH = 2 // protocol unreachable
	ICMPv4_PORT_UNREACH = 3
	ICMPv4_FRAG_NEEDED  = 4
	ICMPv4_NET_UNKNOWN  = 6
	ICMPv4_HOST_UNKNOWN = 7
	ICMPv4_ADMIN_PROHIB = 13 // communication administratively prohibited

	// ICMPv4 codes for ICMPv4_TIME_EXCEEDED
	ICMPv4_EXC_TTL  = 0
	ICMPv4_EXC_FRAG = 1 // fragment reassembly time exceeded

	// ICMPv6 types
	ICMPv6_DEST_UNREACH   = 1
	ICMPv6_PACKET_TOO_BIG = 2
	ICMPv6_TIME_EXCEEDED  = 3
	ICMPv6_ECHO_REQUEST   = 128 // code = 0
	ICMPv6_ECHO_REPLY     = 129 // code = 0

	// ICMPv6 codes for ICMPv6_DEST_UNREACH
	ICMPv6_NET_UNREACH = 0
	ICMPv6_ADMIN_PROHIB = 1
	ICMPv6_HOST_UNREACH = 3
	ICMPv6_PORT_UNREACH = 4

	// ICMPv6 codes for ICMPv6_TIME_EXCEEDED
	ICMPv6_EXC_TTL  = 0 // hop limit exceeded
	ICMPv6_EXC_FRAG = 1

	// IPREF_ICMP types
	IPREF_ICMP_ECHO_REPLY = 0
	IPREF_ICMP_DEST_UNREACH = 3
	IPREF_ICMP_ECHO_REQUEST = 8
	IPREF_ICMP_TIME_EXCEEDED = 11

	// IPREF_ICMP codes for IPREF_ICMP_DEST_UNREACH
	IPREF_ICMP_NET_UNREACH  = 0
	IPREF_ICMP_HOST_UNREACH = 1
	IPREF_ICMP_PORT_UNREACH = 2
	IPREF_ICMP_FRAG_NEEDED  = 4
	IPREF_ICMP_ADMIN_PROHIB = 13

	// IPREF_ICMP codes for IPREF_ICMP_TIME_EXCEEDED
	IPREF_ICMP_EXC_TTL  = 0
	IPREF_ICMP_EXC_FRAG = 1

	ICMPv4_SEND_TTL     = 64
	ICMPv6_SEND_TTL     = 64
	IPREF_ICMP_SEND_TTL = 64
)

// TODO Add a limit to prevent ICMP flooding.

// Allow sending ICMP messages in response to these ICMP messages.
func icmp_respond_icmp(pkt_typ int, typ byte, code byte) bool {

	switch pkt_typ {

	case PKT_IPREF:
		switch typ {
		case IPREF_ICMP_ECHO_REPLY, IPREF_ICMP_ECHO_REQUEST:
			return true
		}

	case PKT_IPv4:
		switch typ {
		case ICMPv4_ECHO_REPLY, ICMPv4_ECHO_REQUEST:
			return true
		}

	case PKT_IPv6:
		switch typ {
		case ICMPv6_ECHO_REQUEST, ICMPv6_ECHO_REPLY:
			return true
		}
	}
	return false
}

func icmp() {

	// If pb.typ == PKT_IPREF && pb.icmp.ours, then this uses pb.gw_hint and
	// pb.rgw_hint.
	for pb := range icmpreq {

		unreach := ""
		switch {
		case pb.typ == PKT_IPv4 && pb.icmp.typ == ICMPv4_DEST_UNREACH:
			unreach = "dest unreach"
		case pb.typ == PKT_IPv4 && pb.icmp.typ == ICMPv4_TIME_EXCEEDED:
			unreach = "time exceeded"
		case pb.typ == PKT_IPv6 && pb.icmp.typ == ICMPv6_DEST_UNREACH:
			unreach = "dest unreach"
		case pb.typ == PKT_IPv6 && pb.icmp.typ == ICMPv6_TIME_EXCEEDED:
			unreach = "time exceeded"
		case pb.typ == PKT_IPREF && pb.icmp.typ == IPREF_ICMP_DEST_UNREACH:
			unreach = "dest unreach"
		case pb.typ == PKT_IPREF && pb.icmp.typ == IPREF_ICMP_TIME_EXCEEDED:
			unreach = "time exceeded"
		}

		switch {

		case pb.typ == PKT_IPv4 && unreach != "" && pb.icmp.ours:

			src := IPFromSlice(pb.pkt[pb.data+IPv4_SRC : pb.data+IPv4_SRC+4])
			dst := IPFromSlice(pb.pkt[pb.data+IPv4_DST : pb.data+IPv4_DST+4])
			log.trace("icmp:    %v (IPv4, ours)  %v  %v", unreach, src, dst)

			if pb.pkt[IPv4_PROTO] == ICMP {
				icmp_hdr := pb.data + pb.ip_hdr_len()
				if pb.tail < icmp_hdr + ICMP_DATA {
					log.trace("icmp:    invalid layer 4, dropping")
					retbuf <- pb
					continue
				}
				typ := pb.pkt[icmp_hdr + ICMP_TYPE]
				code := pb.pkt[icmp_hdr + ICMP_CODE]
				if !icmp_respond_icmp(pb.typ, typ, code) {
					log.trace("icmp:    don't respond to icmp with icmp (%v %v %v), dropping",
						pb.typ, typ, code)
					retbuf <- pb
					continue
				}
			}
			frag_field := be.Uint16(pb.pkt[pb.data + IPv4_FRAG : pb.data + IPv4_FRAG + 2])
			if frag_field & 0x1fff != 0 {
				log.trace("icmp:    not first fragment, dropping")
				retbuf <- pb
				continue
			}

			if pb.len() > ICMP_ENCAP_MAX_LEN {
				pb.tail = pb.data + ICMP_ENCAP_MAX_LEN
			}
			new_hdrs_len := IPv4_HDR_MIN_LEN + ICMP_DATA
			if space_needed := new_hdrs_len - pb.data; space_needed > 0 {
				if len(pb.pkt) - pb.tail < space_needed {
					log.err("icmp:    not enough space in buffer for header, dropping")
					retbuf <- pb
					continue
				}
				copy(pb.pkt[new_hdrs_len:], pb.pkt[pb.data:pb.tail])
				pb.data, pb.tail = new_hdrs_len, new_hdrs_len + pb.len()
			}
			inner_ip_hdr := pb.data
			outer_ip_hdr := inner_ip_hdr - new_hdrs_len
			icmp_hdr := inner_ip_hdr - ICMP_DATA
			pb.data -= new_hdrs_len

			// build outer IP header
			pb.pkt[outer_ip_hdr + IP_VER] = 0x45
			pb.pkt[outer_ip_hdr + IPv4_DSCP] = 0
			if (pb.tail - outer_ip_hdr) >> 16 != 0 {
				log.err("icmp:    packet too large, dropping")
				retbuf <- pb
				continue
			}
			be.PutUint16(pb.pkt[outer_ip_hdr + IPv4_LEN : outer_ip_hdr + IPv4_LEN + 2], uint16(pb.tail - outer_ip_hdr))
			var identb [2]byte
			rand.Read(identb[:])
			be.PutUint16(pb.pkt[outer_ip_hdr + IPv4_ID : outer_ip_hdr + IPv4_ID + 2], be.Uint16(identb[:]))
			be.PutUint16(pb.pkt[outer_ip_hdr + IPv4_FRAG : outer_ip_hdr + IPv4_FRAG + 2], 0)
			pb.pkt[outer_ip_hdr + IPv4_TTL] = ICMPv4_SEND_TTL
			pb.pkt[outer_ip_hdr + IPv4_PROTO] = ICMP
			be.PutUint16(pb.pkt[outer_ip_hdr + IPv4_CSUM : outer_ip_hdr + IPv4_CSUM + 2], 0)
			copy(pb.pkt[outer_ip_hdr + IPv4_SRC:], cli.ea_gwip.AsSlice4())
			copy(pb.pkt[outer_ip_hdr + IPv4_DST:], src.AsSlice4())
			ip_csum := csum_add(0, pb.pkt[outer_ip_hdr : outer_ip_hdr + IPv4_HDR_MIN_LEN])
			be.PutUint16(pb.pkt[outer_ip_hdr + IPv4_CSUM : outer_ip_hdr + IPv4_CSUM + 2], ip_csum^0xffff)

			// build ICMP header
			pb.pkt[icmp_hdr + ICMP_TYPE] = pb.icmp.typ
			pb.pkt[icmp_hdr + ICMP_CODE] = pb.icmp.code
			be.PutUint16(pb.pkt[icmp_hdr + ICMP_CSUM : icmp_hdr + ICMP_CSUM + 2], 0)
			be.PutUint16(pb.pkt[icmp_hdr + ICMP_CSUM + 2 : icmp_hdr + ICMP_CSUM + 4], 0)
			be.PutUint16(pb.pkt[icmp_hdr + ICMP_MTU : icmp_hdr + ICMP_MTU + 2], pb.icmp.mtu)
			icmp_csum := csum_add(0, pb.pkt[icmp_hdr:pb.tail])
			be.PutUint16(pb.pkt[icmp_hdr + ICMP_CSUM : icmp_hdr + ICMP_CSUM + 2], icmp_csum^0xffff)

			send_tun <- pb
			continue

		case pb.typ == PKT_IPv6 && unreach != "" && pb.icmp.ours:

			src := IPFromSlice(pb.pkt[pb.data+IPv6_SRC : pb.data+IPv6_SRC+16])
			dst := IPFromSlice(pb.pkt[pb.data+IPv6_DST : pb.data+IPv6_DST+16])
			log.trace("icmp:    %v (IPv6, ours)  %v  %v", unreach, src, dst)

			if pb.ip_proto() == ICMPv6 {
				icmp_hdr := pb.data + pb.ip_hdr_len()
				if pb.tail < icmp_hdr + ICMP_DATA {
					log.trace("icmp:    invalid layer 4, dropping")
					retbuf <- pb
					continue
				}
				typ := pb.pkt[icmp_hdr + ICMP_TYPE]
				code := pb.pkt[icmp_hdr + ICMP_CODE]
				if !icmp_respond_icmp(pb.typ, typ, code) {
					log.trace("icmp:    don't respond to icmp with icmp (%v %v %v), dropping",
						pb.typ, typ, code)
					retbuf <- pb
					continue
				}
			}
			if pb.pkt[pb.data + IPv6_NEXT] == IPv6_FRAG_EXT {
				i := pb.data + IPv6_HDR_MIN_LEN + IPv6_FRAG_OFF
				frag_field := be.Uint16(pb.pkt[i : i + 2])
				frag_off := int(frag_field &^ 3)
				if frag_off != 0 {
					log.trace("icmp:    not first fragment, dropping")
					retbuf <- pb
					continue
				}
			}

			if pb.len() > ICMP_ENCAP_MAX_LEN {
				pb.tail = pb.data + ICMP_ENCAP_MAX_LEN
			}
			new_hdrs_len := IPv6_HDR_MIN_LEN + ICMP_DATA
			if space_needed := new_hdrs_len - pb.data; space_needed > 0 {
				if len(pb.pkt) - pb.tail < space_needed {
					log.err("icmp:    not enough space in buffer for header, dropping")
					retbuf <- pb
					continue
				}
				copy(pb.pkt[new_hdrs_len:], pb.pkt[pb.data:pb.tail])
				pb.data, pb.tail = new_hdrs_len, new_hdrs_len + pb.len()
			}
			inner_ip_hdr := pb.data
			outer_ip_hdr := inner_ip_hdr - new_hdrs_len
			icmp_hdr := inner_ip_hdr - ICMP_DATA
			pb.data -= new_hdrs_len

			// build outer IP header
			pb.pkt[outer_ip_hdr + IP_VER] = 0x60
			pb.pkt[outer_ip_hdr + 1] = 0 // TODO Flow label?
			pb.pkt[outer_ip_hdr + 2] = 0
			pb.pkt[outer_ip_hdr + 3] = 0
			if (pb.tail - icmp_hdr) >> 16 != 0 {
				log.err("icmp:    packet too large, dropping")
				retbuf <- pb
				continue
			}
			be.PutUint16(pb.pkt[outer_ip_hdr + IPv6_PLD_LEN : outer_ip_hdr + IPv6_PLD_LEN + 2],
				uint16(pb.tail - icmp_hdr))
			pb.pkt[outer_ip_hdr + IPv6_NEXT] = ICMPv6
			pb.pkt[outer_ip_hdr + IPv6_TTL] = ICMPv6_SEND_TTL
			copy(pb.pkt[outer_ip_hdr + IPv6_SRC:], cli.ea_gwip.AsSlice6())
			copy(pb.pkt[outer_ip_hdr + IPv6_DST:], src.AsSlice6())

			// build ICMP header
			pb.pkt[icmp_hdr + ICMP_TYPE] = pb.icmp.typ
			pb.pkt[icmp_hdr + ICMP_CODE] = pb.icmp.code
			be.PutUint16(pb.pkt[icmp_hdr + ICMP_CSUM : icmp_hdr + ICMP_CSUM + 2], 0)
			be.PutUint16(pb.pkt[icmp_hdr + ICMP_CSUM + 2 : icmp_hdr + ICMP_CSUM + 4], 0)
			be.PutUint16(pb.pkt[icmp_hdr + ICMP_MTU : icmp_hdr + ICMP_MTU + 2], pb.icmp.mtu)
			icmp_csum := csum_add(0, pb.pkt[outer_ip_hdr + IPv6_SRC : pb.tail])
			var pseudo [4]byte
			be.PutUint16(pseudo[:2], uint16(pb.tail - icmp_hdr))
			pseudo[3] = ICMPv6
			icmp_csum = csum_add(icmp_csum, pseudo[:])
			be.PutUint16(pb.pkt[icmp_hdr + ICMP_CSUM : icmp_hdr + ICMP_CSUM + 2], icmp_csum^0xffff)

			pb.df = false
			send_tun <- pb
			continue

		case pb.typ == PKT_IPREF && unreach != "":

			var ours_str string
			if pb.icmp.ours {
				ours_str = "ours"
			} else {
				ours_str = "theirs"
			}
			if !pb.ipref_ok() {
				log.fatal("icmp:    invalid ipref packet")
			}
			src := pb.ipref_src()
			dst := pb.ipref_dst()
			log.trace("icmp:    %v (IPREF, %v)  %v  %v", unreach, ours_str, src, dst)

			if pb.ipref_proto() == ICMP {
				icmp_hdr := pb.data + pb.ipref_hdr_len()
				if pb.tail < icmp_hdr + ICMP_DATA {
					log.trace("icmp:    invalid layer 4, dropping")
					retbuf <- pb
					continue
				}
				typ := pb.pkt[icmp_hdr + ICMP_TYPE]
				code := pb.pkt[icmp_hdr + ICMP_CODE]
				if !icmp_respond_icmp(pb.typ, typ, code) {
					log.trace("icmp:    don't respond to icmp with icmp (%v %v %v), dropping",
						pb.typ, typ, code)
					retbuf <- pb
					continue
				}
			}
			if frag_if, frag_off, _, _ := pb.ipref_frag(); frag_if && frag_off != 0 {
				log.trace("icmp:    not first fragment, dropping")
				retbuf <- pb
				continue
			}

			if pb.len() > ICMP_ENCAP_MAX_LEN {
				pb.tail = pb.data + ICMP_ENCAP_MAX_LEN
			}
			iplen := pb.ipref_iplen()
			reflen := pb.ipref_reflen()
			new_reflen := max(min_reflen(src.Ref), min_reflen(cli.gw_ref))
			new_hdrs_len := 4 + iplen * 2 + new_reflen * 2 + ICMP_DATA
			if space_needed := new_hdrs_len - pb.data; space_needed > 0 {
				if len(pb.pkt) - pb.tail < space_needed {
					log.err("icmp:    not enough space in buffer for header, dropping")
					retbuf <- pb
					continue
				}
				copy(pb.pkt[new_hdrs_len:], pb.pkt[pb.data:pb.tail])
				pb.data, pb.tail = new_hdrs_len, new_hdrs_len + pb.len()
			}
			inner_ipref_hdr := pb.data
			outer_ipref_hdr := inner_ipref_hdr - new_hdrs_len
			icmp_hdr := inner_ipref_hdr - ICMP_DATA
			pb.data -= new_hdrs_len

			// build outer IPREF header
			pb.pkt[outer_ipref_hdr] = (0x1 << 4) | (ipref_encode_reflen(new_reflen) << 2)
			pb.pkt[outer_ipref_hdr + 1] = pb.pkt[inner_ipref_hdr + 1]
			pb.pkt[outer_ipref_hdr + 2] = IPREF_ICMP_SEND_TTL
			pb.pkt[outer_ipref_hdr + 3] = ICMP
			i := outer_ipref_hdr + 4
			if gw_iplen != iplen {
				panic("unexpected")
			}
			copy(pb.pkt[i:], cli.gw_pub_ip.AsSlice())
			i += iplen
			copy(pb.pkt[i:], src.IP.AsSlice())
			i += iplen
			ipref_encode_ref(pb.pkt[i : i + reflen], cli.gw_ref)
			i += reflen
			ipref_encode_ref(pb.pkt[i : i + reflen], src.Ref)

			// build ICMP header
			pb.pkt[icmp_hdr + ICMP_TYPE] = pb.icmp.typ
			pb.pkt[icmp_hdr + ICMP_CODE] = pb.icmp.code
			be.PutUint16(pb.pkt[icmp_hdr + ICMP_CSUM : icmp_hdr + ICMP_CSUM + 2], 0)
			be.PutUint16(pb.pkt[icmp_hdr + ICMP_CSUM + 2 : icmp_hdr + ICMP_CSUM + 4], 0)
			be.PutUint16(pb.pkt[icmp_hdr + ICMP_MTU : icmp_hdr + ICMP_MTU + 2], pb.icmp.mtu)
			icmp_csum := csum_add(0, pb.pkt[icmp_hdr:pb.tail])
			be.PutUint16(pb.pkt[icmp_hdr + ICMP_CSUM : icmp_hdr + ICMP_CSUM + 2], icmp_csum^0xffff)

			if pb.icmp.ours {
				verdict := ipref_deencap(pb, true, true, ICMP_ENCAP_MAX_DEPTH, true, false, true)
				if verdict == ACCEPT {
					send_tun <- pb
				} else {
					retbuf <- pb
				}
			} else {
				send_gw <- pb
			}
			continue
		}

		log.info("icmp:    received icmp request (%v %v %v %v), dropping for now",
			pb.typ, pb.icmp.typ, pb.icmp.code, pb.icmp.ours)
		retbuf <- pb
	}
}
