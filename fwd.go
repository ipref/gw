/* Copyright (c) 2018-2021 Waldemar Augustyn */

package main

import . "github.com/ipref/common"

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

func fwd_to_gw() {

	for pb := range recv_tun {

		verdict := DROP

		switch pb.typ {

		case PKT_IPv4, PKT_IPv6:

			verdict = ipref_encap(pb, true, false, ICMP_ENCAP_MAX_DEPTH, true, cli.dec_ttl, true)
			if verdict == ACCEPT {
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

	// If pb.typ == PKT_IPREF, then this uses pb.gw_hint and pb.rgw_hint
	for pb := range recv_gw {

		verdict := DROP

		switch pb.typ {

		case PKT_IPREF:

			verdict = ipref_deencap(pb, false, true, ICMP_ENCAP_MAX_DEPTH, true, cli.dec_ttl, true)
			if verdict == ACCEPT {
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
