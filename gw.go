/* Copyright (c) 2018 Waldemar Augustyn */

package main

import (
	"net"
)

var recv_gw chan (*PktBuf)
var send_gw chan (*PktBuf)

func gw_sender() {

	for pb := range send_gw {

		log.debug("gw: pkt to send to gw interface  IP(%v)  %v  %v  len(%v)",
			pb.pkt[pb.data+IP_PROTO], net.IP(pb.pkt[pb.data+IP_SRC:pb.data+IP_SRC+4]),
			net.IP(pb.pkt[pb.data+IP_DST:pb.data+IP_DST+4]),
			be.Uint16(pb.pkt[pb.data+IP_LEN:pb.data+IP_LEN+2]))
		if log.level <= TRACE {
			pb.pp_net("gw out:  ")
		}

		if DEVEL_ECHO { // echo/discard for development

			pb.set_iphdr()
			pb.set_udphdr()
			pkt := pb.pkt

			if pkt[pb.iphdr+IP_PROTO] == UDP && be.Uint16(pkt[pb.udphdr+UDP_SPORT:pb.udphdr+UDP_SPORT+2]) == IPREF_PORT {

				encap := pb.udphdr + 8
				opt := encap + 4
				udp := opt + uint(pkt[opt+OPT_LEN])

				// ipref discard

				if pkt[encap+ENCAP_PROTO] == UDP && be.Uint16(pkt[udp+UDP_DPORT:udp+UDP_DPORT+2]) == DISCARD {
					retbuf <- pb
					continue
				}

				// ipref echo

				if pkt[encap+ENCAP_PROTO] == UDP && be.Uint16(pkt[udp+UDP_DPORT:udp+UDP_DPORT+2]) == ECHO {

					ip := []byte{0, 0, 0, 0}
					optport := []byte{0, 0}
					ttl := byte(0)
					ref_l := []byte{0, 0, 0, 0, 0, 0, 0, 0}
					ref_h := []byte{0, 0, 0, 0, 0, 0, 0, 0}
					port := []byte{0, 0}

					copy(ip, pkt[pb.iphdr+IP_SRC:pb.iphdr+IP_SRC+4])
					copy(optport, pkt[pb.udphdr+UDP_SPORT:pb.udphdr+UDP_SPORT+2])
					ttl = pkt[encap+ENCAP_TTL]
					if pkt[opt+OPTLEN] == IPREF_OPT64_LEN {
						copy(ref_l, pkt[opt+OPT_SREF64:opt+OPT_SREF64+8])
					} else {
						copy(ref_h, pkt[opt+OPT_SREF128:opt+OPT_SREF128+8])
						copy(ref_l, pkt[opt+OPT_SREF128+8:opt+OPT_SREF128+16])
					}
					copy(port, pkt[udp+UDP_SPORT:udp+UDP_SPORT+2])

					copy(pkt[pb.iphdr+IP_SRC:pb.iphdr+IP_SRC+4], pkt[pb.iphdr+IP_DST:pb.iphdr+IP_DST+4])
					copy(pkt[pb.udphdr+UDP_SPORT:pb.udphdr+UDP_SPORT+2], pkt[pb.udphdr+UDP_DPORT:pb.udphdr+UDP_DPORT+2])
					pkt[encap+ENCAP_TTL] = pkt[encap+ENCAP_HOPS]
					if pkt[opt+OPTLEN] == IPREF_OPT64_LEN {
						copy(pkt[opt+OPT_SREF64:opt+OPT_SREF64+8], pkt[opt+OPT_DREF64:opt+OPT_DREF64+8])
					} else {
						copy(pkt[opt+OPT_SREF128:opt+OPT_SREF128+8], pkt[opt+OPT_DREF128:opt+OPT_DREF128+8])
						copy(pkt[opt+OPT_SREF128+8:opt+OPT_SREF128+16], pkt[opt+OPT_DREF128+8:opt+OPT_DREF128+16])
					}
					copy(pkt[udp+UDP_SPORT:udp+UDP_SPORT+2], pkt[udp+UDP_DPORT:udp+UDP_DPORT+2])

					copy(pkt[pb.iphdr+IP_DST:pb.iphdr+IP_DST+4], ip)
					copy(pkt[pb.udphdr+UDP_DPORT:pb.udphdr+UDP_DPORT+2], optport)
					pkt[encap+ENCAP_HOPS] = ttl
					if pkt[opt+OPTLEN] == IPREF_OPT64_LEN {
						copy(pkt[opt+OPT_DREF64:opt+OPT_DREF64+8], ref_l)
					} else {
						copy(pkt[opt+OPT_DREF128:opt+OPT_DREF128+8], ref_h)
						copy(pkt[opt+OPT_DREF128+8:opt+OPT_DREF128+16], ref_l)
					}
					copy(pkt[udp+UDP_DPORT:udp+UDP_DPORT+2], port)

					recv_gw <- pb
					continue
				}

			} else {

				// ip discard

				if pkt[pb.iphdr+IP_PROTO] == UDP && be.Uint16(pkt[pb.udphdr+UDP_DPORT:pb.udphdr+UDP_DPORT+2]) == DISCARD {
					retbuf <- pb
					continue
				}

				// ip echo

				if pkt[pb.iphdr+IP_PROTO] == UDP && be.Uint16(pkt[pb.udphdr+UDP_DPORT:pb.udphdr+UDP_DPORT+2]) == ECHO {

					ip := []byte{0, 0, 0, 0}
					port := []byte{0, 0}

					copy(ip, pkt[pb.iphdr+IP_SRC:pb.iphdr+IP_SRC+4])
					copy(port, pkt[pb.udphdr+UDP_SPORT:pb.udphdr+UDP_SPORT+2])

					copy(pkt[pb.iphdr+IP_SRC:pb.iphdr+IP_SRC+4], pkt[pb.iphdr+IP_DST:pb.iphdr+IP_DST+4])
					copy(pkt[pb.udphdr+UDP_SPORT:pb.udphdr+UDP_SPORT+2], pkt[pb.udphdr+UDP_DPORT:pb.udphdr+UDP_DPORT+2])

					copy(pkt[pb.iphdr+IP_DST:pb.iphdr+IP_DST+4], ip)
					copy(pkt[pb.udphdr+UDP_DPORT:pb.udphdr+UDP_DPORT+2], port)

					recv_gw <- pb
					continue
				}
			}
		}

		retbuf <- pb
	}
}

func gw_receiver() {

}
