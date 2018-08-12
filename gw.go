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
			pb.pkt[pb.data+9], net.IP(pb.pkt[pb.data+12:pb.data+16]),
			net.IP(pb.pkt[pb.data+16:pb.data+20]),
			be.Uint16(pb.pkt[pb.data+2:pb.data+4]))
		if log.level <= TRACE {
			pb.pp_net("gw out:  ")
		}

		if DEVEL_ECHO { // echo/discard for development

			pb.set_iphdr()
			pb.set_udphdr()
			pkt := pb.pkt

			// discard

			if pkt[pb.iphdr+9] == 17 && be.Uint16(pkt[pb.udphdr+2:pb.udphdr+4]) == 9 {
				retbuf <- pb
				continue
			}

			// echo

			if pkt[pb.iphdr+9] == 17 && be.Uint16(pkt[pb.udphdr+2:pb.udphdr+4]) == 7 {

				ip := []byte{0, 0, 0, 0}
				port := []byte{0, 0}

				copy(ip, pkt[pb.iphdr+12:pb.iphdr+16])
				copy(port, pkt[pb.udphdr+0:pb.udphdr+2])

				copy(pkt[pb.iphdr+12:pb.iphdr+16], pkt[pb.iphdr+16:pb.iphdr+20])
				copy(pkt[pb.udphdr+0:pb.udphdr+2], pkt[pb.udphdr+2:pb.udphdr+4])

				copy(pkt[pb.iphdr+16:pb.iphdr+20], ip)
				copy(pkt[pb.udphdr+2:pb.udphdr+4], port)

				recv_gw <- pb
				continue
			}
		}

		retbuf <- pb
	}
}

func gw_receiver() {

}
