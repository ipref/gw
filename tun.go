/* Copyright (c) 2018 Waldemar Augustyn */

package main

import (
	"net"
	"time"
)

var recv_tun chan (*PktBuf)
var send_tun chan (*PktBuf)

func tun_sender() {

	for pb := range send_tun {

		log.debug("tun: pkt to send to tun interface  IP(%v)  %v  %v  len(%v)",
			pb.pkt[pb.data+IP_PROTO], net.IP(pb.pkt[pb.data+IP_SRC:pb.data+IP_SRC+4]),
			net.IP(pb.pkt[pb.data+IP_DST:pb.data+IP_DST+4]),
			be.Uint16(pb.pkt[pb.data+IP_LEN:pb.data+IP_LEN+2]))
		if log.level <= TRACE {
			pb.pp_net("tun out: ")
		}
		retbuf <- pb
	}
}

func tun_receiver() {

	pb := <-getbuf
	pb.fill(UDP)

	time.Sleep(1879 * time.Microsecond)

	log.debug("tun: pkt received from tun interface  IP(%v)  %v  %v  len(%v)",
		pb.pkt[pb.data+IP_PROTO], net.IP(pb.pkt[pb.data+IP_SRC:pb.data+IP_SRC+4]),
		net.IP(pb.pkt[pb.data+IP_DST:pb.data+IP_DST+4]),
		be.Uint16(pb.pkt[pb.data+IP_LEN:pb.data+IP_LEN+2]))
	if log.level <= TRACE {
		pb.pp_net("tun in:  ")
		pb.pp_tran("tun in:  ")
		pb.pp_raw("tun in:  ")
	}

	recv_tun <- pb
}
