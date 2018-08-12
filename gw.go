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
		retbuf <- pb
	}
}

func gw_receiver() {

}
