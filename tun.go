/* Copyright (c) 2018 Waldemar Augustyn */

package main

import (
	"time"
)

var recv_tun chan (*PktBuf)
var send_tun chan (*PktBuf)

func tun_sender() {

	for pb := range send_tun {

		if cli.debug["tun"] || cli.debug["all"] {
			log.debug("tun out: %v", pb.pp_pkt())
		}

		if log.level <= TRACE {
			pb.pp_net("tun out: ")
			pb.pp_tran("tun out: ")
			pb.pp_raw("tun out: ")
		}
		retbuf <- pb
	}
}

func tun_receiver() {

	pb := <-getbuf
	pb.fill(UDP)

	time.Sleep(1879 * time.Microsecond)

	if len(pb.pkt)-int(pb.data) < int(MIN_PKT_LEN+TUN_HDR_LEN) {

		log.err("tun in:  short packet data/end(%v/%v), dropping", pb.data, len(pb.pkt))
		retbuf <- pb
		return
	}

	if (be.Uint16(pb.pkt[pb.data+TUN_FLAGS:pb.data+TUN_FLAGS+2])&TUN_IFF_TUN) == 0 ||
		be.Uint16(pb.pkt[pb.data+TUN_PROTO:pb.data+TUN_PROTO+2]) != TUN_IPv4 {

		log.err("tun in:  not an IPv4 TUN packet: %08x, dropping", pb.pkt[pb.data:pb.data+4])
		retbuf <- pb
	}

	pb.data += TUN_HDR_LEN

	if cli.debug["tun"] || cli.debug["all"] {
		log.debug("tun in:  %v", pb.pp_pkt())
	}

	if log.level <= TRACE {
		pb.pp_net("tun in:  ")
		pb.pp_tran("tun in:  ")
		pb.pp_raw("tun in:  ")
	}

	recv_tun <- pb
}
