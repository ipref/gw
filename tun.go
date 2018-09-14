/* Copyright (c) 2018 Waldemar Augustyn */

package main

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

}
