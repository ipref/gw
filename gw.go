/* Copyright (c) 2018 Waldemar Augustyn */

package main

import (
	"github.com/mdlayher/raw"
	"net"
)

const (
	EtherIPv4 = 0x0800
)

var recv_gw chan *PktBuf
var send_gw chan *PktBuf

func gw_sender(con net.PacketConn) {

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

		// send raw packet

		// return buffer to the pool

		retbuf <- pb
	}
}

func gw_receiver(con net.PacketConn) {

}

func start_gw() {

	con, err := raw.ListenPacket(&cli.ifc, EtherIPv4, &raw.Config{false, true, false})
	if err != nil {
		log.fatal("gw:  cannot get raw socket: %v", err)
	}

	go gw_sender(con)
	go gw_receiver(con)
}
