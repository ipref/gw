/* Copyright (c) 2018 Waldemar Augustyn */

package main

import (
	"time"
)

var recv_tun chan (*PktBuf)
var send_tun chan (*PktBuf)

func tun_sender() {

}

func tun_receiver() {

	pb := <-getbuf
	pb.fill(UDP)

	time.Sleep(879 * time.Microsecond)

	log.debug("received pkt from tun")
	if log.level <= TRACE {
		pb.pp_net()
		pb.pp_tran()
		pb.pp_raw()
	}

	recv_tun <- pb
}
