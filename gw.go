/* Copyright (c) 2018 Waldemar Augustyn */

package main

var recv_gw chan (*PktBuf)
var send_gw chan (*PktBuf)

func gw_sender() {

	pb := <-send_gw

	log.debug("sending pkt to gw")
	if log.level <= TRACE {
		pb.pp_net()
		pb.pp_tran()
		pb.pp_raw()
	}

	retbuf <- pb

	goexit <- "ok"
}

func gw_receiver() {

}
