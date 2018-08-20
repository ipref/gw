/* Copyright (c) 2018 Waldemar Augustyn */

package main

import (
	"os"
	"os/signal"
	"syscall"
)

const DEVEL_ECHO = true // enable internal discard/echo for development

var goexit chan (string)

func catch_signals() {

	sigchan := make(chan os.Signal, 1)
	signal.Notify(sigchan, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigchan

	signal.Stop(sigchan)
	goexit <- "signal(" + sig.String() + ")"
}

func main() {

	parse_cli() // also initializes log

	log.info("START meadow")

	goexit = make(chan string)
	go catch_signals()

	owners.init()
	marker.init()

	mapper_oid := owners.new_oid("mapper") // both mapper sets need the same oid and timer mark
	map_gw.init(mapper_oid)
	map_tun.init(mapper_oid)
	mapper_mark := marker.now()
	map_gw.set_cur_mark(mapper_oid, mapper_mark)
	map_tun.set_cur_mark(mapper_oid, mapper_mark)

	getbuf = make(chan *PktBuf, 1)
	retbuf = make(chan *PktBuf, MAXBUF)

	icmpreq = make(chan *PktBuf, PKTQLEN)

	recv_tun = make(chan *PktBuf, PKTQLEN)
	send_tun = make(chan *PktBuf, PKTQLEN)
	recv_gw = make(chan *PktBuf, PKTQLEN)
	send_gw = make(chan *PktBuf, PKTQLEN)
	echo = make(chan *PktBuf, PKTQLEN) // for development only

	random_dns_ref = make(chan Ref, GENQLEN)
	random_mapper_ref = make(chan Ref, GENQLEN)
	random_dns_ea = make(chan IP32, GENQLEN)
	random_mapper_ea = make(chan IP32, GENQLEN)

	go gen_dns_refs()
	go gen_mapper_refs()
	go gen_dns_eas()
	go gen_mapper_eas()

	go pkt_buffers()
	go dns_watcher()

	go icmp()

	go fwd_to_gw()
	go fwd_to_tun()

	go gw_receiver()
	go gw_sender()

	go tun_receiver()
	go tun_sender()

	go timer()

	msg := <-goexit

	log.info("FINISH meadow: %v", msg)
}
