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

	owners.init()
	marker.init()

	goexit = make(chan string)
	go catch_signals()

	go gen_dns_refs()
	go gen_mapper_refs()

	getbuf = make(chan *PktBuf, 1)
	retbuf = make(chan *PktBuf, MAXBUF)

	recv_tun = make(chan *PktBuf, PKTQLEN)
	send_tun = make(chan *PktBuf, PKTQLEN)
	recv_gw = make(chan *PktBuf, PKTQLEN)
	send_gw = make(chan *PktBuf, PKTQLEN)

	go pkt_buffers()
	go dns_watcher()

	go fwd_to_gw()
	go fwd_to_tun()

	go gw_receiver()
	go gw_sender()

	go tun_receiver()
	go tun_sender()

	msg := <-goexit

	log.info("FINISH meadow: %v", msg)
}
