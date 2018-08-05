/* Copyright (c) 2018 Waldemar Augustyn */

package main

var goexit chan (string)

func main() {

	parse_cli() // also initializes log

	log.info("start meadow")

	goexit = make(chan string)

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

	log.info("finish meadow: %v", msg)
}
