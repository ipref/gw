/* Copyright (c) 2018 Waldemar Augustyn */

package main

var goexit chan (string)

func main() {

	parse_cli()
	log.set(cli.log_level, cli.stamps)

	log.info("start meadow")

	goexit = make(chan string)

	getbuf = make(chan *PktBuf, 1)
	retbuf = make(chan *PktBuf, MAXBUF)

	recv_tun = make(chan *PktBuf, PKTQLEN)
	send_tun = make(chan *PktBuf, PKTQLEN)
	recv_gw = make(chan *PktBuf, PKTQLEN)
	send_gw = make(chan *PktBuf, PKTQLEN)

	go pkt_buffers()
	go fwd_to_gw()

	go gw_receiver()
	go gw_sender()

	go tun_receiver()
	go tun_sender()

	msg := <-goexit

	log.info("finish meadow: %v", msg)
}
