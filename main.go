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

	go pkt_buffers()
	go fwd_to_gw()

	msg := <-goexit

	log.info("finish meadow: %v", msg)
}
