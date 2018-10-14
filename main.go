/* Copyright (c) 2018 Waldemar Augustyn */

package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
)

var goexit chan (string)

func shell(cmdline string, args ...interface{}) (string, string, int) {

	ret := 0
	cmd := fmt.Sprintf(cmdline, args...)
	runcmd := exec.Command("/bin/sh", "-c", cmd)
	runcmd.Dir = "/"
	out, err := runcmd.CombinedOutput()

	// find out exit code which should be non-negative
	if err != nil {
		toks := strings.Fields(err.Error())
		if len(toks) == 3 && toks[0] == "exit" && toks[1] == "status" {
			res, err := strconv.ParseInt(toks[2], 0, 0)
			if err == nil {
				ret = int(res)
			} else {
				ret = -1
			}
		} else {
			ret = -1 // some other error, not an exit code
		}
	}
	return cmd, strings.TrimSpace(string(out)), ret
}

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

	mapper_oid = owners.new_oid("mapper") // both mapper sets need the same oid and timer mark
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

	start_gw()
	start_tun()

	go timer_tick()
	go purge_tick()
	go arp_tick()

	msg := <-goexit

	log.info("FINISH meadow: %v", msg)
}
