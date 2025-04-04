/* Copyright (c) 2018-2021 Waldemar Augustyn */

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

	log.info("START ipref gateway")

	goexit = make(chan string)
	go catch_signals()

	getbuf = make(chan *PktBuf, 1)
	retbuf = make(chan *PktBuf, cli.maxbuf)
	go pkt_buffers()

	recv_tun = make(chan *PktBuf, PKTQLEN)
	send_tun = make(chan *PktBuf, PKTQLEN)
	recv_gw = make(chan *PktBuf, PKTQLEN)
	send_gw = make(chan *PktBuf, PKTQLEN)
	go fwd_to_gw()
	go fwd_to_tun()

	mb.init()
	owners.init()
	marker.init()
	gen_ea.init()
	gen_ref.init()

	db.init()
	db.start()

	// start of restoration from DB, write directly to the related data objects

	owners.restore_oids()

	mapper_oid = owners.get_oid("mapper")

	map_gw.init(mapper_oid)
	map_tun.init(mapper_oid)

	marker.restore_time_base()
	marker.restore_markers()

	send_marker(marker.now(), mapper_oid, "main")

	map_gw.restore_eas()
	map_tun.restore_refs()

	db.stop_restore()

	// end of restoration from DB

	icmpreq = make(chan *PktBuf, PKTQLEN)

	gen_ea.start()
	gen_ref.start()

	go dns_watcher()

	go icmp()

	start_gw()
	start_tun()

	go timer_tick()

	mb.start()

	//if cli.devmode {
	//	go induce_ea_allocation()
	//	go induce_ref_allocation()
	//}

	msg := <-goexit
	db.stop()
	log.info("STOP ipref gateway: %v", msg)
}
