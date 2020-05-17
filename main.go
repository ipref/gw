/* Copyright (c) 2018-2020 Waldemar Augustyn */

package main

import (
	"fmt"
	rff "github.com/ipref/ref"
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

	go pkt_buffers()

	getbuf = make(chan *PktBuf, 1)
	retbuf = make(chan *PktBuf, cli.maxbuf)
	dbchan = make(chan *PktBuf, PKTQLEN)

	start_db()

	owners.init()
	owners.db_restore()

	mapper_oid = owners.get_oid("mapper")

	marker.init()
	marker.db_restore()

	map_gw.init(mapper_oid)
	map_tun.init(mapper_oid)
	mmark := marker.now()
	map_gw.set_cur_mark(mapper_oid, mmark)
	map_tun.set_cur_mark(mapper_oid, mmark)
	map_gw.db_restore()
	map_tun.db_restore()

	gen_ea.init()
	gen_ea.db_restore()

	//gen_ref.init()
	//gen_ref.db_restore()

	stop_db_restore()

	mapper_mark := marker.now()
	map_gw.set_cur_mark(mapper_oid, mapper_mark)
	map_tun.set_cur_mark(mapper_oid, mapper_mark)

	icmpreq = make(chan *PktBuf, PKTQLEN)

	recv_tun = make(chan *PktBuf, PKTQLEN)
	send_tun = make(chan *PktBuf, PKTQLEN)
	recv_gw = make(chan *PktBuf, PKTQLEN)
	send_gw = make(chan *PktBuf, PKTQLEN)

	random_mapper_ref = make(chan rff.Ref, GENQLEN)

	mbchan = make(chan *PktBuf, PKTQLEN)

	go gen_mapper_refs()
	gen_ea.start()

	go dns_watcher()

	go icmp()

	go fwd_to_gw()
	go fwd_to_tun()

	start_gw()
	start_tun()

	go timer_tick()
	go arp_tick()

	go mbroker_conn()
	go mbroker()

	msg := <-goexit
	stop_db()
	log.info("STOP ipref gateway: %v", msg)
}
