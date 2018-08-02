/* Copyright (c) 2018 Waldemar Augustyn */

package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

var cli struct {
	debug      bool
	trace      bool
	stamps     bool
	gw_ip      string
	ea_net     string
	hosts_path string
	dns_path   string
	// derived
	gw_mtu    uint
	log_level uint
}

func parse_cli() {

	flag.BoolVar(&cli.debug, "debug", false, "enable debug messages")
	flag.BoolVar(&cli.trace, "trace", false, "enable packet trace")
	flag.BoolVar(&cli.stamps, "time-stamps", false, "print logs with time stamps")
	flag.StringVar(&cli.gw_ip, "gateway", "", "ip address on the interface connected to public network")
	flag.StringVar(&cli.ea_net, "encode-net", "10.240.0.0/12", "private network for encoding external ipref addresses")
	flag.StringVar(&cli.hosts_path, "hosts", "/etc/hosts", "static host name lookup file")
	flag.StringVar(&cli.dns_path, "dns", "", "advertised ipref hosts file")
	flag.Usage = func() {
		toks := strings.Split(os.Args[0], "/")
		prog := toks[len(toks)-1]
		fmt.Println("User space implementation of IPREF routing. It supports single router")
		fmt.Println("configuration where all Internet traffic passes through it. It provides")
		fmt.Println("IPREF packet processing for local networks.")
		fmt.Println("")
		fmt.Println("   ", prog, "[FLAGS]")
		fmt.Println("")
		flag.PrintDefaults()
	}
	flag.Parse()

	cli.gw_mtu = 1500

	if cli.trace {
		cli.log_level = TRACE
	} else if cli.debug {
		cli.log_level = DEBUG
	} else {
		cli.log_level = INFO
	}
}
