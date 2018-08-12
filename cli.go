/* Copyright (c) 2018 Waldemar Augustyn */

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var cli struct {
	debug      map[string]bool
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

	var debugstr string

	flag.StringVar(&debugstr, "debug", "", "enable debug in listed, comma separated files or 'all'")
	flag.BoolVar(&cli.trace, "trace", false, "enable packet trace")
	flag.BoolVar(&cli.stamps, "time-stamps", false, "print logs with time stamps")
	flag.StringVar(&cli.gw_ip, "gateway", "", "ip address of the public network interface")
	flag.StringVar(&cli.ea_net, "encode-net", "10.240.0.0/12", "private network for encoding external ipref addresses")
	flag.StringVar(&cli.hosts_path, "hosts", "/etc/hosts", "host name lookup file")
	flag.StringVar(&cli.dns_path, "dns", "", "dns file with IPREF addresses of local hosts")
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

	// parse debug string

	cli.debug = make(map[string]bool)

	for _, fname := range strings.Split(debugstr, ",") {

		if len(fname) == 0 {
			continue
		}
		bix := 0
		eix := len(fname)
		if ix := strings.LastIndex(fname, "/"); ix >= 0 {
			bix = ix + 1
		}
		if ix := strings.LastIndex(fname, "."); ix >= 0 {
			eix = ix
		}
		cli.debug[fname[bix:eix]] = true
	}

	// initialize logger

	if cli.trace {
		cli.log_level = TRACE
	} else {
		cli.log_level = INFO
	}

	log.set(cli.log_level, cli.stamps)

	// verify ip addresses

	cli.gw_ip = "192.168.84.93"

	// deduce mtu

	cli.gw_mtu = 1500

	// normalize file paths

	cli.hosts_path = normalize(cli.hosts_path)
	cli.dns_path = normalize(cli.dns_path)
}

func normalize(path string) string {

	if len(path) == 0 {
		return path
	}

	npath, err := filepath.Abs(path)
	if err != nil {
		log.fatal("invalid file path: %v: %v", path, err)
	}

	npath, err = filepath.EvalSymlinks(npath)
	if err != nil {
		log.fatal("invalid file path: %v: %v", path, err)
	}

	return npath
}
