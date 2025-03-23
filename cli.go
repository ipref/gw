/* Copyright (c) 2018-2021 Waldemar Augustyn */

package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

const (
	ddir = "/var/lib/ipref"
)

var cli struct { // no locks, once setup in cli, never modified thereafter
	debuglist  string
	devmode    bool
	ticks      bool
	trace      bool
	stamps     bool
	datadir    string
	gw         string
	ea         string
	hosts_path string
	sockname   string
	maxbuf     int
	maxrgws    int
	// derived
	debug      map[string]bool
	ea_ip      IP32
	ea_mask    IP32
	ea_masklen int
	gw_ip      IP32
	ifc        net.Interface
	pktbuflen  int
	log_level  uint
}

func parse_cli() {

	flag.StringVar(&cli.debuglist, "debug", "", "enable debug in listed files, comma separated")
	flag.BoolVar(&cli.ticks, "ticks", false, "include timer ticks in debug")
	flag.BoolVar(&cli.trace, "trace", false, "enable packet trace")
	flag.BoolVar(&cli.devmode, "devmode", false, "development mode, disable forwarding, run as a standalone mapper broker")
	flag.BoolVar(&cli.stamps, "time-stamps", false, "print logs with time stamps")
	flag.StringVar(&cli.datadir, "data", ddir, "data directory")
	flag.StringVar(&cli.gw, "gateway", "", "ip address of the public network interface")
	flag.StringVar(&cli.sockname, "mapper-socket", "/run/ipref/mapper.sock", "path to mapper unix socket")
	flag.StringVar(&cli.ea, "encode-net", "10.240.0.0/12", "private network for encoding external ipref addresses")
	flag.StringVar(&cli.hosts_path, "hosts", "/etc/hosts", "host name lookup file")
	flag.IntVar(&cli.maxbuf, "max-buffers", 64, "max number of packet buffers")
	flag.IntVar(&cli.maxrgws, "max-remote-gateways", 1024, "maximum number of remote gateways to track at a time")
	flag.Usage = func() {
		toks := strings.Split(os.Args[0], "/")
		prog := toks[len(toks)-1]
		fmt.Println("User space implementation of IPREF gateway. It supports single gateway")
		fmt.Println("configuration where all Internet traffic passes through it.")
		fmt.Println("")
		fmt.Println("   ", prog, "[FLAGS]")
		fmt.Println("")
		flag.PrintDefaults()
	}
	flag.Parse()

	// initialize logger

	cli.debug = make(map[string]bool)

	for _, fname := range strings.Split(cli.debuglist, ",") {

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

	if cli.trace {
		cli.log_level = TRACE
	} else {
		cli.log_level = INFO
	}

	log.set(cli.log_level, cli.stamps)

	if cli.devmode {

		cli.gw = "198.51.100.1"
		cli.gw_ip = IP32(be.Uint32(net.ParseIP(cli.gw).To4()))
		cli.ifc.MTU = 1500

	} else {

		// parse gw addresses

		gw := net.ParseIP(cli.gw)
		if gw == nil {
			if len(cli.gw) == 0 {
				log.fatal("missing gateway IP address")
			} else {
				log.fatal("invalid gateway IP address: %v", cli.gw)
			}
		}

		if !gw.IsGlobalUnicast() {
			log.fatal("gateway IP address is not a valid unicast address: %v", cli.gw)
		}
		cli.gw_ip = IP32(be.Uint32(gw.To4()))

		// deduce gw interface

		ifcs, err := net.Interfaces()
		if err != nil {
			log.fatal("cannot get interface data: %v", err)
		}
	ifc_loop:
		for _, ifc := range ifcs {
			addrs, err := ifc.Addrs()
			if err == nil {
				for _, addr := range addrs {
					ip := net.ParseIP(strings.Split(addr.String(), "/")[0]) // addr string: 192.168.80.10/24
					if ip == nil {
						continue
					}
					ip4 := ip.To4()
					if ip4 == nil {
						continue
					}
					if IP32(be.Uint32(ip4)) == cli.gw_ip {
						cli.ifc = ifc
						break ifc_loop
					}
				}
			}
		}

		if cli.ifc.Index == 0 {
			log.fatal("cannot find interface with gw address %v", cli.gw_ip)
		}
	}

	cli.pktbuflen = cli.ifc.MTU - IPv4_HDR_MIN_LEN + IPREF_HDR_MAX_LEN + 8
	cli.pktbuflen += 3
	cli.pktbuflen &^= 3

	// parse ea net

	_, ipnet, err := net.ParseCIDR(cli.ea)
	if err != nil {
		log.fatal("invalid encode-net: %v", cli.ea)
	}

	if !ipnet.IP.IsGlobalUnicast() {
		log.fatal("encode-net is not a valid unicast address: %v", cli.ea)
	}

	ones, bits := ipnet.Mask.Size()
	if ones == 0 || ones > 16 || bits != 32 { // needs full second to last byte for allocation
		log.fatal("invalid encode-net mask: %v", cli.ea)
	}

	cli.ea_ip = IP32(be.Uint32(ipnet.IP.To4()))
	cli.ea_mask = IP32(be.Uint32(net.IP(ipnet.Mask).To4()))
	cli.ea_masklen = ones
	cli.ea_ip &= cli.ea_mask

	// validate file paths

	cli.datadir = absolute("data directory path", cli.datadir)
	cli.sockname = absolute("socket path", cli.sockname)
	cli.hosts_path = absolute("host file path", cli.hosts_path)

	// validate maxbuf

	if cli.maxbuf < 16 {
		cli.maxbuf = 16
	}
	if cli.maxbuf > 1024 {
		cli.maxbuf = 1024
	}
}

func absolute(desc, path string) string {

	if len(path) == 0 {
		log.fatal("missing %v", desc)
	}

	apath, err := filepath.Abs(path)
	if err != nil {
		log.fatal("invalid %v: %v: %v", desc, path, err)
	}
	return apath
}
