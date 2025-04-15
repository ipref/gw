/* Copyright (c) 2018-2021 Waldemar Augustyn */

package main

import (
	"flag"
	"fmt"
	rff "github.com/ipref/ref"
	"net"
	"net/netip"
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
	maxlips    int
	// derived
	debug      map[string]bool
	ea_net     netip.Prefix
	ea_ip      IP
	ea_gwip    IP
	gw_ip      IP
	gw_port    int
	rgw_port   int
	gw_refstr  string
	dec_ttl    bool
	gw_ref     rff.Ref
	ifc        net.Interface
	pktbuflen  int
	log_level  uint
}

var ea_iplen int
var gw_iplen int

func is_ea_iplen(ip IP) IP {
	if ip.Len() != ea_iplen {
		panic("invalid IP length")
	}
	return ip
}

func is_gw_iplen(ip IP) IP {
	if ip.Len() != gw_iplen {
		panic("invalid IP length")
	}
	return ip
}

var v1_arec_len int

func parse_cli() {

	flag.StringVar(&cli.debuglist, "debug", "", "enable debug in listed files, comma separated")
	flag.BoolVar(&cli.ticks, "ticks", false, "include timer ticks in debug")
	flag.BoolVar(&cli.trace, "trace", false, "enable packet trace")
	flag.BoolVar(&cli.devmode, "devmode", false, "development mode, disable forwarding, run as a standalone mapper broker")
	flag.BoolVar(&cli.stamps, "time-stamps", false, "print logs with time stamps")
	flag.StringVar(&cli.datadir, "data", ddir, "data directory")
	flag.StringVar(&cli.gw, "gateway", "", "ip address of the public network interface")
	flag.IntVar(&cli.gw_port, "gateway-port", 0, "port to listen on for the gateway")
	flag.IntVar(&cli.rgw_port, "remote-gateway-port", 0, "default destination port when sending to remote gateways")
	flag.StringVar(&cli.gw_refstr, "gateway-ref", "1", "ref to use for the gateway's own ipref address")
	flag.BoolVar(&cli.dec_ttl, "dec-ttl", false, "decrement ttl when forwarding packets")
	flag.StringVar(&cli.sockname, "mapper-socket", "/run/ipref/mapper.sock", "path to mapper unix socket")
	flag.StringVar(&cli.ea, "encode-net", "10.240.0.0/12", "private network for encoding external ipref addresses")
	flag.StringVar(&cli.hosts_path, "hosts", "/etc/hosts", "host name lookup file")
	flag.IntVar(&cli.maxbuf, "max-buffers", 64, "max number of packet buffers")
	flag.IntVar(&cli.maxrgws, "max-remote-gateways", 1024, "maximum number of remote gateways to track at a time")
	flag.IntVar(&cli.maxlips, "max-local-ips", 1024, "maximum number of local IPs to track at a time")
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
		cli.gw_ip = MustParseIP(cli.gw)
		cli.ifc.MTU = 1500

	} else {

		// parse gw addresses

		gw, err := ParseIP(cli.gw)
		if err != nil {
			if len(cli.gw) == 0 {
				log.fatal("missing gateway IP address")
			} else {
				log.fatal("invalid gateway IP address: %v", cli.gw)
			}
		}

		if !netip.Addr(gw).IsGlobalUnicast() {
			log.fatal("gateway IP address is not a valid unicast address: %v", cli.gw)
		}
		cli.gw_ip = gw

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
					net, err := netip.ParsePrefix(addr.String())
					if err != nil {
						log.err("unrecognized address for interface %v: %v", ifc, addr)
						continue
					}
					if net.Contains(netip.Addr(cli.gw_ip)) {
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
	gw_iplen = cli.gw_ip.Len()

	if cli.gw_port <= 0 || cli.gw_port > 0xffff {
		cli.gw_port = IPREF_PORT
	}
	if cli.rgw_port <= 0 || cli.rgw_port > 0xffff {
		cli.rgw_port = IPREF_PORT
	}
	var err error
	cli.gw_ref, err = rff.Parse(cli.gw_refstr)
	if err != nil {
		log.fatal("invalid gateway reference \"%v\": %v", cli.gw_refstr, err)
	}

	cli.pktbuflen = TUN_HDR_LEN + TUN_RECV_OFF + cli.ifc.MTU + 8
	cli.pktbuflen += 7
	cli.pktbuflen &^= 7

	// parse ea net

	cli.ea_net, err = netip.ParsePrefix(cli.ea)
	if err != nil {
		log.fatal("invalid encode-net: %v", cli.ea)
	}
	cli.ea_net = cli.ea_net.Masked()
	if cli.ea_net.Addr().BitLen() - cli.ea_net.Bits() < 16 {
		log.fatal("invalid encode-net (subnet not large enough, need at least 16 bits): %v", cli.ea)
	}
	if !cli.ea_net.Addr().IsGlobalUnicast() {
		log.fatal("encode-net is not a valid unicast address: %v", cli.ea)
	}
	cli.ea_ip = IP(cli.ea_net.Addr())
	ea_iplen = cli.ea_ip.Len()
	ea_gwipb := cli.ea_ip.AsSlice()
	ea_gwipb[len(ea_gwipb)-1] = 1 // hard code .1 as gw address on ea network
	cli.ea_gwip = IPFromSlice(ea_gwipb)

	v1_arec_len = ea_iplen * 2 + gw_iplen + 16 // ea + ip + gw + ref.h + ref.l

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
