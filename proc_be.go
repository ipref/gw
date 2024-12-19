// Copyright (c) 2018 Waldemar Augustyn

//go:build armbe || arm64be || ppc64 || mips || mips64 || mips64p32 || ppc || s390 || s390x || sparc || sparc64
// +build armbe arm64be ppc64 mips mips64 mips64p32 ppc s390 s390x sparc sparc64

package main

import "strconv"

// Some items in /proc are dumped without regard for endianness. We have to
// make proper adjustments.

// helper to read ipv4 addresses
func proc2ip(addr string) IP32 {

	if len(addr) != 8 {
		log.fatal("gw: length of IP address string is not 8: %v", addr)
	}

	var ip IP32

	for ii := 0; ii < 8; ii += 2 {
		bb, err := strconv.ParseUint(addr[ii:ii+2], 16, 8)
		if err != nil {
			log.fatal("gw: cannot parse bytes from %v: %v", addr, err)
		}
		ip |= IP32(bb) << IP32(24-4*ii)
	}

	return ip
}
