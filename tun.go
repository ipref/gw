/* Copyright (c) 2018-2021 Waldemar Augustyn */

package main

import (
	"golang.org/x/sys/unix"
	"net/netip"
	"os"
	"strings"
	"time"
	"unsafe"
)

const (
	TUN_HDR_LEN = 4
	TUN_IFF_TUN = uint16(0x0001)
	// TUN header offsets
	TUN_FLAGS = 0
	TUN_PROTO = 2
	// ETHER types
	ETHER_IPv4 = 0x0800
	ETHER_IPv6 = 0x86dd
	// ETHER offsets
	ETHER_DST_MAC = 0
	ETHER_SRC_MAC = 6
	ETHER_TYPE    = 12
	ETHER_HDRLEN = 6 + 6 + 2

	TUN_RECV_OFF = IPREF_HDR_MAX_LEN +
		(IPv6_HDR_MIN_LEN + IPv6_FRAG_HDR_LEN - IPv4_HDR_MIN_LEN) +
		(IPREF_HDR_MAX_LEN - IPREF_HDR_MIN_LEN) -
		TUN_HDR_LEN
)

var recv_tun chan (*PktBuf)
var send_tun chan (*PktBuf)

func tun_sender(fd *os.File) {

	if cli.devmode {
		return
	}

	for pb := range send_tun {

		if cli.debug["tun"] {
			log.debug("tun out: %v", pb.pp_pkt())
		}

		if cli.trace {
			pb.pp_net("tun out: ")
			pb.pp_tran("tun out: ")
			// pb.pp_raw("tun out: ")
		}

		var proto uint16
		switch pb.typ {
		case PKT_IPv4:
			proto = ETHER_IPv4
		case PKT_IPv6:
			proto = ETHER_IPv6
		default:
			log.fatal("tun out: not an IPv4/6 packet (%v)", pb.typ)
		}

		if pb.data < TUN_HDR_LEN {
			log.err("tun out: not enough space for tun header data/tail(%v/%v), dropping", pb.data, pb.tail)
			retbuf <- pb
			continue
		}
		pb.data -= TUN_HDR_LEN

		be.PutUint16(pb.pkt[pb.data+TUN_FLAGS:pb.data+TUN_FLAGS+2], TUN_IFF_TUN)
		be.PutUint16(pb.pkt[pb.data+TUN_PROTO:pb.data+TUN_PROTO+2], proto)

		wlen, err := fd.Write(pb.pkt[pb.data:pb.tail])
		if err != nil {
			log.err("tun out: send to tun interface failed: %v", err)
		} else if wlen != pb.tail-pb.data {
			log.err("tun out: send to tun interface truncated: wlen(%v) data/tail(%v/%v)",
				wlen, pb.data, pb.tail)
		}

		retbuf <- pb
	}
}

func tun_receiver(fd *os.File) {

	if cli.devmode {
		return
	}

	var rlen int
	var err error

	for {

		pb := <-getbuf
		pb.data = TUN_RECV_OFF
		pkt := pb.pkt[pb.data:]

		maxmsg := 3
		for rlen, err = fd.Read(pkt); err != nil; {

			if maxmsg > 0 {
				log.err("tun in: error reading from tun interface: %v", err)
				maxmsg--
			}
			time.Sleep(769 * time.Millisecond)
		}

		if rlen < TUN_HDR_LEN + min(IPv4_HDR_MIN_LEN, IPv6_HDR_MIN_LEN) {
			log.err("tun in: packet too short, dropping")
			retbuf <- pb
			continue
		}
		if rlen == len(pkt) {
			log.err("tun in: read from tun interface truncated: rlen(%v) data/len(%v/%v)",
				rlen, pb.data, len(pkt))
			retbuf <- pb
			continue
		}

		proto := be.Uint16(pkt[TUN_PROTO : TUN_PROTO+2])
		var ipver byte
		switch proto {
		case ETHER_IPv4:
			pb.typ = PKT_IPv4
			ipver = 4
		case ETHER_IPv6:
			pb.typ = PKT_IPv6
			ipver = 6
		default:
			if cli.debug["tun"] {
				log.debug("tun in: non-IP packet: %04x, dropping", proto)
			}
			retbuf <- pb
			continue
		}

		pb.tail = pb.data + rlen
		pb.data += TUN_HDR_LEN
		pkt = pb.pkt[pb.data:pb.tail]

		if pkt[IP_VER] >> 4 != ipver {
			log.err("tun in: invalid IP packet version, dropping")
			retbuf <- pb
			continue
		}

		if cli.debug["tun"] {
			log.debug("tun in: %v", pb.pp_pkt())
		}

		if cli.trace {
			pb.pp_net("tun in:  ")
			pb.pp_tran("tun in:  ")
			// pb.pp_raw("tun in:  ")
		}

		recv_tun <- pb
	}
}

func start_tun() {

	var fd *os.File

	if !cli.devmode {

		var cmd string
		var out string
		var ret int
		var ufd int
		var err error

		// create tun device

		type IfReq struct {
			name  [unix.IFNAMSIZ]byte
			flags uint16
			pad   [40 - unix.IFNAMSIZ - 2]byte
		}

		ufd, err = unix.Open("/dev/net/tun", os.O_RDWR, 0)
		if err != nil {
			log.fatal("tun: cannot get tun device: %v", err)
		}

		ifreq := IfReq{flags: unix.IFF_TUN}

		_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(ufd), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&ifreq)))
		if errno != 0 {
			log.fatal("tun: cannot setup tun device, errno(%v)", errno)
		}

		err = unix.SetNonblock(ufd, true)
		if err != nil {
			log.fatal("tun: cannot make tun device non blocking, errno(%v)", errno)
		}

		fd = os.NewFile(uintptr(ufd), "/dev/net/tun")
		if fd == nil {
			log.fatal("tun: invalid tun device")
		}

		// bring tun device up

		ifcname := strings.Trim(string(ifreq.name[:]), "\x00")
		ea_ipb := cli.ea_net.Addr().AsSlice()
		ea_ipb[len(ea_ipb)-1] = 1 // hard code .1 as tun ip address
		ea_ip, _ := netip.AddrFromSlice(ea_ipb)
		ea_masklen := cli.ea_net.Bits()
		mtu := cli.ifc.MTU - UDP_HDR_LEN - IPREF_HDR_MAX_LEN
		if cli.ea_net.Addr().Is4() {
			mtu += IPv4_HDR_MIN_LEN
		} else {
			mtu += IPv6_HDR_MIN_LEN
		}
		if cli.gw_ip.Is4() {
			mtu += (16 - 4) * 2
		}
		mtu += 3
		mtu &^= 3
		if cli.ea_net.Addr().Is4() {
			mtu = max(mtu, 68)
		} else {
			mtu = max(mtu, 1280)
		}

		cmd, out, ret = shell("ip l set %v mtu %v", ifcname, mtu)
		if ret != 0 {
			log.debug("tun: %v", cmd)
			log.debug("tun: %v", strings.TrimSpace(out))
			log.fatal("tun: cannot set %v MTU", ifcname)
		}

		cmd, out, ret = shell("ip a add %v/%v dev %v", ea_ip, ea_masklen, ifcname)
		if ret != 0 {
			log.debug("tun: %v", cmd)
			log.debug("tun: %v", strings.TrimSpace(out))
			log.fatal("tun: cannot set address on %v", ifcname)
		}

		cmd, out, ret = shell("ip l set dev %v up", ifcname)
		if ret != 0 {
			log.debug("tun: %v", cmd)
			log.debug("tun: %v", strings.TrimSpace(out))
			log.fatal("tun: cannot bring %v up", ifcname)
		}

		log.info("tun: netifc %v %v mtu(%v)", ea_ip, ifcname, mtu)
	}

	go tun_receiver(fd)
	go tun_sender(fd)
}
