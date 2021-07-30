/* Copyright (c) 2018-2020 Waldemar Augustyn */

package main

import (
	"golang.org/x/sys/unix"
	"os"
	"strings"
	"time"
	"unsafe"
)

var recv_tun chan (*PktBuf)
var send_tun chan (*PktBuf)

func tun_sender(fd *os.File) {

	if cli.mbroker {
		return
	}

	for pb := range send_tun {

		if pb.data < TUN_HDR_LEN {
			log.fatal("tun out: not enough space for tun header data/tail(%v/%v)", pb.data, pb.tail)
		}

		pb.data -= TUN_HDR_LEN

		be.PutUint16(pb.pkt[pb.data+TUN_FLAGS:pb.data+TUN_FLAGS+2], TUN_IFF_TUN)
		be.PutUint16(pb.pkt[pb.data+TUN_PROTO:pb.data+TUN_PROTO+2], TUN_IPv4)

		if cli.debug["tun"] {
			log.debug("tun out: %v", pb.pp_pkt())
		}

		if cli.trace {
			pb.pp_net("tun out: ")
			pb.pp_tran("tun out: ")
			pb.pp_raw("tun out: ")
		}

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

	if cli.mbroker {
		return
	}

	var rlen int
	var err error

	for {

		pb := <-getbuf
		pb.data = ETHER_HDRLEN + OPTLEN
		pb.data += 3
		pb.data &^= 3 // align IP header on 32bit boundary
		pb.data -= TUN_HDR_LEN
		pkt := pb.pkt[pb.data:]

		maxmsg := 3
		for rlen, err = fd.Read(pkt); err != nil; {

			if maxmsg > 0 {
				log.err("tun in: error reading from tun interface: %v", err)
				maxmsg--
			}
			time.Sleep(769 * time.Millisecond)
		}

		if rlen < TUN_HDR_LEN+20 {
			log.err("tun in: packet too short, dropping")
			retbuf <- pb
			continue
		}

		proto := be.Uint16(pkt[TUN_PROTO : TUN_PROTO+2])
		if proto != ETHER_IPv4 {
			if cli.debug["tun"] {
				if proto == ETHER_IPv6 {
					log.debug("tun: IPv6 packet, dropping")
				} else {
					log.debug("tun in: non-IP packet: %04x, dropping", proto)
				}
			}
			retbuf <- pb
			continue
		}

		pb.tail = pb.data + rlen
		pb.data += TUN_HDR_LEN
		pkt = pb.pkt[pb.data:pb.tail]

		if pkt[IP_VER]&0xf0 != 0x40 {
			log.err("tun in: not an IPv4 packet, dropping")
			retbuf <- pb
			continue
		}

		pb.set_iphdr()

		if cli.debug["tun"] {
			log.debug("tun in: %v", pb.pp_pkt())
		}

		if cli.trace {
			pb.pp_net("tun in:  ")
			pb.pp_tran("tun in:  ")
			pb.pp_raw("tun in:  ")
		}

		recv_tun <- pb
	}
}

func start_tun() {

	var fd *os.File

	if !cli.mbroker {

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
		ea_ip := cli.ea_ip + 1 // hard code .1 as tun ip address
		ea_masklen := cli.ea_masklen
		mtu := cli.ifc.MTU - OPTLEN

		cmd, out, ret = shell("ip l set %v mtu %v", ifcname, mtu)
		if ret != 0 {
			log.debug("tun: %v", cmd)
			log.debug("tun: %v", strings.TrimSpace(out))
			log.fatal("tun: cannot set %v MTU: %v", ifcname, err)
		}

		cmd, out, ret = shell("ip a add %v/%v dev %v", ea_ip, ea_masklen, ifcname)
		if ret != 0 {
			log.debug("tun: %v", cmd)
			log.debug("tun: %v", strings.TrimSpace(out))
			log.fatal("tun: cannot set address on %v: %v", ifcname, err)
		}

		cmd, out, ret = shell("ip l set dev %v up", ifcname)
		if ret != 0 {
			log.debug("tun: %v", cmd)
			log.debug("tun: %v", strings.TrimSpace(out))
			log.fatal("tun: cannot bring %v up: %v", ifcname, err)
		}

		log.info("tun: netifc %v %v mtu(%v)", ea_ip, ifcname, mtu)
	}

	go tun_receiver(fd)
	go tun_sender(fd)
}
