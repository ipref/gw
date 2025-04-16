/* Copyright (c) 2018-2021 Waldemar Augustyn */

package main

import (
	lru "github.com/hashicorp/golang-lru/v2/expirable"
	. "github.com/ipref/common"
	"golang.org/x/sys/unix"
	"os"
	"crypto/rand"
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

var tun_mtucache *lru.LRU[IP, int]

func tun_update_mtu(ip IP, mtu int) {
	log.trace("tun:     update local mtu(%v)  %v", mtu, ip)
	tun_mtucache.Add(ip, mtu)
}

// Packet inspection (eg. for detecting PMTU from ICMP messages).
func inspect_from_tun(pb *PktBuf) {

	pkt := pb.pkt

	switch pb.typ {

	case PKT_IPv6:

		if pb.len() < IPv6_HDR_MIN_LEN {
			return
		}
		if (pkt[pb.data+IP_VER] & 0xf0 != 0x60) {
			return
		}
		ip_pld_len := int(be.Uint16(pkt[pb.data+IPv6_PLD_LEN:pb.data+IPv6_PLD_LEN+2]))
		if IPv6_HDR_MIN_LEN + ip_pld_len != pb.len() {
			return
		}
		proto := pkt[pb.data+IPv6_NEXT]
		// ttl := pkt[pb.data+IPv6_TTL]
		src := IPFromSlice(pkt[pb.data+IPv6_SRC : pb.data+IPv6_SRC+16])
		// dst := IPFromSlice(pkt[pb.data+IPv6_DST : pb.data+IPv6_DST+16])
		l4 := pb.data + IPv6_HDR_MIN_LEN
		l4_pkt_len := pb.tail - l4

		// Update the mtu if packet is bigger, and mark the IP as recent in the
		// cache.
		if mtu, exists := tun_mtucache.Get(src); exists && pb.len() > mtu {
			tun_update_mtu(src, pb.len())
		}

		switch proto {

		case ICMPv6:

			if l4_pkt_len < ICMP_DATA {
				return
			}
			typ := pkt[l4+ICMP_TYPE]
			code := pkt[l4+ICMP_CODE]

			switch {

			case typ == ICMPv6_PACKET_TOO_BIG && code == 0:

				mtu := be.Uint32(pkt[l4+ICMP_BODY:])
				if mtu >> 16 != 0 || mtu < 1280 {
					return
				}
				inner_ip_hdr := l4 + ICMP_DATA
				if pb.tail - inner_ip_hdr < IPv6_HDR_MIN_LEN {
					return
				}
				orig_dst := IPFromSlice(pkt[inner_ip_hdr+IPv6_DST : inner_ip_hdr+IPv6_DST+16])
				tun_update_mtu(orig_dst, int(mtu))
			}
		}
	}
}

func tun_sender(fd *os.File) {

	if cli.devmode {
		return
	}

	// uses pb.df if pb.typ == PKT_IPv6
	for pb := range send_tun {
	next_fragment:

		if cli.debug["tun"] {
			log.debug("tun out: %v", pb.pp_pkt())
		}

		if cli.trace {
			pb.pp_net("tun out: ")
			pb.pp_tran("tun out: ")
			// pb.pp_raw("tun out: ")
		}

		var proto uint16
		var sent, trimmed int
		var orig_mf bool
		switch pb.typ {

		case PKT_IPv4:

			proto = ETHER_IPv4

		case PKT_IPv6:

			proto = ETHER_IPv6
			if !pb.df {
				dst := IPFromSlice(pb.pkt[pb.data+IPv6_DST : pb.data+IPv6_DST+16])
				if mtu, exists := tun_mtucache.Get(dst); exists && mtu > 0 {
					var status IPv6FragInPlaceStatus
					sent, trimmed, orig_mf, status = ipv6_frag_in_place(pb, mtu)
					switch status {
					case IPv6_FRAG_IN_PLACE_NOT_NEEDED:
					case IPv6_FRAG_IN_PLACE_SUCCESS:
						log.trace("tun out: fragmenting (%v + %v)", sent, trimmed)
					case IPv6_FRAG_IN_PLACE_SPACE:
						log.err("tun out: not enough space in buffer to fragment, dropping")
						retbuf <- pb
						continue
					default:
						panic("unexpected")
					}
				}
			}

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
		} else {
			pb.data += TUN_HDR_LEN
			if trimmed != 0 {
				frag_off := ipv6_next_frag_in_place(pb, trimmed, orig_mf)
				log.trace("tun out: moving on to next fragment (%v)", frag_off)
				goto next_fragment
			}
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

		inspect_from_tun(pb)

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

		cmd, out, ret = shell("ip a add %v/%v dev %v", cli.ea_ip, ea_masklen, ifcname)
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

		log.info("tun: netifc %v %v mtu(%v)", cli.ea_ip, ifcname, mtu)
	}

	tun_mtucache = lru.NewLRU[IP, int](max(cli.maxlips, 1), nil, 0)

	go tun_receiver(fd)
	go tun_sender(fd)
}

type IPv6FragInPlaceStatus int

const (
	IPv6_FRAG_IN_PLACE_NOT_NEEDED = IPv6FragInPlaceStatus(iota)
	IPv6_FRAG_IN_PLACE_SUCCESS    = IPv6FragInPlaceStatus(iota) // fragmented
	IPv6_FRAG_IN_PLACE_SPACE      = IPv6FragInPlaceStatus(iota) // not enough space
)

func ipv6_frag_in_place(pb *PktBuf, mtu int) (
	sent, trimmed int, orig_mf bool, status IPv6FragInPlaceStatus) {

	if pb.len() <= mtu {
		status = IPv6_FRAG_IN_PLACE_NOT_NEEDED
		return
	}

	// Calculate sizes
	ipv6_hdr_len := IPv6_HDR_MIN_LEN
	frag_if := false
	if pb.pkt[pb.data + IPv6_NEXT] == IPv6_FRAG_EXT {
		ipv6_hdr_len += IPv6_FRAG_HDR_LEN
		frag_if = true
	}
	l4_size := pb.len() - ipv6_hdr_len
	sent = ((l4_size + 1) / 2 + 7) / 8 * 8
	if !frag_if {
		// We're going to need that space to add the Fragment extension header.
		ipv6_hdr_len += IPv6_FRAG_HDR_LEN
	}
	if sent + ipv6_hdr_len > mtu {
		sent = (mtu - ipv6_hdr_len) / 8 * 8
	}
	trimmed = l4_size - sent
	if sent <= 0 || trimmed <= 0 {
		status = IPv6_FRAG_IN_PLACE_SPACE
		return
	}
	pb.tail -= trimmed
	be.PutUint16(pb.pkt[pb.data+IPv6_PLD_LEN:], uint16(IPv6_FRAG_HDR_LEN + sent))

	if frag_if {
		frag_ext := pb.pkt[pb.data+IPv6_HDR_MIN_LEN:]
		frag_field := be.Uint16(frag_ext[IPv6_FRAG_OFF:])
		orig_mf = frag_field & 1 != 0
		frag_field |= 1
		be.PutUint16(frag_ext[IPv6_FRAG_OFF:], frag_field)
	} else {
		// Add Fragment extension header.
		if pb.data < IPv6_FRAG_HDR_LEN {
			status = IPv6_FRAG_IN_PLACE_SPACE
			return
		}
		pb.data -= IPv6_FRAG_HDR_LEN
		copy(pb.pkt[pb.data:pb.data+IPv6_HDR_MIN_LEN], pb.pkt[pb.data+IPv6_FRAG_HDR_LEN:])
		frag_ext := pb.pkt[pb.data+IPv6_HDR_MIN_LEN:]
		pb.pkt[pb.data+IPv6_NEXT], frag_ext[IPv6_FRAG_NEXT] = IPv6_FRAG_EXT, pb.pkt[pb.data+IPv6_NEXT]
		frag_ext[1] = 0
		be.PutUint16(frag_ext[IPv6_FRAG_OFF:], 1)
		rand.Read(frag_ext[IPv6_FRAG_IDENT:IPv6_FRAG_IDENT+4])
	}

	status = IPv6_FRAG_IN_PLACE_SUCCESS
	return
}

func ipv6_next_frag_in_place(pb *PktBuf, trimmed int, orig_mf bool) int {

	if pb.pkt[pb.data + IPv6_NEXT] != IPv6_FRAG_EXT {
		panic("unexpected")
	}
	ipv6_hdr_len := IPv6_HDR_MIN_LEN + IPv6_FRAG_HDR_LEN
	sent := pb.len() - ipv6_hdr_len
	if sent <= 0 || sent & 7 != 0 {
		panic("unexpected")
	}

	// Move the header to just before the data that was trimmed/not yet sent.
	copy(pb.pkt[pb.tail-ipv6_hdr_len:], pb.pkt[pb.data:pb.data+ipv6_hdr_len])
	pb.data = pb.tail - ipv6_hdr_len
	pb.tail += trimmed

	// Set new payload length
	be.PutUint16(pb.pkt[pb.data+IPv6_PLD_LEN:], uint16(IPv6_FRAG_HDR_LEN + trimmed))

	// Adjust Fragment extension header.
	frag_ext := pb.pkt[pb.data+IPv6_HDR_MIN_LEN:]
	frag_off := int(be.Uint16(frag_ext[IPv6_FRAG_OFF:]) &^ 7)
	frag_off += sent
	if frag_off >> 16 != 0 {
		panic("unexpected")
	}
	frag_field := uint16(frag_off)
	if orig_mf {
		frag_field |= 1
	}
	be.PutUint16(frag_ext[IPv6_FRAG_OFF:], frag_field)

	return frag_off
}
