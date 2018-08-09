/* Copyright (c) 2018 Waldemar Augustyn */

package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

const (
	ICMP    = 1
	TCP     = 6
	UDP     = 17
	OPTLEN  = uint(8 + 4 + 4 + 16 + 16) // udphdr + encap + opt + ref + ref
	TUNHDR  = uint(4)
	PKTQLEN = 2
)

var be = binary.BigEndian

/* PktBuf helper functions */

func (pb *PktBuf) pp_raw() {

	// RAW  45 00 00 74 2e 52 40 00 40 11 d0 b6 0a fb 1b 6f c0 a8 54 5e 04 15 04 15 00 ..

	const max = 128
	var sb strings.Builder

	pkt := pb.pkt[pb.data:pb.tail]
	sb.WriteString("RAW ")
	for ii := 0; ii < len(pkt); ii++ {
		if ii < max {
			sb.WriteString(" ")
			sb.WriteString(hex.EncodeToString(pkt[ii : ii+1]))
		} else {
			sb.WriteString("  ..")
			break
		}
	}
	log.trace(sb.String())
}

func (pb *PktBuf) pp_net() {

	// IP[udp] 4500  192.168.84.93  10.254.22.202  len(64) id(1) ttl(64) frag:4000 csum:0000

	var sb strings.Builder

	pkt := pb.pkt[pb.iphdr:pb.tail]
	if (len(pkt) < 20) || (pkt[0]&0xf0 != 0x40) || (len(pkt) < int((pkt[0]&0xf)*4)) {
		sb.WriteString("NON-IP ")
		if len(pkt) >= 2 {
			sb.WriteString(hex.EncodeToString(pkt[:2]))
		}
		log.trace(sb.String())
		return
	}

	switch pkt[9] {
	case TCP:
		sb.WriteString("IP[tcp] ")
	case UDP:
		sb.WriteString("IP[udp] ")
	case ICMP:
		sb.WriteString("IP[ICMP] ")
	default:
		sb.WriteString(fmt.Sprintf("IP[%v]", pkt[9]))
	}
	sb.WriteString(hex.EncodeToString(pkt[:2]))
	sb.WriteString("  ")
	sb.WriteString(net.IP(pkt[12:16]).String())
	sb.WriteString("  ")
	sb.WriteString(net.IP(pkt[16:20]).String())
	sb.WriteString(fmt.Sprintf("  len(%v)", be.Uint16(pkt[2:4])))
	sb.WriteString(fmt.Sprintf(" id(%v)", be.Uint16(pkt[4:6])))
	sb.WriteString(fmt.Sprintf(" ttl(%v)", pkt[8]))
	sb.WriteString(fmt.Sprintf(" frag:%04x", be.Uint16(pkt[6:8])))
	sb.WriteString(fmt.Sprintf(" csum:%04x", be.Uint16(pkt[10:12])))

	log.trace(sb.String())
}

func (pb *PktBuf) pp_tran() {

	pkt := pb.pkt[pb.iphdr:pb.tail]
	if len(pkt) < 20 {
		return
	}

	var sb strings.Builder
	off := (pkt[0] & 0xf) * 4

	switch pkt[9] {
	case TCP:
	case UDP:

		// UDP  1045  1045  len(96) csum 0

		if len(pkt) < int(off+8) {
			return
		}
		sb.WriteString("UDP")
		sb.WriteString(fmt.Sprintf("  %v", be.Uint16(pkt[off+0:off+2])))
		sb.WriteString(fmt.Sprintf("  %v", be.Uint16(pkt[off+2:off+4])))
		sb.WriteString(fmt.Sprintf("  len(%v)", be.Uint16(pkt[off+4:off+6])))
		sb.WriteString(fmt.Sprintf(" csum:%04x", be.Uint16(pkt[off+6:off+8])))

	case ICMP:
	default:
		return
	}

	log.trace(sb.String())
}

func (pb *PktBuf) fill_iphdr() {

	pb.iphdr = pb.tail
	pb.tail += 20

	be.PutUint16(pb.pkt[pb.iphdr+0:pb.iphdr+2], 0x4500)
	be.PutUint16(pb.pkt[pb.iphdr+2:pb.iphdr+4], uint16(pb.tail-pb.iphdr)) // pktlen
	be.PutUint16(pb.pkt[pb.iphdr+4:pb.iphdr+6], 0x0001)                   // id
	be.PutUint16(pb.pkt[pb.iphdr+6:pb.iphdr+8], 0x4000)                   // DF + fragment offset
	pb.pkt[pb.iphdr+8] = 64                                               // ttl
	pb.pkt[pb.iphdr+9] = 0                                                // protocol
	be.PutUint16(pb.pkt[pb.iphdr+10:pb.iphdr+12], 0x0000)                 // hdr csum
	copy(pb.pkt[pb.iphdr+12:pb.iphdr+16], []byte{192, 168, 84, 93})       // src
	copy(pb.pkt[pb.iphdr+16:pb.iphdr+20], []byte{192, 168, 84, 94})       // dst
}

func (pb *PktBuf) fill_udphdr() {

	pb.udphdr = pb.tail
	pb.tail += 8

	pb.pkt[pb.iphdr+9] = UDP

	be.PutUint16(pb.pkt[pb.udphdr+0:pb.udphdr+2], 44123)                     // src port
	be.PutUint16(pb.pkt[pb.udphdr+2:pb.udphdr+4], 2177)                      // dst port
	be.PutUint16(pb.pkt[pb.udphdr+4:pb.udphdr+6], uint16(pb.tail-pb.udphdr)) // datalen
	be.PutUint16(pb.pkt[pb.udphdr+6:pb.udphdr+8], 0x0000)                    // udp csum

	be.PutUint16(pb.pkt[pb.iphdr+2:pb.iphdr+4], uint16(pb.tail-pb.iphdr)) // pktlen
}

func (pb *PktBuf) fill_payload() {

	bb := byte(7)
	beg := pb.tail
	pb.tail += 64

	for ii := beg; ii < pb.tail; ii++ {
		pb.pkt[ii] = bb
		bb++
	}

	switch pb.pkt[pb.iphdr+9] {
	case UDP:
		be.PutUint16(pb.pkt[pb.udphdr+4:pb.udphdr+6], uint16(pb.tail-pb.udphdr)) // datalen
	}
	be.PutUint16(pb.pkt[pb.iphdr+2:pb.iphdr+4], uint16(pb.tail-pb.iphdr)) // pktlen
}

func (pb *PktBuf) fill(proto int) {

	if len(pb.pkt) < int(cli.gw_mtu+TUNHDR) {
		log.fatal("packet buffer too short: %v, needs %v", len(pb.pkt), cli.gw_mtu+TUNHDR)
	}

	pb.data = OPTLEN + TUNHDR
	pb.tail = pb.data
	pb.fill_iphdr()

	switch proto {
	case TCP:
	case UDP:
		pb.fill_udphdr()
		pb.fill_payload()
	case ICMP:
	}
}

func insert_ipref_option(pb *PktBuf) int {
	return DROP
}

func remove_ipref_option(pb *PktBuf) int {
	return DROP
}

func fwd_to_gw() {

	their_ipref = make(map[uint32]IpRefRec)
	our_ipref = make(map[uint32]IpRefRec)

	for pb := range recv_tun {

		pb.qualify()
		switch {

		case pb.iphdr != 0:

			verdict := insert_ipref_option(pb)
			switch verdict {
			case ACCEPT:
				send_gw <- pb
			case DROP:
				retbuf <- pb
			case STOLEN:
			default:
				log.err("fwd_to_gw: unknown verdict: %v, dropping", verdict)
				retbuf <- pb
			}

		case pb.arechdr != 0:
			retbuf <- pb
		case pb.tmrhdr != 0:
			retbuf <- pb
		default:
			log.err("fwd_to_gw: unknown packet, dropping")
			retbuf <- pb
		}
	}
}

func fwd_to_tun() {

	our_ip = make(map[uint32]map[Ref]IpRec)
	our_ea = make(map[uint32]map[Ref]IpRec)

	for pb := range recv_gw {

		pb.qualify()
		switch {

		case pb.iphdr != 0:

			verdict := remove_ipref_option(pb)
			switch verdict {
			case ACCEPT:
				send_tun <- pb
			case DROP:
				retbuf <- pb
			case STOLEN:
			default:
				log.err("fwd_to_gw: unknown verdict: %v, dropping", verdict)
				retbuf <- pb
			}

		case pb.arechdr != 0:
			retbuf <- pb
		case pb.tmrhdr != 0:
			retbuf <- pb
		default:
			log.err("fwd_to_gw: unknown packet, dropping")
			retbuf <- pb
		}
	}
}
