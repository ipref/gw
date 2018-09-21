/* Copyright (c) 2018 Waldemar Augustyn */

package main

import (
	"github.com/mdlayher/raw"
	"golang.org/x/net/bpf"
	"net"
)

const (
	EtherIPv4 = 0x0800
)

var recv_gw chan *PktBuf
var send_gw chan *PktBuf

func gw_transmit_pkt(pb *PktBuf, mac []byte) {
}

func get_arp(pkt []byte) (IP32, []byte) {

	return 0, []byte{0, 0, 0, 0, 0, 0}
}

/* Send packets to next hop

Each go routine instance sends to one next hop. It is given the mac address
via v1 protocol. If no address, packets are queued, then released when mac
address becomes available.
*/
func gw_send_pkts(pkts <-chan *PktBuf) {

	var dst_ip IP32
	var dst_mac []byte
	var pktq []*PktBuf
	var last int

	for pb := range pkts {

		pkt := pb.pkt[pb.data:pb.tail]

		if pkt[V1_VER] == V1_SIG {

			// new arp info, save and send any packets on the queue

			dst_ip, dst_mac = get_arp(pkt)

			if dst_ip != 0 {

				for _, queued_pb := range pktq[:last] {
					gw_transmit_pkt(queued_pb, dst_mac)
					last = 0
				}
			}

			retbuf <- pb

		} else if dst_ip != 0 {

			// arp entry exists, transmit packet

			gw_transmit_pkt(pb, dst_mac)
			retbuf <- pb

		} else {

			// no arp entry, queue for better times

			pktq = append(pktq, pb)
			last++
		}

	}
}

func gw_sender(con net.PacketConn) {

	for pb := range send_gw {

		if len(pb.pkt)-int(pb.data) < MIN_PKT_LEN {

			log.err("gw out:  short packet data/end(%v/%v), dropping", pb.data, len(pb.pkt))
			retbuf <- pb
			continue
		}

		if cli.debug["gw"] || cli.debug["all"] {
			log.debug("gw out:  %v", pb.pp_pkt())
		}

		if log.level <= TRACE {
			pb.pp_net("gw out:  ")
			pb.pp_tran("gw out:  ")
			pb.pp_raw("gw out:  ")
		}

		// send raw packet

		// return buffer to the pool

		retbuf <- pb
	}
}

func gw_receiver(con net.PacketConn) {

	for {

		pb := <-getbuf

		rlen, haddr, err := con.ReadFrom(pb.pkt[pb.data:])
		log.debug("gw in: hdw addr: %v  rcvlen(%v)", haddr, rlen)
		pb.tail = rlen
		pb.pp_raw("gw_in:   ")
		if rlen == 0 {
			log.debug("gw in: read failed: %v", err)
		}

		retbuf <- pb
	}

}

func start_gw() {

	con, err := raw.ListenPacket(&cli.ifc, EtherIPv4, &raw.Config{false, true, false})
	if err != nil {
		log.fatal("gw:  cannot get raw socket: %v", err)
	}

	// filter IPREF packets: UDP with src or dst equal to IPREF_PORT

	filter, err := bpf.Assemble([]bpf.Instruction{
		bpf.LoadAbsolute{Off: 12, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: EtherIPv4, SkipTrue: 1},
		bpf.RetConstant{Val: 0}, // not IPv4 packet
		bpf.LoadAbsolute{Off: 14 + IP_DST, Size: 4},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(cli.gw_ip), SkipTrue: 1},
		bpf.RetConstant{Val: 0}, // not our gateway IP address
		bpf.LoadAbsolute{Off: 14 + IP_PROTO, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: UDP, SkipTrue: 1},
		bpf.RetConstant{Val: 0}, // not UDP
		bpf.LoadMemShift{Off: 14 + IP_VER},
		bpf.LoadIndirect{Off: 14 + UDP_SPORT, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: IPREF_PORT, SkipTrue: 1},
		bpf.RetConstant{Val: uint32(cli.pktbuflen)}, // src port match, copy packet
		bpf.LoadIndirect{Off: 14 + UDP_DPORT, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: IPREF_PORT, SkipTrue: 1},
		bpf.RetConstant{Val: uint32(cli.pktbuflen)}, // dst port match, copy packet
		bpf.RetConstant{Val: 0},                     // no match, ignore packet
	})

	if err != nil {
		log.fatal("gw:  cannot assemble bpf filter: %v", err)
	}

	err = con.SetBPF(filter)

	if err != nil {
		log.fatal("gw:  cannot set bpf filter: %v", err)
	}

	go gw_sender(con)
	go gw_receiver(con)
}
