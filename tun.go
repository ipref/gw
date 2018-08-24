/* Copyright (c) 2018 Waldemar Augustyn */

package main

import (
	"time"
)

var recv_tun chan (*PktBuf)
var send_tun chan (*PktBuf)

func tun_sender() {

	var rt_num uint64
	var rt_sum uint64
	var rt_min uint64
	var rt_avg uint64
	var rt_max uint64

	for pb := range send_tun {

		if cli.debug["tun"] || cli.debug["all"] {

			pb.set_iphdr()
			pkt := pb.pkt[pb.iphdr:pb.tail]
			udp := pb.iphdr_len()
			if len(pkt) > 20 &&
				pkt[IP_PROTO] == UDP &&
				len(pkt) > pb.iphdr_len()+16 &&
				be.Uint16(pkt[udp+UDP_DPORT:udp+UDP_DPORT+2]) == 44123 {

				now_ux := uint64(time.Now().UnixNano())
				stamp := be.Uint64(pkt[udp+8 : udp+8+8])
				rt := (now_ux - stamp) / 1000

				rt_num++
				rt_sum += rt
				if rt_min == 0 || rt < rt_min {
					rt_min = rt
				}
				rt_avg = rt_sum / rt_num
				if rt_max < rt {
					rt_max = rt
				}

				log.debug("tun out: %v  rt: %v [us]  min/avg/max %v %v %v",
					pb.pp_pkt(), rt, rt_min, rt_avg, rt_max)
			} else {
				log.debug("tun out: %v", pb.pp_pkt())
			}
		}

		if log.level <= TRACE {
			pb.pp_net("tun out: ")
			pb.pp_tran("tun out: ")
			pb.pp_raw("tun out: ")
		}
		retbuf <- pb
	}
}

func tun_receiver() {

	// Send some packets

	for ii := 0; ii < 7; ii++ {

		time.Sleep(174879 * time.Microsecond)

		pb := <-getbuf
		pb.fill(UDP)

		if len(pb.pkt)-int(pb.data) < int(MIN_PKT_LEN+TUN_HDR_LEN) {

			log.err("tun in:  short packet data/end(%v/%v), dropping", pb.data, len(pb.pkt))
			retbuf <- pb
			return
		}

		if (be.Uint16(pb.pkt[pb.data+TUN_FLAGS:pb.data+TUN_FLAGS+2])&TUN_IFF_TUN) == 0 ||
			be.Uint16(pb.pkt[pb.data+TUN_PROTO:pb.data+TUN_PROTO+2]) != TUN_IPv4 {

			log.err("tun in:  not an IPv4 TUN packet: %08x, dropping", pb.pkt[pb.data:pb.data+4])
			retbuf <- pb
		}

		pb.data += TUN_HDR_LEN

		if cli.debug["tun"] || cli.debug["all"] {
			log.debug("tun in:  %v", pb.pp_pkt())
		}

		if log.level <= TRACE {
			pb.pp_net("tun in:  ")
			pb.pp_tran("tun in:  ")
			pb.pp_raw("tun in:  ")
		}

		recv_tun <- pb
	}
}
