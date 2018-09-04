/* Copyright (c) 2018 Waldemar Augustyn */

package main

import (
	"bufio"
	"crypto/rand"
	"net"
	"os"
	"strings"
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

				log.debug("tun out: %v  rt: %v [µs]  min/avg/max %v %v %v",
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

	// Read /etc/hosts file to get some addresses

	us := make([]IP32, 0, 256)
	them := make([]IP32, 0, 256)

	fd, err := os.Open(cli.hosts_path)
	if err != nil {
		log.fatal("tun in:  cannot read %v file", cli.hosts_path)
	}

	fs := bufio.NewScanner(fd)
	for fs.Scan() {
		toks := strings.Fields(fs.Text())
		if len(toks) == 0 || toks[0][0] == '#' {
			continue
		}

		addr := net.ParseIP(toks[0])
		if addr == nil {
			continue
		}
		addr = addr.To4()

		if addr[0] == 10 {
			them = append(them, IP32(be.Uint32(addr)))
		} else {
			us = append(us, IP32(be.Uint32(addr)))
		}

	}
	fd.Close()

	log.debug("tun in:  ip addresses read:")
	log.debug("tun in:      us %3d", len(us))
	log.debug("tun in:    them %3d", len(them))

	if len(us) == 0 || len(them) == 0 {
		log.fatal("tun in:  not enough addresses read")
	}

	num_pkts := len(them)/20 + 1

	log.debug("tun in:  sending %v packets", num_pkts)

	creep := make([]byte, 4)

	// Send packet from random sources to random destinations

	for ii := 0; ii < num_pkts; ii++ {

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

		// put random src and dst addresses

		_, err = rand.Read(creep)
		if err != nil {
			continue // cannot get random number
		}

		srcix := int(be.Uint16(creep[0:2])) % len(us)
		dstix := int(be.Uint16(creep[2:4])) % len(them)
		if ii%7 == 0 { // make some packets originate from addresses not in dns
			src := us[srcix]
			src &= 0xffff
			src |= 0xac150000 // 172.21.x.x
			be.PutUint32(pb.pkt[pb.data+IP_SRC:pb.data+IP_SRC+4], uint32(src))
		} else {
			be.PutUint32(pb.pkt[pb.data+IP_SRC:pb.data+IP_SRC+4], uint32(us[srcix]))
		}
		be.PutUint32(pb.pkt[pb.data+IP_DST:pb.data+IP_DST+4], uint32(them[dstix]))

		pb.fill_csum()

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
