/* Copyright (c) 2018-2021 Waldemar Augustyn */

package main

import (
	"net"
)

var recv_gw chan *PktBuf
var send_gw chan *PktBuf

func gw_sender(con *net.UDPConn) {

	for pb := range send_gw {

		switch pb.typ {

		case PKT_V1:

			pkt := pb.pkt[pb.data:pb.tail]

			if pkt[V1_CMD] == V1_SET_MARK {

				// update time mark

				off := V1_HDR_LEN
				oid := O32(be.Uint32(pkt[off+V1_OID : off+V1_OID+4]))
				if oid == arp_oid {
					// arp_marker = M32(be.Uint32(pkt[off+V1_MARK : off+V1_MARK+4]))
				} else {
					log.err("gw out:  arp timer update oid(%v) does not match arp_oid(%v), ignoring", oid, arp_oid)
				}
				retbuf <- pb
				continue

			} else {
				log.err("gw out:  unknown v1 packet data/end(%v/%v), dropping", pb.data, len(pb.pkt))
				retbuf <- pb
				continue
			}

		case PKT_IPREF:

			if cli.debug["gw"] {
				log.debug("gw out:  %v", pb.pp_pkt())
			}

			if cli.trace {
				pb.pp_net("gw out:  ")
				pb.pp_tran("gw out:  ")
				pb.pp_raw("gw out:  ")
			}

			src := []byte{0, 0, 0, 0}
			be.PutUint32(src, uint32(pb.src))
			dst := []byte{0, 0, 0, 0}
			be.PutUint32(dst, uint32(pb.dst))

			if pb.src != cli.gw_ip {
				log.fatal("gw out:  src(%v) is not gateway", pb.src)
			}

			daddr := net.UDPAddr{dst, int(pb.dport), ""}
			wlen, err := con.WriteToUDP(pb.pkt[pb.data:pb.tail], &daddr)
			if err != nil {
				log.fatal("gw out:  write failed: %v", err)
			}
			if wlen != pb.tail - pb.data {
				log.fatal("gw out:  write failed")
			}

			retbuf <- pb

		default:
			log.fatal("gw out:  unknown packet type: %v", pb.typ)
		}
	}
}

func gw_receiver(con *net.UDPConn) {

	if cli.devmode {
		return
	}

	for {

		pb := <-getbuf
		pb.typ = PKT_IPREF
		pb.data = TUN_HDR_LEN + IPREF_HDR_MAX_LEN - IP_HDR_MIN_LEN

		rlen, addr, err := con.ReadFromUDP(pb.pkt[pb.data:])
		if cli.debug["gw"] {
			log.debug("gw in:   src IP: %v  rcvlen(%v)", addr, rlen)
		}
		if err != nil {
			log.err("gw in:   read failed: %v", err)
			goto drop
		}
		if rlen == 0 || rlen == len(pb.pkt) - pb.data {
			log.err("gw in:   read failed")
			goto drop
		}
		pb.tail = pb.data + rlen
		pb.src = IP32(be.Uint32(addr.IP))
		pb.sport = uint16(addr.Port)
		pb.dst = cli.gw_ip
		pb.dport = IPREF_PORT

		if cli.debug["gw"] {
			log.debug("gw in:   %v", pb.pp_pkt())
		}

		if cli.trace {
			pb.pp_net("gw in:   ")
			pb.pp_tran("gw in:   ")
			pb.pp_raw("gw in:   ")
		}

		recv_gw <- pb
		continue

	drop:
		retbuf <- pb
	}

}

func start_gw() {

	var con *net.UDPConn

	if !cli.devmode {

		var err error

		gw_ip := []byte{0, 0, 0, 0}
		be.PutUint32(gw_ip, uint32(cli.gw_ip))
		con, err = net.ListenUDP("udp4", &net.UDPAddr{gw_ip, IPREF_PORT, ""})
		if err != nil {
			log.fatal("gw: cannot listen on UDP: %v", err)
		}

		log.info("gw: gateway %v %v mtu(%v) %v pkt buffers",
			cli.gw_ip, cli.ifc.Name, cli.ifc.MTU, cli.maxbuf)
	}

	go gw_sender(con)
	go gw_receiver(con)
}
