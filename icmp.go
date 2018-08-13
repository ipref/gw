/* Copyright (c) 2018 Waldemar Augustyn */

package main

var icmpreq chan (*PktBuf)

func icmp() {

	for pb := range icmpreq {

		log.info("icmp: received icmp request (%v %v %v), dropping for now",
			pb.icmp.thype, pb.icmp.code, pb.icmp.mtu)
		retbuf <- pb
	}
}
