/* Copyright (c) 2018 Waldemar Augustyn */

package main

var icmpreq chan (*PktBuf)

const (
	// icmp types
	ICMP_DEST_UNREACH  = 3
	ICMP_SOURCE_QUENCH = 4
	ICMP_REDIRECT      = 5
	ICMP_TIME_EXCEEDED = 11

	// icmp codes for ICMP_DEST_UNREACH
	ICMP_NET_UNREACH  = 0
	ICMP_HOST_UNREACH = 1
	ICMP_PROT_UNREACH = 2
	ICMP_PORT_UNREACH = 3
	ICMP_FRAG_NEEDED  = 4
	ICMP_NET_UNKNOWN  = 6
	ICMP_HOST_UNKNOWN = 7

	// icmp codes for ICMP_TIME_EXCEEDED
	ICMP_EXC_TTL = 0
)

func icmp() {

	for pb := range icmpreq {

		log.info("icmp: received icmp request (%v %v %v), dropping for now",
			pb.icmp.typ, pb.icmp.code, pb.icmp.mtu)
		retbuf <- pb
	}
}
