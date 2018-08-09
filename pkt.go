/* Copyright (c) 2018 Waldemar Augustyn */

package main

const (
	MAXBUF = 10
)

const ( // packet handling verdicts

	ACCEPT = iota + 1
	DROP
	STOLEN
)

const ( // internal packet constants (Ipv1)

	V1_HDRLEN = 16
	V1_CMDIX  = 1
	V1_SRCQIX = 2
	V1_DSTQIX = 3
	V1_MARKIX = 4
)

const ( // data item types

	V1_AREC = iota + 1
)

const ( // internal packet types

	V1_PKT_AREC = iota + 1
	V1_PKT_TMR
)

const ( // AREC commands

	V1_SET_HOSTS_REC = iota + 1
)

const ( // TMR commands

	V1_PURGE_EXPIRED = iota + 1
)

type PktBuf struct {
	pkt     []byte
	data    uint
	tail    uint
	iphdr   uint
	udphdr  uint
	tcphdr  uint
	icmphdr uint
	arechdr uint
	tmrhdr  uint
}

func (pb *PktBuf) len() int {
	return int(pb.tail - pb.data)
}

func (pb *PktBuf) qualify() {

	pblen := pb.len()

	if pblen == 0 { // empty pkt
		return
	}

	if (pb.pkt[pb.data] & 0xf0) == 0x40 { // IPv4 pkt
		pb.iphdr = pb.data
		return
	}

	// we use IPv1 for internal packet types

	if (pb.pkt[pb.data]&0xf0) != 0x10 || pblen < 16 {
		log.err("PktBuf: unexpected packet type: %v len(%v)", pb.pkt[pb.data]>>4, pblen)
		return
	}

	switch pb.pkt[pb.data] & 0x0f {
	case V1_PKT_AREC:
		pb.arechdr = pb.data
	case V1_PKT_TMR:
		pb.tmrhdr = pb.data
	default:
		log.err("PktBuf: unknown packet type: %v", pb.pkt[pb.data]&0x0f)
	}
}

var getbuf chan (*PktBuf)
var retbuf chan (*PktBuf)

/* Buffer allocator

We use getbuf channel of length 1. As soon as it gets empty we try to put
a packet into it.  We try to get it from the retbuf but if not availale we
allocate a new one but no more than MAXBUF in total. If we exceed this
limit and no packets in retbuf, we wait until one is returned.
*/
func pkt_buffers() {

	var pb *PktBuf
	allocated := 0 // num of allocated buffers

	for {

		if allocated < MAXBUF {
			select {
			case pb = <-retbuf:
			default:
				pb = &PktBuf{pkt: make([]byte, cli.gw_mtu+TUNHDR, cli.gw_mtu+TUNHDR)}
				allocated += 1
				log.info("new PktBuf allocated, total(%v)", allocated)
			}
		} else {
			pb = <-retbuf
		}

		pb.data = 0
		pb.tail = 0
		pb.iphdr = 0
		pb.arechdr = 0
		pb.tmrhdr = 0

		getbuf <- pb
	}
}
