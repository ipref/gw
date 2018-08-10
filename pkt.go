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

	V1_HDRLEN   = 16
	V1_CMD      = 1
	V1_SRCQ     = 2
	V1_DSTQ     = 3
	V1_MARK     = 4
	V1_OID      = 8
	V1_RESERVED = 12

	V1_AREC_LEN = 4 + 4 + 4 + 8 + 8 // ea + ip + gw + ref.h + ref.l
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

func (pb *PktBuf) copy_from(pbo *PktBuf) {

	if len(pb.pkt) < int(pbo.tail) {
		log.fatal("pkt: buffer to small to copy from another pkt")
	}

	pb.data = pbo.data
	pb.tail = pbo.tail
	pb.iphdr = pbo.iphdr
	pb.udphdr = pbo.udphdr
	pb.tcphdr = pbo.tcphdr
	pb.icmphdr = pbo.icmphdr
	pb.arechdr = pbo.arechdr
	pb.tmrhdr = pbo.tmrhdr

	copy(pb.pkt[pb.data:pb.tail], pbo.pkt[pb.data:pb.tail])
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
				log.info("pkt: new PktBuf allocated, total(%v)", allocated)
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
