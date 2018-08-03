/* Copyright (c) 2018 Waldemar Augustyn */

package main

const (
	MAXBUF = 10
)

type PktBuf struct {
	pkt     []byte
	data    uint
	tail    uint
	iphdr   uint
	udphdr  uint
	tcphdr  uint
	icmphdr uint
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
		getbuf <- pb
	}
}
