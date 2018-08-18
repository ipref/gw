/* Copyright (c) 2018 Waldemar Augustyn */

package main

const (
	MAXBUF = 10
)

const ( // V1 constants

	V1_HDR_LEN      = 16
	V1_AREC_HDR_LEN = 4
	V1_AREC_LEN     = 4 + 4 + 4 + 8 + 8 // ea + ip + gw + ref.h + ref.l
)

const (
	// V1 header offsets
	V1_VER      = 0
	V1_CMD      = 1
	V1_SRCQ     = 2
	V1_DSTQ     = 3
	V1_OID      = 4
	V1_MARK     = 8
	V1_RESERVED = 12
	// V1 address record header offsets
	V1_ITEM_TYPE = 1
	V1_NUM_ITEMS = 2
	// V1 address record offsets
	V1_EA   = 0
	V1_IP   = 4
	V1_GW   = 8
	V1_REFH = 12
	V1_REFL = 20
)

const ( // data item types

	V1_AREC = iota + 1
)

const ( // internal packet types

	V1_PKT_AREC = iota + 1
	V1_PKT_TMR
)

const ( // AREC commands

	V1_SET_AREC = iota + 1
	V1_SET_MARK
)

const ( // TMR commands

	V1_PURGE_EXPIRED = iota + 1
)

const ( // packet handling verdicts

	ACCEPT = iota + 1
	DROP
	STOLEN
)

const (
	MIN_PKT_LEN      = V1_HDR_LEN
	ICMP             = 1
	TCP              = 6
	UDP              = 17
	ECHO             = 7
	DISCARD          = 9
	IPREF_PORT       = 1045
	IPREF_OPT        = 0x9E // C(1) + CLS(0) + OptNum(30) (rfc3692 EXP 30)
	IPREF_OPT64_LEN  = 4 + 8 + 8
	IPREF_OPT128_LEN = 4 + 16 + 16
	OPTLEN           = uint(8 + 4 + 4 + 16 + 16) // udphdr + encap + opt + ref + ref
	TUNHDR           = uint(4)
	PKTQLEN          = 2
	// IP header offests
	IP_VER   = 0
	IP_DSCP  = 1
	IP_LEN   = 2
	IP_ID    = 4
	IP_FRAG  = 6
	IP_TTL   = 8
	IP_PROTO = 9
	IP_CSUM  = 10
	IP_SRC   = 12
	IP_DST   = 16
	// UDP offsets
	UDP_SPORT = 0
	UDP_DPORT = 2
	UDP_LEN   = 4
	UDP_CSUM  = 6
	// encap offsets
	ENCAP_TTL   = 0
	ENCAP_PROTO = 1
	ENCAP_HOPS  = 2
	ENCAP_RSVD  = 3
	// opt offsets
	OPT_OPT     = 0
	OPT_LEN     = 1
	OPT_RSVD    = 2
	OPT_SREF64  = 4
	OPT_SREF128 = 4
	OPT_DREF64  = 12
	OPT_DREF128 = 20
)

type IcmpReq struct { // params for icmp requests
	thype byte // we want 'type' but it's a reserved keyword
	code  byte
	mtu   uint16
}
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
	icmp    IcmpReq
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
	pb.icmp = pbo.icmp

	copy(pb.pkt[pb.data:pb.tail], pbo.pkt[pb.data:pb.tail])
}

func (pb *PktBuf) iphdrlen() int {
	return int((pb.pkt[pb.iphdr] & 0x0f) * 4)
}

func (pb *PktBuf) len() int {
	return int(pb.tail - pb.data)
}

func (pb *PktBuf) set_arechdr() {

	pb.arechdr = pb.data
}

func (pb *PktBuf) set_iphdr() {

	pb.iphdr = pb.data
}

func (pb *PktBuf) set_tcphdr() {

	pb.tcphdr = pb.iphdr + uint(pb.iphdrlen())
}

func (pb *PktBuf) set_udphdr() {

	pb.udphdr = pb.iphdr + uint(pb.iphdrlen())
}

func (pb *PktBuf) write_v1_header(thype, cmd byte, oid, mark uint32) {

	pkt := pb.pkt
	off := pb.arechdr

	if (len(pkt) - int(off)) < V1_HDR_LEN {
		log.fatal("pkt: not enough space for v1 header")
	}

	pkt[off+0] = 0x10 + thype
	pkt[off+V1_CMD] = cmd
	pkt[off+V1_SRCQ] = 0
	pkt[off+V1_DSTQ] = 0
	be.PutUint32(pkt[off+V1_OID:off+V1_OID+4], oid)
	be.PutUint32(pkt[off+V1_MARK:off+V1_MARK+4], mark)
	be.PutUint32(pkt[off+V1_RESERVED:off+V1_RESERVED+4], 0)
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
				pb = &PktBuf{pkt: make([]byte, cli.gw_mtu, cli.gw_mtu)}
				allocated += 1
				log.debug("pkt: new PktBuf allocated, total(%v)", allocated)
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
