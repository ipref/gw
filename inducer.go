/* Copyright (c) 2020-2021 Waldemar Augustyn */

package main

import (
	. "github.com/ipref/common"
	rff "github.com/ipref/ref"
	prng "math/rand"
)

/* Induce address allocation

Only active in devmode running as a standalone mapper broker. Induces
allocation of ea and ref addresses in a predictable manner. Used for
development and debugging of the mapper and the mapper broker without
the need to run external mapper agents or ipref aware resolvers.
*/

// -- ea allocation inducer ----------------------------------------------------

func allocate_eas(gw []IP, ref rff.Ref, from, to uint64) {

	pktid := uint16(prng.Intn(0x10000))

	log.info("inducing ea allocation")

	var arec AddrRec
	arec.EA = IPNum(ea_iplen, 0)
	arec.IP = IPNum(ea_iplen, 0)
	arec.Ref = ref

	for lword := from; lword < to+1; lword++ {

		pktid++
		if pktid == 0 {
			pktid++
		}

		pb := <-getbuf
		pb.write_v1_header(V1_REQ|V1_GET_EA, pktid)
		pkt := pb.pkt[pb.data:]

		off := V1_HDR_LEN

		be.PutUint32(pkt[off+V1_OID:off+V1_OID+4], uint32(mapper_oid))
		copy(pkt[off+V1_MARK:off+V1_MARK+4], []byte{0, 0, 0, 0})

		off += V1_MARK_LEN

		arec.GW = gw[int(lword)%len(gw)]
		arec.Ref.L++
		arec.Encode(pkt[off:])

		// send to fwd_to_tun and forget it

		pb.tail = pb.data + V1_HDR_LEN + V1_MARK_LEN + v1_arec_len
		be.PutUint16(pkt[V1_PKTLEN:V1_PKTLEN+2], uint16(V1_HDR_LEN+V1_MARK_LEN+v1_arec_len)/4)
		pb.peer = "ea allocation inducer"
		pb.schan = retbuf
		recv_gw <- pb
	}
}

func induce_ea_allocation() {

	dly := (MAPPER_TMOUT * 1000) / 3

	base_ref := rff.Ref{0, 0x11110000}
	base_gw := []IP{
		IPNum(gw_iplen, 0x01010101),
		IPNum(gw_iplen, 0x01010102),
		IPNum(gw_iplen, 0x01010103),
		IPNum(gw_iplen, 0x01010104)}

	log.info("START inducing ea allocation")

	allocate_eas(base_gw[0:1], base_ref, 0x0002, 0x0009) // range is inclusive
	allocate_eas(base_gw[0:1], base_ref, 0x0005, 0x000d) // some existing ones
	sleep(dly, dly/8)
	allocate_eas(base_gw[1:2], base_ref, 0x0117, 0x011a)
	allocate_eas(base_gw[1:2], base_ref, 0x0119, 0x011f)
	sleep(dly, dly/8)
	allocate_eas(base_gw[0:1], base_ref, 0x0007, 0x000b) // some existing ones after a while
	sleep(dly, dly/8)
	allocate_eas(base_gw[2:3], base_ref, 0x0222, 0x022b)
	allocate_eas(base_gw[2:3], base_ref, 0x0227, 0x022e)
	sleep(dly, dly/8)
	allocate_eas(base_gw[:3], base_ref, 0x0335, 0x033b)
	sleep(dly, dly/8)
	allocate_eas(base_gw[1:4], base_ref, 0x0442, 0x044c)
	sleep(dly, dly/8)
	allocate_eas(base_gw[0:2], base_ref, 0x0555, 0x055f)
	sleep(dly, dly/8)
	allocate_eas(base_gw[1:3], base_ref, 0x0664, 0x066a)
	sleep(dly, dly/8)
	allocate_eas(base_gw[2:4], base_ref, 0x0771, 0x077c)

	log.info("STOP inducing ea allocation")
}

// -- ref allocation inducer ---------------------------------------------------

func allocate_refs(base, from, to IP) {

	pktid := uint16(prng.Intn(0x10000))

	log.info("inducing ref allocation")

	one := IPNum(from.Len(), 1)

	var arec AddrRec
	arec.EA = IPNum(ea_iplen, 0)
	arec.GW = cli.gw_ip

	for ip := from;; {

		if pktid++; pktid == 0 {
			pktid++
		}

		pb := <-getbuf
		pb.write_v1_header(V1_REQ|V1_GET_REF, pktid)
		pkt := pb.pkt[pb.data:]

		off := V1_HDR_LEN

		be.PutUint32(pkt[off+V1_OID:off+V1_OID+4], uint32(mapper_oid))
		copy(pkt[off+V1_MARK:off+V1_MARK+4], []byte{0, 0, 0, 0})

		off += V1_MARK_LEN

		arec.IP = base.Add(ip)
		arec.Encode(pkt[off:])

		// send to fwd_to_gw and forget it

		pb.tail = pb.data + V1_HDR_LEN + V1_MARK_LEN + v1_arec_len
		be.PutUint16(pkt[V1_PKTLEN:V1_PKTLEN+2], uint16(V1_HDR_LEN+V1_MARK_LEN+v1_arec_len)/4)
		pb.peer = "ref allocation inducer"
		pb.schan = retbuf
		recv_tun <- pb

		if ip == to {
			break
		}
		ip = ip.Add(one)
	}
}

func induce_ref_allocation() {

	dly := (MAPPER_TMOUT * 1000) / 3

	iplen := ea_iplen
	base_ip := IPNum(iplen, 0xac160000)

	sleep(dly/2, dly/16)

	log.info("START inducing ref allocation")

	allocate_refs(base_ip.Or(IPNum(iplen, 0x100)), IPNum(iplen, 1), IPNum(iplen, 17)) // range is inclusive
	allocate_refs(base_ip.Or(IPNum(iplen, 0x100)), IPNum(iplen, 8), IPNum(iplen, 15)) // some existing ones
	sleep(dly, dly/8)
	allocate_refs(base_ip.Or(IPNum(iplen, 0x200)), IPNum(iplen, 21), IPNum(iplen, 27))
	allocate_refs(base_ip.Or(IPNum(iplen, 0x200)), IPNum(iplen, 25), IPNum(iplen, 29))
	sleep(dly, dly/8)
	allocate_refs(base_ip.Or(IPNum(iplen, 0x100)), IPNum(iplen, 5), IPNum(iplen, 11)) // some existing ones after a while
	sleep(dly, dly/8)
	allocate_refs(base_ip.Or(IPNum(iplen, 0x300)), IPNum(iplen, 35), IPNum(iplen, 38))
	allocate_refs(base_ip.Or(IPNum(iplen, 0x300)), IPNum(iplen, 33), IPNum(iplen, 36))
	sleep(dly, dly/8)
	allocate_refs(base_ip.Or(IPNum(iplen, 0x400)), IPNum(iplen, 43), IPNum(iplen, 47))
	sleep(dly, dly/8)
	allocate_refs(base_ip.Or(IPNum(iplen, 0x500)), IPNum(iplen, 55), IPNum(iplen, 58))
	sleep(dly, dly/8)
	allocate_refs(base_ip.Or(IPNum(iplen, 0x600)), IPNum(iplen, 62), IPNum(iplen, 66))
	sleep(dly, dly/8)
	allocate_refs(base_ip.Or(IPNum(iplen, 0x700)), IPNum(iplen, 73), IPNum(iplen, 78))
	sleep(dly, dly/8)
	allocate_refs(base_ip.Or(IPNum(iplen, 0x800)), IPNum(iplen, 84), IPNum(iplen, 87))

	log.info("STOP inducing ref allocation")
}
