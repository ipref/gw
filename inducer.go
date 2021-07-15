/* Copyright (c) 2020-2021 Waldemar Augustyn */

package main

import (
	rff "github.com/ipref/ref"
	prng "math/rand"
)

/* Induce address allocation

Only active in standalone mapper broker mode. Induces allocation of ea and ref
addresses in a predictable manner. Used for development and debugging of the
mapper and the mapper broker without the need to run external mapper agents
or ipref aware resolvers.
*/

// -- ea allocation inducer ----------------------------------------------------

func allocate_eas(gw []IP32, ref rff.Ref, from, to uint64) {

	pktid := uint16(prng.Intn(0x10000))

	log.info("inducing ea allocation")

	for lword := from; lword < to+1; lword++ {

		pktid++
		if pktid == 0 {
			pktid++
		}

		pb := <-getbuf
		pb.write_v1_header(V1_REQ|V1_GET_EA, pktid)
		pkt := pb.pkt[pb.iphdr:]

		off := V1_HDR_LEN

		be.PutUint32(pkt[off+V1_OID:off+V1_OID+4], uint32(mapper_oid))
		copy(pkt[off+V1_MARK:off+V1_MARK+4], []byte{0, 0, 0, 0})

		off += V1_MARK_LEN

		copy(pkt[off+V1_AREC_EA:off+V1_AREC_EA+4], []byte{0, 0, 0, 0})
		copy(pkt[off+V1_AREC_IP:off+V1_AREC_IP+4], []byte{0, 0, 0, 0})
		be.PutUint32(pkt[off+V1_AREC_GW:off+V1_AREC_GW+4], uint32(gw[int(lword)%len(gw)]))
		be.PutUint64(pkt[off+V1_AREC_REFH:off+V1_AREC_REFH+8], ref.H)
		be.PutUint64(pkt[off+V1_AREC_REFL:off+V1_AREC_REFL+8], ref.L+lword)

		// send to fwd_to_tun and forget it

		pb.tail = pb.iphdr + V1_HDR_LEN + V1_MARK_LEN + V1_AREC_LEN
		be.PutUint16(pkt[V1_PKTLEN:V1_PKTLEN+2], (V1_HDR_LEN+V1_MARK_LEN+V1_AREC_LEN)/4)
		pb.peer = "ea allocation inducer"
		pb.schan = retbuf
		recv_gw <- pb
	}
}

func induce_ea_allocation() {

	dly := (MAPPER_TMOUT * 1000) / 3

	base_ref := rff.Ref{0, 0x11110000}
	base_gw := []IP32{0x01010101, 0x01010102, 0x01010103, 0x01010104}

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

func allocate_refs(base, from, to IP32) {

	pktid := uint16(prng.Intn(0x10000))

	log.info("inducing ref allocation")

	for ip := from; ip < to+1; ip++ {

		if pktid++; pktid == 0 {
			pktid++
		}

		pb := <-getbuf
		pb.write_v1_header(V1_REQ|V1_GET_REF, pktid)
		pkt := pb.pkt[pb.iphdr:]

		off := V1_HDR_LEN

		be.PutUint32(pkt[off+V1_OID:off+V1_OID+4], uint32(mapper_oid))
		copy(pkt[off+V1_MARK:off+V1_MARK+4], []byte{0, 0, 0, 0})

		off += V1_MARK_LEN

		be.PutUint32(pkt[off+V1_AREC_EA:off+V1_AREC_EA+4], 0)
		be.PutUint32(pkt[off+V1_AREC_IP:off+V1_AREC_IP+4], uint32(base+ip))
		be.PutUint32(pkt[off+V1_AREC_GW:off+V1_AREC_GW+4], uint32(cli.gw_ip))
		be.PutUint64(pkt[off+V1_AREC_REFH:off+V1_AREC_REFH+8], 0)
		be.PutUint64(pkt[off+V1_AREC_REFL:off+V1_AREC_REFL+8], 0)

		// send to fwd_to_gw and forget it

		pb.tail = pb.iphdr + V1_HDR_LEN + V1_MARK_LEN + V1_AREC_LEN
		be.PutUint16(pkt[V1_PKTLEN:V1_PKTLEN+2], (V1_HDR_LEN+V1_MARK_LEN+V1_AREC_LEN)/4)
		pb.peer = "ref allocation inducer"
		pb.schan = retbuf
		recv_tun <- pb
	}
}

func induce_ref_allocation() {

	dly := (MAPPER_TMOUT * 1000) / 3

	base_ip := IP32(0xac160000)

	sleep(dly/2, dly/16)

	log.info("START inducing ref allocation")

	allocate_refs(base_ip|0x100, 1, 17) // range is inclusive
	allocate_refs(base_ip|0x100, 8, 15) // some existing ones
	sleep(dly, dly/8)
	allocate_refs(base_ip|0x200, 21, 27)
	allocate_refs(base_ip|0x200, 25, 29)
	sleep(dly, dly/8)
	allocate_refs(base_ip|0x100, 5, 11) // some existing ones after a while
	sleep(dly, dly/8)
	allocate_refs(base_ip|0x300, 35, 38)
	allocate_refs(base_ip|0x300, 33, 36)
	sleep(dly, dly/8)
	allocate_refs(base_ip|0x400, 43, 47)
	sleep(dly, dly/8)
	allocate_refs(base_ip|0x500, 55, 58)
	sleep(dly, dly/8)
	allocate_refs(base_ip|0x600, 62, 66)
	sleep(dly, dly/8)
	allocate_refs(base_ip|0x700, 73, 78)
	sleep(dly, dly/8)
	allocate_refs(base_ip|0x800, 84, 87)

	log.info("STOP inducing ref allocation")
}
