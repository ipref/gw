/* Copyright (c) 2018-2021 Waldemar Augustyn */

package main

import (
	rff "github.com/ipref/ref"
	"net"
)

/* Data organization

    ea  - encoding address
    ip  - real ip address of a host
    gw  - geteway representing a local network (our or their)
    ref - reference assigned by related local network (our or their)

Conceptualy, every address record is a relation between four elements:

    (ea, ip, gw, ref)

In this implementation of the gateway, where local network host addresses are
never aliased by encoding addresses, the quad can be decomposed into two
disjoined relations comprised of three elements:

    (ea,     gw, ref)     implemented with:      our_ea  their_gw:their_ref
    (    ip, gw, ref)     implemented with:      our_ip  our_gw:our_ref

These relations must be maintained across all maps used in the implementation.

    (ea,     gw, ref) relation:

        our_ea      ->      (their_gw, their_ref)
        their_gw    ->      their_ref   ->   our_ea

    (    ip, gw, ref) relation:

        our_ip      ->      (our_gw, our_ref)
        our_gw      ->      our_ref     ->   our_ip

The result is four maps. These maps are read by forwarders for every packet. It
is important to make these reads efficient. Updates to the maps come at a far
slower pace, therefore efficiency of updates is not a factor.

In this design, forwarders have exclusive access to their related maps. There
is no locking. Updates to the maps are performed by the forwardes when prompted
by DNS watchers or timers.
*/

type M32 int32   // mark, a monotonic counter
type O32 int32   // owner id, an index into array
type IP32 uint32 // ip address

func (ip IP32) String() string {
	addr := []byte{0, 0, 0, 0}
	be.PutUint32(addr, uint32(ip))
	return net.IP(addr).String()
}

type AddrRec struct {
	ea  IP32
	ip  IP32
	gw  IP32
	ref rff.Ref
}

type IpRef struct {
	ip  IP32
	ref rff.Ref
}

type IpRefRec struct {
	ip   IP32
	ref  rff.Ref
	oid  O32 // owner id
	mark M32 // time offset or revision (which could be time offset, too)
}

type IpRec struct {
	ip   IP32
	oid  O32
	mark M32
}

func ref_cmp(a, b interface{}) int {

	if a.(rff.Ref).H < b.(rff.Ref).H {
		return -1
	} else if a.(rff.Ref).H > b.(rff.Ref).H {
		return 1
	} else if a.(rff.Ref).L < b.(rff.Ref).L {
		return -1
	} else if a.(rff.Ref).L > b.(rff.Ref).L {
		return 1
	} else {
		return 0
	}
}

func addr_cmp(a, b interface{}) int {

	if a.(IP32) < b.(IP32) {
		return -1
	} else if a.(IP32) > b.(IP32) {
		return 1
	} else {
		return 0
	}
}

// get a packet with an address record
func get_arec_pkt(ea, ip, gw IP32, ref rff.Ref, oid O32, mark M32) *PktBuf {

	pb := <-getbuf

	pkt := pb.pkt[pb.data:]

	pb.write_v1_header(V1_SET_AREC, 0)

	off := V1_HDR_LEN

	be.PutUint32(pkt[off+V1_OID:off+V1_OID+4], uint32(oid))
	be.PutUint32(pkt[off+V1_MARK:off+V1_MARK+4], uint32(mark))

	off += V1_MARK_LEN

	be.PutUint32(pkt[off+V1_AREC_EA:off+V1_AREC_EA+4], uint32(ea))
	be.PutUint32(pkt[off+V1_AREC_IP:off+V1_AREC_IP+4], uint32(ip))
	be.PutUint32(pkt[off+V1_AREC_GW:off+V1_AREC_GW+4], uint32(gw))
	be.PutUint64(pkt[off+V1_AREC_REFH:off+V1_AREC_REFH+8], ref.H)
	be.PutUint64(pkt[off+V1_AREC_REFL:off+V1_AREC_REFL+8], ref.L)

	off += V1_AREC_LEN

	pb.tail = off
	be.PutUint16(pkt[V1_PKTLEN:V1_PKTLEN+2], uint16(off/4))

	return pb
}

// -- mapper variables ---------------------------------------------------------

const (
	MAPPER_TMOUT   = 1800 * 8                      // [s] mapper record timeout
	MAPPER_REFRESH = MAPPER_TMOUT - MAPPER_TMOUT/4 // [s] when to refresh
)

var map_gw MapGw   // exclusively owned by fwd_to_gw
var map_tun MapTun // exclusively owned by fwd_to_tun

// -- MapGw --------------------------------------------------------------------

type MapGw struct {
	their_ipref map[IP32]IpRefRec // our_ea -> (their_gw, their_ref)
	our_ipref   map[IP32]IpRefRec // our_ip -> (our_gw,   our_ref)
	oid         O32               // must be the same for both mgw and mtun
	cur_mark    []M32             // current mark per oid
	pfx         string // prefix for printing messages
}

func (mgw *MapGw) init(oid O32) {

	mgw.pfx = "mgw"
	mgw.their_ipref = make(map[IP32]IpRefRec)
	mgw.our_ipref = make(map[IP32]IpRefRec)
	mgw.oid = oid
	mgw.cur_mark = make([]M32, 2)
}

func (mgw *MapGw) set_cur_mark(oid O32, mark M32) {

	if oid == 0 || mark == 0 {
		log.fatal("mgw:  unexpected invalid oid(%v) or mark(%v)", oid, mark)
	}
	if int(oid) >= len(mgw.cur_mark) {
		mgw.cur_mark = append(mgw.cur_mark, make([]M32, int(oid)-len(mgw.cur_mark)+1)...)
	}
	mgw.cur_mark[oid] = mark
}

func (mgw *MapGw) get_dst_ipref(dst IP32) IpRefRec {

	rec, ok := mgw.their_ipref[dst]
	if !ok {
		if cli.debug["mapper"] {
			log.debug("mgw:  dst ipref not found for: %v", dst)
		}
		return IpRefRec{0, rff.Ref{0, 0}, 0, 0} // not found
	}

	if int(rec.oid) >= len(mgw.cur_mark) {
		log.err("mgw:  invalid oid(%v) in their_ipref, ignoring record", rec.oid)
		return IpRefRec{0, rff.Ref{0, 0}, 0, 0}
	}

	if rec.mark < mgw.cur_mark[rec.oid] {
		if cli.debug["mapper"] {
			log.debug("mgw:  dst ipref expired for: %v", dst)
		}
		return IpRefRec{0, rff.Ref{0, 0}, 0, 0} // expired
	}

	if rec.oid == mgw.oid && rec.mark-mgw.cur_mark[mgw.oid] < MAPPER_REFRESH {

		if cli.debug["mapper"] {
			log.debug("mgw:  refreshing dst ipref for: %v", dst)
		}
		mark := mgw.cur_mark[mgw.oid] + MAPPER_TMOUT
		rec.mark = mark
		mgw.their_ipref[dst] = rec // bump up expiration
		pb := get_arec_pkt(dst, 0, rec.ip, rec.ref, rec.oid, rec.mark)
		pbb := <-getbuf
		pbb.copy_from(pb)
		recv_gw <- pb  // tell mtun
		db.recv <- pbb // tell db

	}

	return rec
}

func (mgw *MapGw) get_src_ipref(src IP32) IpRefRec {

	rec, ok := mgw.our_ipref[src]

	if ok {

		if int(rec.oid) >= len(mgw.cur_mark) {
			log.err("mgw:  invalid oid(%v) in our_ipref, ignoring record", rec.oid)
			return IpRefRec{0, rff.Ref{0, 0}, 0, 0}
		}

		if rec.mark < mgw.cur_mark[rec.oid] {

			if cli.debug["mapper"] {
				log.debug("mgw:  src ipref expired for: %v, reallocating", src)
			}

		} else {

			if rec.oid == mgw.oid && rec.mark-mgw.cur_mark[mgw.oid] < MAPPER_REFRESH {

				if cli.debug["mapper"] {
					log.debug("mgw:  refreshing src ipref for: %v", src)
				}
				mark := mgw.cur_mark[mgw.oid] + MAPPER_TMOUT
				rec.mark = mark
				mgw.our_ipref[src] = rec // bump up expiration
				pb := get_arec_pkt(0, src, rec.ip, rec.ref, rec.oid, rec.mark)
				pbb := <-getbuf
				pbb.copy_from(pb)
				recv_gw <- pb  // tell mtun
				db.recv <- pbb // tell db
			}

			return rec
		}
	}

	// local host's ip does not have a map to ipref, create one

	ref := <-gen_ref.ref
	if cli.debug["mapper"] {
		log.debug("mgw:  no src ipref for: %v, allocating: %v", src, &ref)
	}
	if ref.IsZero() {
		log.err("mgw:  cannot get new reference for %v, ignoring record", src)
		return IpRefRec{0, rff.Ref{0, 0}, 0, 0}
	}
	mark := mgw.cur_mark[mgw.oid] + MAPPER_TMOUT
	rec = IpRefRec{cli.gw_ip, ref, mgw.oid, mark}
	mgw.our_ipref[src] = rec // add new record
	pb := get_arec_pkt(0, src, rec.ip, rec.ref, rec.oid, rec.mark)
	pbb := <-getbuf
	pbb.copy_from(pb)
	recv_gw <- pb  // tell mtun
	db.recv <- pbb // tell db

	return rec
}

func (mgw *MapGw) insert_record(oid O32, mark M32, arec []byte) {

	var ref rff.Ref
	ea := IP32(be.Uint32(arec[V1_AREC_EA : V1_AREC_EA+4]))
	ip := IP32(be.Uint32(arec[V1_AREC_IP : V1_AREC_IP+4]))
	gw := IP32(be.Uint32(arec[V1_AREC_GW : V1_AREC_GW+4]))
	ref.H = be.Uint64(arec[V1_AREC_REFH : V1_AREC_REFH+8])
	ref.L = be.Uint64(arec[V1_AREC_REFL : V1_AREC_REFL+8])

	if gw == 0 || ref.IsZero() {
		log.err("mgw:  unexpected null gw + ref, %v %v %v %v, dropping record", ea, ip, gw, &ref)
		return
	}

	if ea != 0 && ip == 0 {

		if (oid == mgw.oid && arec[V1_AREC_EA+2] < SECOND_BYTE) ||
			(oid != mgw.oid && arec[V1_AREC_EA+2] >= SECOND_BYTE) {

			log.err("mgw:  %v(%v): second byte rule violation(ea), %v %v %v %v, dropping record",
				owners.name(oid), oid, ea, ip, gw, &ref)
			return
		}

		if cli.debug["mapper"] {
			log.debug("mgw:  set their_ipref  %v  ->  %v + %v", ea, gw, &ref)
		}
		mgw.their_ipref[ea] = IpRefRec{gw, ref, oid, mark}

	} else if ea == 0 && ip != 0 {

		if (oid == mgw.oid && arec[V1_AREC_REFL+6] < SECOND_BYTE) ||
			(oid != mgw.oid && arec[V1_AREC_REFL+6] >= SECOND_BYTE) {
			log.err("mgw:  %v(%v): second byte rule violation(ref), %v %v %v %v, dropping record",
				owners.name(oid), oid, ea, ip, gw, &ref)
			return
		}

		if cli.debug["mapper"] {
			log.debug("mgw:  set our_ipref  %v  ->  %v + %v", ip, gw, &ref)
		}
		mgw.our_ipref[ip] = IpRefRec{gw, ref, oid, mark}

	} else {
		log.err("mgw:  invalid address record, %v %v %v %v, dropping record", ea, ip, gw, &ref)
	}
}

func (mgw *MapGw) set_new_address_records(pb *PktBuf) int {

	pkt := pb.pkt[pb.data:pb.tail]
	pktlen := len(pkt)
	if pktlen < V1_HDR_LEN+V1_MARK_LEN+V1_AREC_LEN {
		log.err("mgw:  SET_AREC packet too short, dropping")
		return DROP
	}
	if int(be.Uint16(pkt[V1_PKTLEN:V1_PKTLEN+2]))*4 != pktlen {
		log.err("mgw:  SET_AREC packet length mismatch, dropping")
		return DROP
	}

	off := V1_HDR_LEN

	oid := O32(be.Uint32(pkt[off+V1_OID : off+V1_OID+4]))
	mark := M32(be.Uint32(pkt[off+V1_MARK : off+V1_MARK+4]))

	for off += V1_MARK_LEN; off < pktlen; off += V1_AREC_LEN {
		mgw.insert_record(oid, mark, pkt[off:off+V1_AREC_LEN])
	}

	return DROP
}

func (mgw *MapGw) get_ref(pb *PktBuf) int {

	pkt := pb.pkt[pb.data:pb.tail]

	if err := pb.validate_v1_header(len(pkt)); err != nil {
		log.err("mgw:  invalid GET_REF pkt from %v: %v", pb.peer, err)
		return DROP
	}

	if cli.debug["mapper"] {
		log.debug("mgw:  in from %v: %v", pb.peer, pb.pp_pkt())
	}
	if cli.trace {
		pb.pp_raw("mgw in:  ")
	}

	if len(pkt) != V1_HDR_LEN+V1_MARK_LEN+V1_AREC_LEN {
		log.err("mgw:  invalid GET_REF pkt")
		return DROP
	}

	off := V1_HDR_LEN + V1_MARK_LEN

	ip := IP32(be.Uint32(pkt[off+V1_AREC_IP : off+V1_AREC_IP+4]))

	rec := mgw.get_src_ipref(ip)

	if rec.ref.IsZero() {
		// NACK
		pkt[V1_CMD] = V1_NACK | V1_GET_REF
		be.PutUint16(pkt[V1_PKTLEN:V1_PKTLEN+2], uint16(V1_HDR_LEN/4))
		pb.tail = pb.data + V1_HDR_LEN
	} else {
		// ACK
		pkt[V1_CMD] = V1_ACK | V1_GET_REF
		off = V1_HDR_LEN
		be.PutUint32(pkt[off+V1_OID:off+V1_OID+32], uint32(rec.oid))
		be.PutUint32(pkt[off+V1_MARK:off+V1_MARK+32], uint32(rec.mark))
		off += V1_MARK_LEN
		be.PutUint32(pkt[off+V1_AREC_GW:off+V1_AREC_GW+4], uint32(rec.ip))
		be.PutUint64(pkt[off+V1_AREC_REFH:off+V1_AREC_REFH+8], rec.ref.H)
		be.PutUint64(pkt[off+V1_AREC_REFL:off+V1_AREC_REFL+8], rec.ref.L)
	}

	if pb.schan == nil {
		log.err("mgw:  nil return channel from %v, dropping", pb.peer)
		return DROP
	}
	pb.peer = "mgw"
	pb.schan <- pb
	return ACCEPT
}

func (mgw *MapGw) set_new_mark(pb *PktBuf) int {

	pkt := pb.pkt[pb.data:pb.tail]
	if len(pkt) != V1_HDR_LEN+V1_MARK_LEN || pkt[V1_CMD] != V1_SET_MARK {
		log.err("mgw:  invalid SET_MARK packet: PKT %08x data/tail(%v/%v), dropping",
			be.Uint32(pb.pkt[pb.data:pb.data+4]), pb.data, pb.tail)
		return DROP
	}
	off := V1_HDR_LEN
	oid := O32(be.Uint32(pkt[off+V1_OID : off+V1_OID+4]))
	mark := M32(be.Uint32(pkt[off+V1_MARK : off+V1_MARK+4]))
	if cli.debug["mapper"] {
		log.debug("mgw:  set mark %v(%v): %v", owners.name(oid), oid, mark)
	}
	mgw.set_cur_mark(oid, mark)

	return DROP
}

func (mgw *MapGw) remove_expired_eas(pb *PktBuf) int {

	pkt := pb.pkt[pb.data:pb.tail]
	pktlen := len(pkt)

	off := V1_HDR_LEN

	if off+V1_MARK_LEN+V1_AREC_LEN > pktlen {
		log.err("mgw:  remove expired eas pkt too short")
		return DROP
	}

	oid := O32(be.Uint32(pkt[off+V1_OID : off+V1_OID+4]))

	if oid != mgw.oid {
		log.err("mgw:  remove expired eas oid(%v) does not match mgw oid(%v)", oid, mgw.oid)
		return DROP
	}

	off += V1_MARK_LEN

	if (pktlen-off)%V1_AREC_LEN != 0 {
		log.err("mgw:  remove expired eas pkt corrupted")
		return DROP
	}

	var arec AddrRec

	for ; off < pktlen; off += V1_AREC_LEN {

		arec.ea = IP32(be.Uint32(pkt[off+V1_AREC_EA : off+V1_AREC_EA+4]))
		arec.gw = IP32(be.Uint32(pkt[off+V1_AREC_GW : off+V1_AREC_GW+4]))
		arec.ref.H = be.Uint64(pkt[off+V1_AREC_REFH : off+V1_AREC_REFH+8])
		arec.ref.L = be.Uint64(pkt[off+V1_AREC_REFL : off+V1_AREC_REFL+8])

		if arec.ea == 0 {
			continue
		}

		rec, ok := mgw.their_ipref[arec.ea]

		if !ok {
			continue
		}

		if oid != rec.oid {
			log.err("mgw:  remove expired ea(%v): pkt oid(%v) does not match record oid(%v)",
				arec.ea, oid, rec.oid)
			continue
		}
		if arec.gw != rec.ip {
			log.err("mgw:  remove expired ea(%v): pkt gw(%v) does not match record gw(%v)",
				arec.ea, arec.gw, rec.ip)
			continue
		}
		if arec.ref.H != rec.ref.H || arec.ref.L != rec.ref.L {
			log.err("mgw:  remove expired ea(%v): pkt ref(%v) does not match record ref(%v)",
				arec.ea, &arec.ref, &rec.ref)
			continue
		}

		delete(mgw.their_ipref, arec.ea)

		if cli.debug["mapper"] {
			log.debug("mgw:  removed expired ea(%v): %v + %v mark(%v)",
				arec.ea, rec.ip, &rec.ref, rec.mark)
		}
	}

	pb.peer = "mgw"
	db.recv <- pb

	return ACCEPT
}

func (mgw *MapGw) query_expired_refs(pb *PktBuf) int {

	pkt := pb.pkt[pb.data:pb.tail]
	pktlen := len(pkt)

	off := V1_HDR_LEN

	if off+V1_MARK_LEN+V1_AREC_LEN > pktlen {
		log.err("mgw:  query expired refs pkt too short")
		return DROP
	}

	oid := O32(be.Uint32(pkt[off+V1_OID : off+V1_OID+4]))

	if oid != mgw.oid {
		log.err("mgw:  query expired refs oid(%v) does not match mgw oid(%v)", oid, mgw.oid)
		return DROP
	}

	off += V1_MARK_LEN

	if (pktlen-off)%V1_AREC_LEN != 0 {
		log.err("mgw:  query expired refs pkt corrupted")
		return DROP
	}

	var arec AddrRec

	for ; off < pktlen; off += V1_AREC_LEN {

		arec.ip = IP32(be.Uint32(pkt[off+V1_AREC_IP : off+V1_AREC_IP+4]))
		arec.gw = IP32(be.Uint32(pkt[off+V1_AREC_GW : off+V1_AREC_GW+4]))
		arec.ref.H = be.Uint64(pkt[off+V1_AREC_REFH : off+V1_AREC_REFH+8])
		arec.ref.L = be.Uint64(pkt[off+V1_AREC_REFL : off+V1_AREC_REFL+8])

		rec, ok := mgw.our_ipref[arec.ip]

		if !ok {
			if cli.debug["mapper"] {
				log.debug("mgw:  removed expired gw+ref(%v + %v) -> %v record not found",
					arec.gw, &arec.ref, arec.ip)
			}
			continue
		}

		if rec.oid != oid {
			if cli.debug["mapper"] {
				log.debug("mgw:  removed expired gw+ref(%v + %v) -> %v rec.oid(%v) does not match oid(%v)",
					arec.gw, &arec.ref, arec.ip, rec.oid, oid)
			}
			continue
		}

		if rec.ip != arec.gw {
			if cli.debug["mapper"] {
				log.debug("mgw: removed expired gw+ref(%v + %v) -> %v rec.gw(%v) does not match",
					arec.gw, &arec.ref, arec.ip, rec.ip)
			}
			continue
		}

		if rec.ref.H != arec.ref.H || rec.ref.L != arec.ref.L {
			if cli.debug["mapper"] {
				log.debug("mgw: removed expired gw+ref(%v + %v) -> %v rec.ref(%v) does not match",
					arec.gw, &arec.ref, arec.ip, &rec.ref)
			}
			continue
		}

		if !(rec.mark < mgw.cur_mark[rec.oid]) {
			be.PutUint32(pkt[off+V1_AREC_IP:off+V1_AREC_IP+4], 0)
			be.PutUint64(pkt[off+V1_AREC_REFH:off+V1_AREC_REFH+8], 0)
			be.PutUint64(pkt[off+V1_AREC_REFL:off+V1_AREC_REFL+8], 0)
			if cli.debug["mapper"] {
				log.debug("mgw:  keeping non-expired gw+ref(%v + %v) -> %v rec.mark(%v) not less than mark(%v)",
					arec.gw, &arec.ref, arec.ip, rec.mark, mgw.cur_mark[rec.oid])
			}
			continue
		}

		delete(mgw.our_ipref, arec.ip)
		if cli.debug["mapper"] {
			log.debug("mgw: removed expired gw+ref(%v + %v) -> %v rec.mark(%v) less than mark(%v)",
				arec.gw, &arec.ref, arec.ip, rec.mark, mgw.cur_mark[rec.oid])
		}
	}

	pb.peer = "mgw"
	recv_gw <- pb

	return ACCEPT
}

// -- MapTun -------------------------------------------------------------------

type MapTun struct {
	our_ip   map[IP32]map[rff.Ref]IpRec // our_gw   -> our_ref   -> our_ip
	our_ea   map[IP32]map[rff.Ref]IpRec // their_gw -> their_ref -> our_ea
	oid      O32                        // must be the same for both mgw and mtun
	cur_mark []M32                      // current mark per oid
	pfx      string
}

func (mtun *MapTun) init(oid O32) {

	mtun.pfx = "mtun"
	mtun.our_ip = make(map[IP32]map[rff.Ref]IpRec)
	mtun.our_ea = make(map[IP32]map[rff.Ref]IpRec)
	mtun.oid = oid
	mtun.cur_mark = make([]M32, 2)
}

func (mtun *MapTun) set_cur_mark(oid O32, mark M32) {

	if oid == 0 || mark == 0 {
		log.fatal("mtun: unexpected invalid oid(%v) or mark(%v)", oid, mark)
	}
	if int(oid) >= len(mtun.cur_mark) {
		mtun.cur_mark = append(mtun.cur_mark, make([]M32, int(oid)-len(mtun.cur_mark)+1)...)
	}
	mtun.cur_mark[oid] = mark
}

func (mtun *MapTun) get_dst_ip(gw IP32, ref rff.Ref) IP32 {

	our_refs, ok := mtun.our_ip[gw]
	if !ok {
		log.err("mtun: local gw not in the map: %v", gw)
		return 0
	}

	rec, ok := our_refs[ref]
	if !ok {
		log.err("mtun: no local host mapped to ref: %v", &ref)
		return 0
	}

	if int(rec.oid) >= len(mtun.cur_mark) {
		log.err("mtun: invalid oid(%v) in our_ip, ignoring record", rec.oid)
		return 0
	}

	if rec.mark < mtun.cur_mark[rec.oid] {
		if cli.debug["mapper"] {
			log.debug("mtun: dst ip expired for: %v + %v", gw, &ref)
		}
		return 0 // expired
	}

	if rec.oid == mtun.oid && rec.mark-mtun.cur_mark[mtun.oid] < MAPPER_REFRESH {

		if cli.debug["mapper"] {
			log.debug("mtun: refreshing dst ip for: %v + %v", gw, &ref)
		}
		mark := mtun.cur_mark[mtun.oid] + MAPPER_TMOUT
		rec.mark = mark
		our_refs[ref] = rec // bump up expiration
		pb := get_arec_pkt(0, rec.ip, gw, ref, rec.oid, rec.mark)
		pbb := <-getbuf
		pbb.copy_from(pb)
		recv_tun <- pb // tell mgw
		db.recv <- pbb // tell db
	}

	return rec.ip
}

func (mtun *MapTun) get_src_iprec(gw IP32, ref rff.Ref) *IpRec {

	their_refs, ok := mtun.our_ea[gw]
	if !ok {
		// unknown remote gw, allocate a map for it
		their_refs = make(map[rff.Ref]IpRec)
		mtun.our_ea[gw] = their_refs
	}

	rec, ok := their_refs[ref]

	if ok {

		if int(rec.oid) >= len(mtun.cur_mark) {
			log.err("mtun: invalid oid(%v) in our_ea, ignoring record", rec.oid)
			return nil
		}

		if rec.mark < mtun.cur_mark[rec.oid] {

			if cli.debug["mapper"] {
				log.debug("mtun: src ea expired for: %v + %v, reallocating", gw, &ref)
			}

		} else {

			if rec.oid == mtun.oid && rec.mark-mtun.cur_mark[mtun.oid] < MAPPER_REFRESH {

				if cli.debug["mapper"] {
					log.debug("mtun: refreshing src ea(%v) for: %v + %v", rec.ip, gw, &ref)
				}
				mark := mtun.cur_mark[mtun.oid] + MAPPER_TMOUT
				rec.mark = mark
				their_refs[ref] = rec // bump up expiration
				pb := get_arec_pkt(rec.ip, 0, gw, ref, rec.oid, rec.mark)
				pbb := <-getbuf
				pbb.copy_from(pb)
				recv_tun <- pb // tell mgw
				db.recv <- pbb // tell db
			}

			return &rec
		}
	}

	// no ea for this remote host, allocate one

	ea := <-gen_ea.ea
	if cli.debug["mapper"] {
		log.debug("mtun: no src ea for: %v + %v, allocating: %v", gw, &ref, ea)
	}
	if ea == 0 {
		log.err("mtun: cannot get new ea for %v + %v, ignoring record", gw, &ref)
		return nil // cannot get new ea
	}
	mark := mtun.cur_mark[mtun.oid] + MAPPER_TMOUT
	rec = IpRec{ea, mtun.oid, mark}
	their_refs[ref] = rec
	pb := get_arec_pkt(rec.ip, 0, gw, ref, rec.oid, rec.mark)
	pbb := <-getbuf
	pbb.copy_from(pb)
	recv_tun <- pb // tell mgw
	db.recv <- pbb // tell db

	return &rec
}

func (mtun *MapTun) insert_record(oid O32, mark M32, arec []byte) {

	var ref rff.Ref
	ea := IP32(be.Uint32(arec[V1_AREC_EA : V1_AREC_EA+4]))
	ip := IP32(be.Uint32(arec[V1_AREC_IP : V1_AREC_IP+4]))
	gw := IP32(be.Uint32(arec[V1_AREC_GW : V1_AREC_GW+4]))
	ref.H = be.Uint64(arec[V1_AREC_REFH : V1_AREC_REFH+8])
	ref.L = be.Uint64(arec[V1_AREC_REFL : V1_AREC_REFL+8])

	if gw == 0 || ref.IsZero() {
		log.err("mtun: unexpected null gw + ref, %v %v %v %v, dropping record", ea, ip, gw, &ref)
		return
	}

	if ea != 0 && ip == 0 {

		if (oid == mtun.oid && arec[V1_AREC_EA+2] < SECOND_BYTE) ||
			(oid != mtun.oid && arec[V1_AREC_EA+2] >= SECOND_BYTE) {
			log.err("mtun: %v(%v): second byte rule violation(ea), %v %v %v %v, dropping record",
				owners.name(oid), oid, ea, ip, gw, &ref)
			return
		}

		their_refs, ok := mtun.our_ea[gw]
		if !ok {
			their_refs = make(map[rff.Ref]IpRec)
			mtun.our_ea[gw] = their_refs
		}
		if cli.debug["mapper"] {
			log.debug("mtun: set their_refs  %v  ->  %v  ->  %v", gw, &ref, ea)
		}
		their_refs[ref] = IpRec{ea, oid, mark}

	} else if ea == 0 && ip != 0 {

		if (oid == mtun.oid && arec[V1_AREC_REFL+6] < SECOND_BYTE) ||
			(oid != mtun.oid && arec[V1_AREC_REFL+6] >= SECOND_BYTE) {
			log.err("mtun: %v(%v): second byte rule violation(ref), %v %v %v %v, dropping record",
				owners.name(oid), oid, ea, ip, gw, &ref)
			return
		}

		our_refs, ok := mtun.our_ip[gw]
		if !ok {
			our_refs = make(map[rff.Ref]IpRec)
			mtun.our_ip[gw] = our_refs
		}
		if cli.debug["mapper"] {
			log.debug("mtun: set our_refs  %v  ->  %v  ->  %v", gw, &ref, ip)
		}
		our_refs[ref] = IpRec{ip, oid, mark}

	} else {
		log.err("mtun: invalid address record, %v %v %v %v, dropping record", ea, ip, gw, &ref)
	}
}

func (mtun *MapTun) set_new_address_records(pb *PktBuf) int {

	pkt := pb.pkt[pb.data:pb.tail]
	pktlen := len(pkt)
	if pktlen < V1_HDR_LEN+V1_MARK_LEN+V1_AREC_LEN {
		log.err("mtun: SET_AREC packet too short, dropping")
		return DROP
	}
	if int(be.Uint16(pkt[V1_PKTLEN:V1_PKTLEN+2]))*4 != pktlen {
		log.err("mtun: SET_AREC packet length mismatch, dropping")
		return DROP
	}

	off := V1_HDR_LEN

	oid := O32(be.Uint32(pkt[off+V1_OID : off+V1_OID+4]))
	mark := M32(be.Uint32(pkt[off+V1_MARK : off+V1_MARK+4]))

	for off += V1_MARK_LEN; off < pktlen; off += V1_AREC_LEN {
		mtun.insert_record(oid, mark, pkt[off:off+V1_AREC_LEN])
	}

	return DROP
}

func (mtun *MapTun) get_ea(pb *PktBuf) int {

	pkt := pb.pkt[pb.data:pb.tail]

	if err := pb.validate_v1_header(len(pkt)); err != nil {
		log.err("mtun: invalid GET_EA pkt from %v: %v", pb.peer, err)
		return DROP
	}

	if cli.debug["mapper"] {
		log.debug("mtun: in from %v: %v", pb.peer, pb.pp_pkt())
	}
	if cli.trace {
		pb.pp_raw("mtun in: ")
	}

	if len(pkt) != V1_HDR_LEN+V1_MARK_LEN+V1_AREC_LEN {
		log.err("mtun: invalid GET_EA pkt")
		return DROP
	}

	var gw IP32
	var ref rff.Ref

	off := V1_HDR_LEN + V1_MARK_LEN

	gw = IP32(be.Uint32(pkt[off+V1_AREC_GW : off+V1_AREC_GW+4]))
	ref.H = be.Uint64(pkt[off+V1_AREC_REFH : off+V1_AREC_REFH+8])
	ref.L = be.Uint64(pkt[off+V1_AREC_REFL : off+V1_AREC_REFL+8])

	iprec := mtun.get_src_iprec(gw, ref)

	if iprec == nil {
		// NACK
		pkt[V1_CMD] = V1_NACK | V1_GET_EA
		be.PutUint16(pkt[V1_PKTLEN:V1_PKTLEN+2], uint16(V1_HDR_LEN/4))
		pb.tail = pb.data + V1_HDR_LEN
	} else {
		// ACK
		pkt[V1_CMD] = V1_ACK | V1_GET_EA
		off = V1_HDR_LEN
		be.PutUint32(pkt[off+V1_OID:off+V1_OID+32], uint32(iprec.oid))
		be.PutUint32(pkt[off+V1_MARK:off+V1_MARK+32], uint32(iprec.mark))
		off += V1_MARK_LEN
		be.PutUint32(pkt[off+V1_AREC_EA:off+V1_AREC_EA+4], uint32(iprec.ip))
	}

	if pb.schan == nil {
		log.err("mtun: nil return channel from %v, dropping", pb.peer)
		return DROP
	}
	pb.peer = "mtun"
	pb.schan <- pb
	return ACCEPT
}

func (mtun *MapTun) set_new_mark(pb *PktBuf) int {

	pkt := pb.pkt[pb.data:pb.tail]
	if len(pkt) != V1_HDR_LEN+V1_MARK_LEN || pkt[V1_CMD] != V1_SET_MARK {
		log.err("mtun: invalid SET_MARK packet: PKT %08x data/tail(%v/%v), dropping",
			be.Uint32(pb.pkt[pb.data:pb.data+4]), pb.data, pb.tail)
		return DROP
	}
	off := V1_HDR_LEN
	oid := O32(be.Uint32(pkt[off+V1_OID : off+V1_OID+4]))
	mark := M32(be.Uint32(pkt[off+V1_MARK : off+V1_MARK+4]))
	if cli.debug["mapper"] {
		log.debug("mtun: set mark %v(%v): %v", owners.name(oid), oid, mark)
	}
	mtun.set_cur_mark(oid, mark)

	return DROP
}

func (mtun *MapTun) remove_expired_refs(pb *PktBuf) int {

	pkt := pb.pkt[pb.data:pb.tail]
	pktlen := len(pkt)

	off := V1_HDR_LEN

	if off+V1_MARK_LEN+V1_AREC_LEN > pktlen {
		log.err("mtun: remove expired refs pkt too short")
		return DROP
	}

	oid := O32(be.Uint32(pkt[off+V1_OID : off+V1_OID+4]))

	if oid != mtun.oid {
		log.err("mtun: remove expired refs oid(%v) does not match mtun oid(%v)", oid, mtun.oid)
		return DROP
	}

	off += V1_MARK_LEN

	if (pktlen-off)%V1_AREC_LEN != 0 {
		log.err("mtun: remove expired refs pkt corrupted")
		return DROP
	}

	var arec AddrRec

	for ; off < pktlen; off += V1_AREC_LEN {

		arec.ref.H = be.Uint64(pkt[off+V1_AREC_REFH : off+V1_AREC_REFH+8])
		arec.ref.L = be.Uint64(pkt[off+V1_AREC_REFL : off+V1_AREC_REFL+8])

		if arec.ref.IsZero() {
			continue
		}

		arec.ip = IP32(be.Uint32(pkt[off+V1_AREC_IP : off+V1_AREC_IP+4]))
		arec.gw = IP32(be.Uint32(pkt[off+V1_AREC_GW : off+V1_AREC_GW+4]))

		our_refs, ok := mtun.our_ip[arec.gw]
		if !ok {
			//log.err("mtun: remove expired gw+ref(%v + %v) -> %v gw not found",
			//	arec.gw, &arec.ref, arec.ip)
			continue
		}

		rec, ok := our_refs[arec.ref]
		if !ok {
			//log.err("mtun: remove expired gw+ref(%v + %v) -> %v rec not found",
			//	arec.gw, &arec.ref, arec.ip)
			continue
		}

		if rec.oid != oid {
			log.err("mtun: remove expired gw+ref(%v + %v) -> %v rec.oid(%v) does not match oid(%v)",
				arec.gw, &arec.ref, arec.ip, rec.oid, oid)
			continue
		}

		if rec.ip != arec.ip {
			log.err("mtun: remove expired gw+ref(%v + %v) -> %v rec.ip(%v) does not match",
				arec.gw, &arec.ref, arec.ip, rec.ip)
			continue
		}

		if !(rec.mark < mtun.cur_mark[oid]) {
			log.err("mtun: remove non-expired gw+ref(%v + %v) -> %v rec.mark(%v) not less than mark(%v)",
				arec.gw, &arec.ref, arec.ip, rec.mark, mtun.cur_mark[oid])
			continue
		}

		delete(our_refs, arec.ref)

		if cli.debug["mapper"] {
			log.debug("mtun: removed expired gw+ref(%v + %v) -> %v",
				arec.gw, &arec.ref, arec.ip)
		}
	}

	pb.peer = "mtun"
	db.recv <- pb

	return ACCEPT
}

func (mtun *MapTun) query_expired_eas(pb *PktBuf) int {

	if pb.typ != PKT_V1 {
		log.fatal("mtun: invalid packet type")
	}

	pkt := pb.pkt[pb.data:pb.tail]
	pktlen := len(pkt)

	off := V1_HDR_LEN

	if off+V1_MARK_LEN+V1_AREC_LEN > pktlen {
		log.err("mtun: query expired eas pkt too short")
		return DROP
	}

	oid := O32(be.Uint32(pkt[off+V1_OID : off+V1_OID+4]))

	if oid != mtun.oid {
		log.err("mtun: query expired eas oid(%v) does not match mtun oid(%v)", oid, mtun.oid)
		return DROP
	}

	off += V1_MARK_LEN

	if (pktlen-off)%V1_AREC_LEN != 0 {
		log.err("mtun: query expired eas pkt corrupted")
		return DROP
	}

	var arec AddrRec

	for ; off < pktlen; off += V1_AREC_LEN {

		arec.ea = IP32(be.Uint32(pkt[off+V1_AREC_EA : off+V1_AREC_EA+4]))
		arec.gw = IP32(be.Uint32(pkt[off+V1_AREC_GW : off+V1_AREC_GW+4]))
		arec.ref.H = be.Uint64(pkt[off+V1_AREC_REFH : off+V1_AREC_REFH+8])
		arec.ref.L = be.Uint64(pkt[off+V1_AREC_REFL : off+V1_AREC_REFL+8])

		their_refs, ok := mtun.our_ea[arec.gw]

		if !ok {
			if cli.debug["mapper"] {
				log.debug("mtun: removed expired ea(%v): %v + %v gw not found",
					arec.ea, arec.gw, &arec.ref)
			}
			continue
		}

		rec, ok := their_refs[arec.ref]

		if !ok {
			if cli.debug["mapper"] {
				log.debug("mtun: removed expired ea(%v): %v + %v record not found",
					arec.ea, arec.gw, &arec.ref)
			}
			continue
		}

		if rec.oid != oid {
			if cli.debug["mapper"] {
				log.debug("mtun: removed expired ea(%v): %v + %v rec.oid(%v) does not match oid(%v)",
					arec.ea, arec.gw, &arec.ref, rec.oid, oid)
			}
			continue
		}

		if rec.ip != arec.ea {
			if cli.debug["mapper"] {
				log.debug("mtun: removed expired ea(%v): %v + %v rec.ea(%v) does not match",
					arec.ea, arec.gw, &arec.ref, oid, rec.ip)
			}
			continue
		}

		if !(rec.mark < mtun.cur_mark[rec.oid]) {
			be.PutUint32(pkt[off+V1_AREC_EA:off+V1_AREC_EA+4], 0)
			if cli.debug["mapper"] {
				log.debug("mtun: keeping non-expired ea(%v): %v + %v rec.mark(%v) not less than mark(%v)",
					arec.ea, arec.gw, &arec.ref, rec.mark, mtun.cur_mark[rec.oid])
			}
			continue
		}

		delete(their_refs, arec.ref)
		if cli.debug["mapper"] {
			log.debug("mtun: removed expired ea(%v): %v + %v rec.mark(%v) less than mark(%v)",
				arec.ea, arec.gw, &arec.ref, rec.mark, mtun.cur_mark[rec.oid])
		}
	}

	pb.peer = "mtun"
	recv_tun <- pb

	return ACCEPT
}

// -----------------------------------------------------------------------------
