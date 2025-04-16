/* Copyright (c) 2018-2021 Waldemar Augustyn */

package main

import (
	. "github.com/ipref/common"
	rff "github.com/ipref/ref"
	"slices"
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

type M32 int32 // mark, a monotonic counter
type O32 int32 // owner id, an index into array

type IpRefRec struct {
	IpRef
	oid  O32 // owner id
	mark M32 // time offset or revision (which could be time offset, too)
}

type IpRec struct {
	ip   IP
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

	aip, ok := a.(IP)
	if !ok {
		return 0
	}
	bip, ok := b.(IP)
	if !ok {
		return 0
	}
	return slices.Compare(aip.AsSlice(), bip.AsSlice())
}

// get a packet with an address record
func get_arec_pkt(ea, ip, gw IP, ref rff.Ref, oid O32, mark M32) *PktBuf {

	pb := <-getbuf

	pkt := pb.pkt[pb.data:]

	pb.write_v1_header(V1_SET_AREC, 0)

	off := V1_HDR_LEN

	be.PutUint32(pkt[off+V1_OID:], uint32(oid))
	be.PutUint32(pkt[off+V1_MARK:], uint32(mark))

	off += V1_MARK_LEN

	AddrRec{ea, ip, gw, ref}.Encode(pkt[off:])

	off += v1_arec_len

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
	their_ipref map[IP]IpRefRec // our_ea -> (their_gw, their_ref)
	our_ipref   map[IP]IpRefRec // our_ip -> (our_gw,   our_ref)
	oid         O32             // must be the same for both mgw and mtun
	cur_mark    []M32           // current mark per oid
	pfx         string // prefix for printing messages
}

func (mgw *MapGw) init(oid O32) {

	mgw.pfx = "mgw"
	mgw.their_ipref = make(map[IP]IpRefRec)
	mgw.our_ipref = make(map[IP]IpRefRec)
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

func (mgw *MapGw) get_dst_iprec(dst IP) (IpRefRec, bool) {

	is_ea_iplen(dst)
	rec, ok := mgw.their_ipref[dst]
	if !ok {
		if cli.debug["mapper"] {
			log.debug("mgw:  dst ipref not found for: %v", dst)
		}
		return IpRefRec{}, false // not found
	}

	if int(rec.oid) >= len(mgw.cur_mark) {
		log.err("mgw:  invalid oid(%v) in their_ipref, ignoring record", rec.oid)
		return IpRefRec{}, false
	}

	if rec.mark < mgw.cur_mark[rec.oid] {
		if cli.debug["mapper"] {
			log.debug("mgw:  dst ipref expired for: %v", dst)
		}
		return IpRefRec{}, false // expired
	}

	if rec.oid == mgw.oid && rec.mark-mgw.cur_mark[mgw.oid] < MAPPER_REFRESH {

		if cli.debug["mapper"] {
			log.debug("mgw:  refreshing dst ipref for: %v", dst)
		}
		mark := mgw.cur_mark[mgw.oid] + MAPPER_TMOUT
		rec.mark = mark
		mgw.their_ipref[dst] = rec // bump up expiration
		pb := get_arec_pkt(dst, IPNum(ea_iplen, 0), rec.IP, rec.Ref, rec.oid, rec.mark)
		pbb := <-getbuf
		pbb.copy_from(pb)
		recv_gw <- pb  // tell mtun
		db.recv <- pbb // tell db

	}

	return rec, true
}

func (mgw *MapGw) get_src_iprec(src IP) (IpRefRec, bool) {

	is_ea_iplen(src)
	rec, ok := mgw.our_ipref[src]

	if ok {

		if int(rec.oid) >= len(mgw.cur_mark) {
			log.err("mgw:  invalid oid(%v) in our_ipref, ignoring record", rec.oid)
			return IpRefRec{}, false
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
				pb := get_arec_pkt(IPNum(ea_iplen, 0), src, rec.IP, rec.Ref, rec.oid, rec.mark)
				pbb := <-getbuf
				pbb.copy_from(pb)
				recv_gw <- pb  // tell mtun
				db.recv <- pbb // tell db
			}

			return rec, true
		}
	}

	// local host's ip does not have a map to ipref, create one

	ref := <-gen_ref.ref
	if cli.debug["mapper"] {
		log.debug("mgw:  no src ipref for: %v, allocating: %v", src, &ref)
	}
	if ref.IsZero() {
		log.err("mgw:  cannot get new reference for %v, ignoring record", src)
		return IpRefRec{}, false
	}
	mark := mgw.cur_mark[mgw.oid] + MAPPER_TMOUT
	rec = IpRefRec{IpRef{cli.gw_ip, ref}, mgw.oid, mark}
	mgw.our_ipref[src] = rec // add new record
	pb := get_arec_pkt(IPNum(ea_iplen, 0), src, rec.IP, rec.Ref, rec.oid, rec.mark)
	pbb := <-getbuf
	pbb.copy_from(pb)
	recv_gw <- pb  // tell mtun
	db.recv <- pbb // tell db

	return rec, true
}

func (mgw *MapGw) insert_record(oid O32, mark M32, arecb []byte) {

	arec := AddrRecDecode(ea_iplen, gw_iplen, arecb)

	if arec.GW.IsZeroAddr() || arec.Ref.IsZero() {
		log.err("mgw:  unexpected null gw + ref, %v %v %v %v, dropping record",
			arec.EA, arec.IP, arec.GW, &arec.Ref)
		return
	}

	if !arec.EA.IsZeroAddr() && arec.IP.IsZeroAddr() {

		if (oid == mgw.oid && arec.EA.ByteFromEnd(1) < SECOND_BYTE) ||
			(oid != mgw.oid && arec.EA.ByteFromEnd(1) >= SECOND_BYTE) {

			log.err("mgw:  %v(%v): second byte rule violation(ea), %v %v %v %v, dropping record",
				owners.name(oid), oid, arec.EA, arec.IP, arec.GW, &arec.Ref)
			return
		}

		if cli.debug["mapper"] {
			log.debug("mgw:  set their_ipref  %v  ->  %v + %v", arec.EA, arec.GW, &arec.Ref)
		}
		mgw.their_ipref[arec.EA] = IpRefRec{IpRef{arec.GW, arec.Ref}, oid, mark}

	} else if arec.EA.IsZeroAddr() && !arec.IP.IsZeroAddr() {

		if (oid == mgw.oid && ref_secondbyte(arec.Ref) < SECOND_BYTE) ||
			(oid != mgw.oid && ref_secondbyte(arec.Ref) >= SECOND_BYTE) {
			log.err("mgw:  %v(%v): second byte rule violation(ref), %v %v %v %v, dropping record",
				owners.name(oid), oid, arec.EA, arec.IP, arec.GW, &arec.Ref)
			return
		}

		if cli.debug["mapper"] {
			log.debug("mgw:  set our_ipref  %v  ->  %v + %v", arec.IP, arec.GW, &arec.Ref)
		}
		mgw.our_ipref[arec.IP] = IpRefRec{IpRef{arec.GW, arec.Ref}, oid, mark}

	} else {
		log.err("mgw:  invalid address record, %v %v %v %v, dropping record",
			arec.EA, arec.IP, arec.GW, &arec.Ref)
	}
}

func (mgw *MapGw) set_new_address_records(pb *PktBuf) int {

	pkt := pb.pkt[pb.data:pb.tail]
	pktlen := len(pkt)
	if pktlen < V1_HDR_LEN+V1_MARK_LEN+v1_arec_len {
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

	for off += V1_MARK_LEN; off < pktlen; off += v1_arec_len {
		mgw.insert_record(oid, mark, pkt[off:off+v1_arec_len])
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

	if len(pkt) != V1_HDR_LEN+V1_MARK_LEN+v1_arec_len {
		log.err("mgw:  invalid GET_REF pkt")
		return DROP
	}

	off := V1_HDR_LEN + V1_MARK_LEN

	arec := AddrRecDecode(ea_iplen, gw_iplen, pkt[off:])

	rec, found := mgw.get_src_iprec(arec.IP)

	if !found {
		// NACK
		pkt[V1_CMD] = V1_NACK | V1_GET_REF
		be.PutUint16(pkt[V1_PKTLEN:V1_PKTLEN+2], uint16(V1_HDR_LEN/4))
		pb.tail = pb.data + V1_HDR_LEN
	} else {
		// ACK
		pkt[V1_CMD] = V1_ACK | V1_GET_REF
		off = V1_HDR_LEN
		be.PutUint32(pkt[off+V1_OID:], uint32(rec.oid))
		be.PutUint32(pkt[off+V1_MARK:], uint32(rec.mark))
		off += V1_MARK_LEN
		arec.GW = rec.IP
		arec.Ref = rec.Ref
		arec.Encode(pkt[off:])
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

	if off+V1_MARK_LEN+v1_arec_len > pktlen {
		log.err("mgw:  remove expired eas pkt too short")
		return DROP
	}

	oid := O32(be.Uint32(pkt[off+V1_OID : off+V1_OID+4]))

	if oid != mgw.oid {
		log.err("mgw:  remove expired eas oid(%v) does not match mgw oid(%v)", oid, mgw.oid)
		return DROP
	}

	off += V1_MARK_LEN

	if (pktlen-off)%v1_arec_len != 0 {
		log.err("mgw:  remove expired eas pkt corrupted")
		return DROP
	}

	for ; off < pktlen; off += v1_arec_len {

		arec := AddrRecDecode(ea_iplen, gw_iplen, pkt[off:])

		if arec.EA.IsZeroAddr() {
			continue
		}

		rec, ok := mgw.their_ipref[arec.EA]

		if !ok {
			continue
		}

		if oid != rec.oid {
			log.err("mgw:  remove expired ea(%v): pkt oid(%v) does not match record oid(%v)",
				arec.EA, oid, rec.oid)
			continue
		}
		if arec.GW != rec.IP {
			log.err("mgw:  remove expired ea(%v): pkt gw(%v) does not match record gw(%v)",
				arec.EA, arec.GW, rec.IP)
			continue
		}
		if arec.Ref.H != rec.Ref.H || arec.Ref.L != rec.Ref.L {
			log.err("mgw:  remove expired ea(%v): pkt ref(%v) does not match record ref(%v)",
				arec.EA, &arec.Ref, &rec.Ref)
			continue
		}

		delete(mgw.their_ipref, arec.EA)

		if cli.debug["mapper"] {
			log.debug("mgw:  removed expired ea(%v): %v + %v mark(%v)",
				arec.EA, rec.IP, &rec.Ref, rec.mark)
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

	if off+V1_MARK_LEN+v1_arec_len > pktlen {
		log.err("mgw:  query expired refs pkt too short")
		return DROP
	}

	oid := O32(be.Uint32(pkt[off+V1_OID : off+V1_OID+4]))

	if oid != mgw.oid {
		log.err("mgw:  query expired refs oid(%v) does not match mgw oid(%v)", oid, mgw.oid)
		return DROP
	}

	off += V1_MARK_LEN

	if (pktlen-off)%v1_arec_len != 0 {
		log.err("mgw:  query expired refs pkt corrupted")
		return DROP
	}

	for ; off < pktlen; off += v1_arec_len {

		arec := AddrRecDecode(ea_iplen, gw_iplen, pkt[off:])

		rec, ok := mgw.our_ipref[arec.IP]

		if !ok {
			if cli.debug["mapper"] {
				log.debug("mgw:  removed expired gw+ref(%v + %v) -> %v record not found",
					arec.GW, &arec.Ref, arec.IP)
			}
			continue
		}

		if rec.oid != oid {
			if cli.debug["mapper"] {
				log.debug("mgw:  removed expired gw+ref(%v + %v) -> %v rec.oid(%v) does not match oid(%v)",
					arec.GW, &arec.Ref, arec.IP, rec.oid, oid)
			}
			continue
		}

		if rec.IP != arec.GW {
			if cli.debug["mapper"] {
				log.debug("mgw: removed expired gw+ref(%v + %v) -> %v rec.gw(%v) does not match",
					arec.GW, &arec.Ref, arec.IP, rec.IP)
			}
			continue
		}

		if rec.Ref.H != arec.Ref.H || rec.Ref.L != arec.Ref.L {
			if cli.debug["mapper"] {
				log.debug("mgw: removed expired gw+ref(%v + %v) -> %v rec.ref(%v) does not match",
					arec.GW, &arec.Ref, arec.IP, &rec.Ref)
			}
			continue
		}

		if !(rec.mark < mgw.cur_mark[rec.oid]) {
			arec.IP = IPNum(arec.IP.Len(), 0)
			arec.Ref = rff.Ref{}
			arec.Encode(pkt[off:])
			if cli.debug["mapper"] {
				log.debug("mgw:  keeping non-expired gw+ref(%v + %v) -> %v rec.mark(%v) not less than mark(%v)",
					arec.GW, &arec.Ref, arec.IP, rec.mark, mgw.cur_mark[rec.oid])
			}
			continue
		}

		delete(mgw.our_ipref, arec.IP)
		if cli.debug["mapper"] {
			log.debug("mgw: removed expired gw+ref(%v + %v) -> %v rec.mark(%v) less than mark(%v)",
				arec.GW, &arec.Ref, arec.IP, rec.mark, mgw.cur_mark[rec.oid])
		}
	}

	pb.peer = "mgw"
	recv_gw <- pb

	return ACCEPT
}

// -- MapTun -------------------------------------------------------------------

type MapTun struct {
	our_ip   map[IP]map[rff.Ref]IpRec // our_gw   -> our_ref   -> our_ip
	our_ea   map[IP]map[rff.Ref]IpRec // their_gw -> their_ref -> our_ea
	oid      O32                      // must be the same for both mgw and mtun
	cur_mark []M32                    // current mark per oid
	pfx      string
}

func (mtun *MapTun) init(oid O32) {

	mtun.pfx = "mtun"
	mtun.our_ip = make(map[IP]map[rff.Ref]IpRec)
	mtun.our_ea = make(map[IP]map[rff.Ref]IpRec)
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

func (mtun *MapTun) get_dst_ip(gw IP, ref rff.Ref) (IP, bool) {

	is_gw_iplen(gw)
	our_refs, ok := mtun.our_ip[gw]
	if !ok {
		log.err("mtun: local gw not in the map: %v", gw)
		return IP{}, false
	}

	rec, ok := our_refs[ref]
	if !ok {
		log.err("mtun: no local host mapped to ref: %v", &ref)
		return IP{}, false
	}

	if int(rec.oid) >= len(mtun.cur_mark) {
		log.err("mtun: invalid oid(%v) in our_ip, ignoring record", rec.oid)
		return IP{}, false
	}

	if rec.mark < mtun.cur_mark[rec.oid] {
		if cli.debug["mapper"] {
			log.debug("mtun: dst ip expired for: %v + %v", gw, &ref)
		}
		return IP{}, false // expired
	}

	if rec.oid == mtun.oid && rec.mark-mtun.cur_mark[mtun.oid] < MAPPER_REFRESH {

		if cli.debug["mapper"] {
			log.debug("mtun: refreshing dst ip for: %v + %v", gw, &ref)
		}
		mark := mtun.cur_mark[mtun.oid] + MAPPER_TMOUT
		rec.mark = mark
		our_refs[ref] = rec // bump up expiration
		pb := get_arec_pkt(IPNum(ea_iplen, 0), rec.ip, gw, ref, rec.oid, rec.mark)
		pbb := <-getbuf
		pbb.copy_from(pb)
		recv_tun <- pb // tell mgw
		db.recv <- pbb // tell db
	}

	return rec.ip, true
}

func (mtun *MapTun) get_src_iprec(gw IP, ref rff.Ref) (IpRec, bool) {

	is_gw_iplen(gw)
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
			return IpRec{}, false
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
				pb := get_arec_pkt(rec.ip, IPNum(ea_iplen, 0), gw, ref, rec.oid, rec.mark)
				pbb := <-getbuf
				pbb.copy_from(pb)
				recv_tun <- pb // tell mgw
				db.recv <- pbb // tell db
			}

			return rec, true
		}
	}

	// no ea for this remote host, allocate one

	ea := <-gen_ea.ea
	if cli.debug["mapper"] {
		log.debug("mtun: no src ea for: %v + %v, allocating: %v", gw, &ref, ea)
	}
	if ea.IsZero() {
		log.err("mtun: cannot get new ea for %v + %v, ignoring record", gw, &ref)
		return IpRec{}, false // cannot get new ea
	}
	mark := mtun.cur_mark[mtun.oid] + MAPPER_TMOUT
	rec = IpRec{ea, mtun.oid, mark}
	their_refs[ref] = rec
	pb := get_arec_pkt(rec.ip, IPNum(ea_iplen, 0), gw, ref, rec.oid, rec.mark)
	pbb := <-getbuf
	pbb.copy_from(pb)
	recv_tun <- pb // tell mgw
	db.recv <- pbb // tell db

	return rec, true
}

func (mtun *MapTun) insert_record(oid O32, mark M32, arecb []byte) {

	arec := AddrRecDecode(ea_iplen, gw_iplen, arecb)

	if arec.GW.IsZeroAddr() || arec.Ref.IsZero() {
		log.err("mtun: unexpected null gw + ref, %v %v %v %v, dropping record",
			arec.EA, arec.IP, arec.GW, &arec.Ref)
		return
	}

	if !arec.EA.IsZeroAddr() && arec.IP.IsZeroAddr() {

		if (oid == mtun.oid && arec.EA.ByteFromEnd(1) < SECOND_BYTE) ||
			(oid != mtun.oid && arec.EA.ByteFromEnd(1) >= SECOND_BYTE) {
			log.err("mtun: %v(%v): second byte rule violation(ea), %v %v %v %v, dropping record",
				owners.name(oid), oid, arec.EA, arec.IP, arec.GW, &arec.Ref)
			return
		}

		their_refs, ok := mtun.our_ea[arec.GW]
		if !ok {
			their_refs = make(map[rff.Ref]IpRec)
			mtun.our_ea[arec.GW] = their_refs
		}
		if cli.debug["mapper"] {
			log.debug("mtun: set their_refs  %v  ->  %v  ->  %v", arec.GW, &arec.Ref, arec.EA)
		}
		their_refs[arec.Ref] = IpRec{arec.EA, oid, mark}

	} else if arec.EA.IsZeroAddr() && !arec.IP.IsZeroAddr() {

		if (oid == mtun.oid && ref_secondbyte(arec.Ref) < SECOND_BYTE) ||
			(oid != mtun.oid && ref_secondbyte(arec.Ref) >= SECOND_BYTE) {
			log.err("mtun: %v(%v): second byte rule violation(ref), %v %v %v %v, dropping record",
				owners.name(oid), oid, arec.EA, arec.IP, arec.GW, &arec.Ref)
			return
		}

		our_refs, ok := mtun.our_ip[arec.GW]
		if !ok {
			our_refs = make(map[rff.Ref]IpRec)
			mtun.our_ip[arec.GW] = our_refs
		}
		if cli.debug["mapper"] {
			log.debug("mtun: set our_refs  %v  ->  %v  ->  %v",
				arec.GW, &arec.Ref, arec.IP)
		}
		our_refs[arec.Ref] = IpRec{arec.IP, oid, mark}

	} else {
		log.err("mtun: invalid address record, %v %v %v %v, dropping record",
			arec.EA, arec.IP, arec.GW, &arec.Ref)
	}
}

func (mtun *MapTun) set_new_address_records(pb *PktBuf) int {

	pkt := pb.pkt[pb.data:pb.tail]
	pktlen := len(pkt)
	if pktlen < V1_HDR_LEN+V1_MARK_LEN+v1_arec_len {
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

	for off += V1_MARK_LEN; off < pktlen; off += v1_arec_len {
		mtun.insert_record(oid, mark, pkt[off:off+v1_arec_len])
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

	if len(pkt) != V1_HDR_LEN+V1_MARK_LEN+v1_arec_len {
		log.err("mtun: invalid GET_EA pkt")
		return DROP
	}

	off := V1_HDR_LEN + V1_MARK_LEN

	arec := AddrRecDecode(ea_iplen, gw_iplen, pkt[off:])

	iprec, found := mtun.get_src_iprec(arec.GW, arec.Ref)

	if !found {
		// NACK
		pkt[V1_CMD] = V1_NACK | V1_GET_EA
		be.PutUint16(pkt[V1_PKTLEN:V1_PKTLEN+2], uint16(V1_HDR_LEN/4))
		pb.tail = pb.data + V1_HDR_LEN
	} else {
		// ACK
		pkt[V1_CMD] = V1_ACK | V1_GET_EA
		off = V1_HDR_LEN
		be.PutUint32(pkt[off+V1_OID:], uint32(iprec.oid))
		be.PutUint32(pkt[off+V1_MARK:], uint32(iprec.mark))
		off += V1_MARK_LEN
		arec.EA = iprec.ip
		arec.Encode(pkt[off:])
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

	if off+V1_MARK_LEN+v1_arec_len > pktlen {
		log.err("mtun: remove expired refs pkt too short")
		return DROP
	}

	oid := O32(be.Uint32(pkt[off+V1_OID : off+V1_OID+4]))

	if oid != mtun.oid {
		log.err("mtun: remove expired refs oid(%v) does not match mtun oid(%v)", oid, mtun.oid)
		return DROP
	}

	off += V1_MARK_LEN

	if (pktlen-off)%v1_arec_len != 0 {
		log.err("mtun: remove expired refs pkt corrupted")
		return DROP
	}

	for ; off < pktlen; off += v1_arec_len {

		arec := AddrRecDecode(ea_iplen, gw_iplen, pkt[off:])

		if arec.Ref.IsZero() {
			continue
		}

		our_refs, ok := mtun.our_ip[arec.GW]
		if !ok {
			//log.err("mtun: remove expired gw+ref(%v + %v) -> %v gw not found",
			//	arec.GW, &arec.Ref, arec.IP)
			continue
		}

		rec, ok := our_refs[arec.Ref]
		if !ok {
			//log.err("mtun: remove expired gw+ref(%v + %v) -> %v rec not found",
			//	arec.GW, &arec.Ref, arec.IP)
			continue
		}

		if rec.oid != oid {
			log.err("mtun: remove expired gw+ref(%v + %v) -> %v rec.oid(%v) does not match oid(%v)",
				arec.GW, &arec.Ref, arec.IP, rec.oid, oid)
			continue
		}

		if rec.ip != arec.IP {
			log.err("mtun: remove expired gw+ref(%v + %v) -> %v rec.ip(%v) does not match",
				arec.GW, &arec.Ref, arec.IP, rec.ip)
			continue
		}

		if !(rec.mark < mtun.cur_mark[oid]) {
			log.err("mtun: remove non-expired gw+ref(%v + %v) -> %v rec.mark(%v) not less than mark(%v)",
				arec.GW, &arec.Ref, arec.IP, rec.mark, mtun.cur_mark[oid])
			continue
		}

		delete(our_refs, arec.Ref)

		if cli.debug["mapper"] {
			log.debug("mtun: removed expired gw+ref(%v + %v) -> %v",
				arec.GW, &arec.Ref, arec.IP)
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

	if off+V1_MARK_LEN+v1_arec_len > pktlen {
		log.err("mtun: query expired eas pkt too short")
		return DROP
	}

	oid := O32(be.Uint32(pkt[off+V1_OID : off+V1_OID+4]))

	if oid != mtun.oid {
		log.err("mtun: query expired eas oid(%v) does not match mtun oid(%v)", oid, mtun.oid)
		return DROP
	}

	off += V1_MARK_LEN

	if (pktlen-off)%v1_arec_len != 0 {
		log.err("mtun: query expired eas pkt corrupted")
		return DROP
	}

	for ; off < pktlen; off += v1_arec_len {

		arec := AddrRecDecode(ea_iplen, gw_iplen, pkt[off:])

		their_refs, ok := mtun.our_ea[arec.GW]

		if !ok {
			if cli.debug["mapper"] {
				log.debug("mtun: removed expired ea(%v): %v + %v gw not found",
					arec.EA, arec.GW, &arec.Ref)
			}
			continue
		}

		rec, ok := their_refs[arec.Ref]

		if !ok {
			if cli.debug["mapper"] {
				log.debug("mtun: removed expired ea(%v): %v + %v record not found",
					arec.EA, arec.GW, &arec.Ref)
			}
			continue
		}

		if rec.oid != oid {
			if cli.debug["mapper"] {
				log.debug("mtun: removed expired ea(%v): %v + %v rec.oid(%v) does not match oid(%v)",
					arec.EA, arec.GW, &arec.Ref, rec.oid, oid)
			}
			continue
		}

		if rec.ip != arec.EA {
			if cli.debug["mapper"] {
				log.debug("mtun: removed expired ea(%v): %v + %v rec.ea(%v) does not match",
					arec.EA, arec.GW, &arec.Ref, oid, rec.ip)
			}
			continue
		}

		if !(rec.mark < mtun.cur_mark[rec.oid]) {
			arec.EA = IPNum(ea_iplen, 0)
			arec.Encode(pkt[off:])
			if cli.debug["mapper"] {
				log.debug("mtun: keeping non-expired ea(%v): %v + %v rec.mark(%v) not less than mark(%v)",
					arec.EA, arec.GW, &arec.Ref, rec.mark, mtun.cur_mark[rec.oid])
			}
			continue
		}

		delete(their_refs, arec.Ref)
		if cli.debug["mapper"] {
			log.debug("mtun: removed expired ea(%v): %v + %v rec.mark(%v) less than mark(%v)",
				arec.EA, arec.GW, &arec.Ref, rec.mark, mtun.cur_mark[rec.oid])
		}
	}

	pb.peer = "mtun"
	recv_tun <- pb

	return ACCEPT
}

// -----------------------------------------------------------------------------
