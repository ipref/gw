/* Copyright (c) 2018-2021 Waldemar Augustyn */

package main

/* NOTE: We use cznic implementation of btree: modernc.org/b. It allows
   interruptible traversal of the tree. Other implemenations, such as
   github.com/google/btree, rely on closures as iterators. This makes
   it more difficult to traverse in chunks while the tree is modified
   by other go routines.
*/

import (
	rff "github.com/ipref/ref"
	"modernc.org/b"
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

/* Soft state

IPREF maintains soft state describing status of peer gateways. In this
implementation of the gateway, where local network has only one gateway,
soft state is implemented as a simple map:

	their_gw -> state

In this design, there are two copies of the map, each exclusively owned by
their forwarders. The relation between the two maps is asymmetric. The map
is created by the fwd_to_tun forwarder. This forwarder creates new entries,
updates and removes entries as appropriate. It then informs the other forwarder
of changes made. The other forwarder only reads entries from the map.

The entries in the map exists for as long as gateway's related host entries
exist. When all host entries, related to the gatway, are removed then the
gateway's soft state is also removed.
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

type SoftRec struct {
	gw   IP32
	port uint16
	mtu  uint16
	ttl  byte
	hops byte
}

func (sft *SoftRec) init(gw IP32) {

	sft.gw = gw
	sft.port = IPREF_PORT
	sft.mtu = uint16(cli.ifc.MTU)
	sft.ttl = 1
	sft.hops = 1
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

// send soft record to fwd_to_gw forwarder
func send_soft_rec(soft SoftRec) {

	pb := <-getbuf

	pkt := pb.pkt[pb.iphdr:]

	pb.write_v1_header(V1_SET_SOFT, 0)

	off := V1_HDR_LEN

	be.PutUint32(pkt[off+V1_SOFT_GW:off+V1_SOFT_GW+4], uint32(soft.gw))
	be.PutUint16(pkt[off+V1_SOFT_MTU:off+V1_SOFT_MTU+2], soft.mtu)
	be.PutUint16(pkt[off+V1_SOFT_PORT:off+V1_SOFT_PORT+2], soft.port)
	pkt[off+V1_SOFT_TTL] = soft.ttl
	pkt[off+V1_SOFT_HOPS] = soft.hops
	be.PutUint16(pkt[off+V1_SOFT_RSVD:off+V1_SOFT_RSVD+2], 0)

	pb.tail = pb.iphdr + V1_HDR_LEN + V1_SOFT_LEN
	be.PutUint16(pkt[V1_PKTLEN:V1_PKTLEN+2], uint16((V1_HDR_LEN+V1_SOFT_LEN)/4))

	recv_tun <- pb
}

// get a packet with an address record
func get_arec_pkt(ea, ip, gw IP32, ref rff.Ref, oid O32, mark M32) *PktBuf {

	pb := <-getbuf

	pkt := pb.pkt[pb.iphdr:]

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
	MAPPER_TMOUT   = 1800                          // [s] mapper record timeout
	MAPPER_REFRESH = MAPPER_TMOUT - MAPPER_TMOUT/4 // [s] when to refresh
)

var map_gw MapGw   // exclusively owned by fwd_to_gw
var map_tun MapTun // exclusively owned by fwd_to_tun

// -- MapGw --------------------------------------------------------------------

type MapGw struct {
	their_ipref *b.Tree // map[uint32]IpRefRec		our_ea -> (their_gw, their_ref)
	our_ipref   *b.Tree // map[uint32]IpRefRec		our_ip -> (our_gw,   our_ref)
	oid         O32     // must be the same for both mgw and mtun
	cur_mark    []M32   // current mark per oid
	soft        map[IP32]SoftRec
	pfx         string // prefix for printing messages
}

func (mgw *MapGw) init(oid O32) {

	mgw.pfx = "mgw"
	mgw.their_ipref = b.TreeNew(b.Cmp(addr_cmp))
	mgw.our_ipref = b.TreeNew(b.Cmp(addr_cmp))
	mgw.oid = oid
	mgw.cur_mark = make([]M32, 2)
	mgw.soft = make(map[IP32]SoftRec)
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

	iprefrec, ok := mgw.their_ipref.Get(dst)
	if !ok {
		if cli.debug_mapper {
			log.debug("mgw:  dst ipref not found for: %v", dst)
		}
		return IpRefRec{0, rff.Ref{0, 0}, 0, 0} // not found
	}

	rec := iprefrec.(IpRefRec)

	if int(rec.oid) >= len(mgw.cur_mark) {
		log.err("mgw:  invalid oid(%v) in their_ipref, ignoring record", rec.oid)
		return IpRefRec{0, rff.Ref{0, 0}, 0, 0}
	}

	if rec.mark < mgw.cur_mark[rec.oid] {
		if cli.debug_mapper {
			log.debug("mgw:  dst ipref expired for: %v", dst)
		}
		return IpRefRec{0, rff.Ref{0, 0}, 0, 0} // expired
	}

	if rec.oid == mgw.oid && rec.mark-mgw.cur_mark[mgw.oid] < MAPPER_REFRESH {

		if cli.debug_mapper {
			log.debug("mgw:  refreshing dst ipref for: %v", dst)
		}
		mark := mgw.cur_mark[mgw.oid] + MAPPER_TMOUT
		rec.mark = mark
		mgw.their_ipref.Set(dst, rec) // bump up expiration
		pb := get_arec_pkt(dst, 0, rec.ip, rec.ref, rec.oid, rec.mark)
		pbb := <-getbuf
		pbb.copy_from(pb)
		recv_gw <- pb  // tell mtun
		db.recv <- pbb // tell db

	}

	return rec
}

func (mgw *MapGw) get_src_ipref(src IP32) IpRefRec {

	iprefrec, ok := mgw.our_ipref.Get(src)

	if ok {

		rec := iprefrec.(IpRefRec)

		if int(rec.oid) >= len(mgw.cur_mark) {
			log.err("mgw:  invalid oid(%v) in our_ipref, ignoring record", rec.oid)
			return IpRefRec{0, rff.Ref{0, 0}, 0, 0}
		}

		if rec.mark < mgw.cur_mark[rec.oid] {

			if cli.debug_mapper {
				log.debug("mgw:  src ipref expired for: %v, reallocating", src)
			}

		} else {

			if rec.oid == mgw.oid && rec.mark-mgw.cur_mark[mgw.oid] < MAPPER_REFRESH {

				if cli.debug_mapper {
					log.debug("mgw:  refreshing src ipref for: %v", src)
				}
				mark := mgw.cur_mark[mgw.oid] + MAPPER_TMOUT
				rec.mark = mark
				mgw.our_ipref.Set(src, rec) // bump up expiration
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
	if cli.debug_mapper {
		log.debug("mgw:  no src ipref for: %v, allocating: %v", src, &ref)
	}
	if ref.IsZero() {
		log.err("mgw:  cannot get new reference for %v, ignoring record", src)
		return IpRefRec{0, rff.Ref{0, 0}, 0, 0}
	}
	mark := mgw.cur_mark[mgw.oid] + MAPPER_TMOUT
	rec := IpRefRec{cli.gw_ip, ref, mgw.oid, mark}
	mgw.our_ipref.Set(src, rec) // add new record
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

		if cli.debug_mapper {
			log.debug("mgw:  set their_ipref  %v  ->  %v + %v", ea, gw, &ref)
		}
		mgw.their_ipref.Set(ea, IpRefRec{gw, ref, oid, mark})

	} else if ea == 0 && ip != 0 {

		if (oid == mgw.oid && arec[V1_AREC_REFL+6] < SECOND_BYTE) ||
			(oid != mgw.oid && arec[V1_AREC_REFL+6] >= SECOND_BYTE) {
			log.err("mgw:  %v(%v): second byte rule violation(ref), %v %v %v %v, dropping record",
				owners.name(oid), oid, ea, ip, gw, &ref)
			return
		}

		if cli.debug_mapper {
			log.debug("mgw:  set our_ipref  %v  ->  %v + %v", ip, gw, &ref)
		}
		mgw.our_ipref.Set(ip, IpRefRec{gw, ref, oid, mark})

	} else {
		log.err("mgw:  invalid address record, %v %v %v %v, dropping record", ea, ip, gw, &ref)
	}
}

func (mgw *MapGw) set_new_address_records(pb *PktBuf) int {

	pkt := pb.pkt[pb.iphdr:pb.tail]
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

func (mgw *MapGw) set_new_mark(pb *PktBuf) int {

	pkt := pb.pkt[pb.iphdr:pb.tail]
	if len(pkt) != V1_HDR_LEN+V1_MARK_LEN || pkt[V1_CMD] != V1_SET_MARK {
		log.err("mgw:  invalid SET_MARK packet: PKT %08x data/tail(%v/%v), dropping",
			be.Uint32(pb.pkt[pb.data:pb.data+4]), pb.data, pb.tail)
		return DROP
	}
	off := V1_HDR_LEN
	oid := O32(be.Uint32(pkt[off+V1_OID : off+V1_OID+4]))
	mark := M32(be.Uint32(pkt[off+V1_MARK : off+V1_MARK+4]))
	if cli.debug_mapper {
		log.debug("mgw:  set mark %v(%v): %v", owners.name(oid), oid, mark)
	}
	mgw.set_cur_mark(oid, mark)

	return DROP
}

func (mgw *MapGw) update_soft(pb *PktBuf) int {

	pkt := pb.pkt[pb.iphdr:pb.tail]

	if len(pkt) != V1_HDR_LEN+V1_SOFT_LEN || pkt[V1_CMD] != V1_SET_SOFT {

		log.err("mgw:  invalid SET_SOFT packet: PKT %08x data/tail(%v/%v), dropping",
			be.Uint32(pb.pkt[pb.data:pb.data+4]), pb.data, pb.tail)

		return DROP
	}

	off := V1_HDR_LEN

	var soft SoftRec

	soft.gw = IP32(be.Uint32(pkt[off+V1_SOFT_GW : off+V1_SOFT_GW+4]))
	soft.port = be.Uint16(pkt[off+V1_SOFT_PORT : off+V1_SOFT_PORT+2])
	soft.mtu = be.Uint16(pkt[off+V1_SOFT_MTU : off+V1_SOFT_MTU+2])
	soft.ttl = pkt[off+V1_SOFT_TTL]
	soft.hops = pkt[off+V1_SOFT_HOPS]

	if soft.port != 0 {
		if cli.debug_mapper {
			log.debug("mgw:  update soft %v:%v mtu(%v) ttl/hops %v/%v", soft.gw, soft.port,
				soft.mtu, soft.ttl, soft.hops)
		}
		mgw.soft[soft.gw] = soft
	} else {
		if cli.debug_mapper {
			log.debug("mgw:  remove soft %v", soft.gw)
		}
		delete(mgw.soft, soft.gw)
	}

	return DROP
}

func (mgw *MapGw) remove_expired_eas(pb *PktBuf) int {

	pkt := pb.pkt[pb.iphdr:pb.tail]
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

		iprefrec, ok := mgw.their_ipref.Get(arec.ea)

		if !ok {
			continue
		}

		rec := iprefrec.(IpRefRec)

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

		mgw.their_ipref.Delete(arec.ea)

		if cli.debug_mapper {
			log.debug("mgw:  removed expired ea(%v): %v + %v mark(%v)",
				arec.ea, rec.ip, &rec.ref, rec.mark)
		}
	}

	pb.peer = "mgw"
	db.recv <- pb

	return ACCEPT
}

/* func (mgw *MapGw) check_for_expired_eas(pb *PktBuf) int {

	pkt := pb.pkt[pb.iphdr:pb.tail]
	pktlen := len(pkt)

	off := V1_HDR_LEN

	if off+4 > pktlen {
		log.err("mgw: ea expiration query pkt too short")
		return DROP
	}

	oid := O32(be.Uint32(pkt[off : off+4]))

	if oid != mgw.oid {
		log.err("mgw: ea expiration query oid(%v) does not match mgw oid(%v)", oid, mgw.oid)
		return DROP
	}

	off += 4

	if (pktlen-off)%8 != 0 {
		log.err("mgw: corrupted ea expiration query packet")
		return DROP
	}

	for ; off < pktlen; off += 8 {

		ea := IP32(be.Uint32(pkt[off+4 : off+4+4]))

		iprefrec, ok := mgw.their_ipref.Get(ea)

		if !ok {
			// not found, treat as expired
			copy(pkt[off:off+4], []byte{0, 0, 0, 0})
			continue
		}

		rec := iprefrec.(IpRefRec)

		if rec.oid != oid {
			// oid mismatch, clear ea
			copy(pkt[off+4:off+4+4], []byte{0, 0, 0, 0})
			continue
		}

		if rec.mark < mgw.cur_mark[rec.oid] {
			// expired
			copy(pkt[off:off+4], []byte{0, 0, 0, 0})
			continue
		}

		// in use

		be.PutUint32(pkt[off:off+4], uint32(rec.mark))
	}

	pkt[V1_CMD] &= 0x3f
	pkt[V1_CMD] |= V1_ACK

	pb.peer = "mgw"
	pb.schan <- pb

	return ACCEPT
}
*/

// -- MapTun -------------------------------------------------------------------

type MapTun struct {
	our_ip   *b.Tree // map[uint32]map[Ref]IpRec		our_gw   -> our_ref   -> our_ip
	our_ea   *b.Tree // map[uint32]map[Ref]IpRec		their_gw -> their_ref -> our_ea
	oid      O32     // must be the same for both mgw and mtun
	cur_mark []M32   // current mark per oid
	soft     map[IP32]SoftRec
	pfx      string
}

func (mtun *MapTun) init(oid O32) {

	mtun.pfx = "mtun"
	mtun.our_ip = b.TreeNew(b.Cmp(addr_cmp))
	mtun.our_ea = b.TreeNew(b.Cmp(addr_cmp))
	mtun.oid = oid
	mtun.cur_mark = make([]M32, 2)
	mtun.soft = make(map[IP32]SoftRec)
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

func (mtun *MapTun) set_soft(src IP32, soft SoftRec) {

	if cli.debug_mapper {
		log.debug("mtun: set soft %v:%v mtu(%v) ttl/hops %v/%v", soft.gw, soft.port,
			soft.mtu, soft.ttl, soft.hops)
	}

	mtun.soft[src] = soft

	send_soft_rec(soft) // tel mgw about new or changed soft record
}

func (mtun *MapTun) get_dst_ip(gw IP32, ref rff.Ref) IP32 {

	our_refs, ok := mtun.our_ip.Get(gw)
	if !ok {
		log.err("mtun: local gw not in the map: %v", gw)
		return 0
	}

	iprec, ok := our_refs.(*b.Tree).Get(ref)
	if !ok {
		log.err("mtun: no local host mapped to ref: %v", &ref)
		return 0
	}

	rec := iprec.(IpRec)

	if int(rec.oid) >= len(mtun.cur_mark) {
		log.err("mtun: invalid oid(%v) in our_ip, ignoring record", rec.oid)
		return 0
	}

	if rec.mark < mtun.cur_mark[rec.oid] {
		if cli.debug_mapper {
			log.debug("mtun: dst ip expired for: %v + %v", gw, &ref)
		}
		return 0 // expired
	}

	if rec.oid == mtun.oid && rec.mark-mtun.cur_mark[mtun.oid] < MAPPER_REFRESH {

		if cli.debug_mapper {
			log.debug("mtun: refreshing dst ip for: %v + %v", gw, &ref)
		}
		mark := mtun.cur_mark[mtun.oid] + MAPPER_TMOUT
		rec.mark = mark
		our_refs.(*b.Tree).Set(ref, rec) // bump up expiration
		pb := get_arec_pkt(0, rec.ip, gw, ref, rec.oid, rec.mark)
		pbb := <-getbuf
		pbb.copy_from(pb)
		recv_tun <- pb // tell mgw
		db.recv <- pbb // tell db
	}

	return rec.ip
}

func (mtun *MapTun) get_src_iprec(gw IP32, ref rff.Ref) *IpRec {

	their_refs, ok := mtun.our_ea.Get(gw)
	if !ok {
		// unknown remote gw, allocate a map for it
		their_refs = interface{}(b.TreeNew(b.Cmp(ref_cmp)))
		mtun.our_ea.Set(gw, their_refs)
	}

	iprec, ok := their_refs.(*b.Tree).Get(ref)

	if ok {

		rec := iprec.(IpRec)

		if int(rec.oid) >= len(mtun.cur_mark) {
			log.err("mtun: invalid oid(%v) in our_ea, ignoring record", rec.oid)
			return nil
		}

		if rec.mark < mtun.cur_mark[rec.oid] {

			if cli.debug_mapper {
				log.debug("mtun: src ea expired for: %v + %v, reallocating", gw, &ref)
			}

		} else {

			if rec.oid == mtun.oid && rec.mark-mtun.cur_mark[mtun.oid] < MAPPER_REFRESH {

				if cli.debug_mapper {
					log.debug("mtun: refreshing src ea(%v) for: %v + %v", rec.ip, gw, &ref)
				}
				mark := mtun.cur_mark[mtun.oid] + MAPPER_TMOUT
				rec.mark = mark
				their_refs.(*b.Tree).Set(ref, rec) // bump up expiration
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
	if cli.debug_mapper {
		log.debug("mtun: no src ea for: %v + %v, allocating: %v", gw, &ref, ea)
	}
	if ea == 0 {
		log.err("mtun: cannot get new ea for %v + %v, ignoring record", gw, &ref)
		return nil // cannot get new ea
	}
	mark := mtun.cur_mark[mtun.oid] + MAPPER_TMOUT
	rec := IpRec{ea, mtun.oid, mark}
	their_refs.(*b.Tree).Set(ref, rec)
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

		their_refs, ok := mtun.our_ea.Get(gw)
		if !ok {
			their_refs = interface{}(b.TreeNew(b.Cmp(ref_cmp)))
			mtun.our_ea.Set(gw, their_refs)
		}
		if cli.debug_mapper {
			log.debug("mtun: set their_refs  %v  ->  %v  ->  %v", gw, &ref, ea)
		}
		their_refs.(*b.Tree).Set(ref, IpRec{ea, oid, mark})

	} else if ea == 0 && ip != 0 {

		if (oid == mtun.oid && arec[V1_AREC_REFL+6] < SECOND_BYTE) ||
			(oid != mtun.oid && arec[V1_AREC_REFL+6] >= SECOND_BYTE) {
			log.err("mtun: %v(%v): second byte rule violation(ref), %v %v %v %v, dropping record",
				owners.name(oid), oid, ea, ip, gw, &ref)
			return
		}

		our_refs, ok := mtun.our_ip.Get(gw)
		if !ok {
			our_refs = interface{}(b.TreeNew(b.Cmp(ref_cmp)))
			mtun.our_ip.Set(gw, our_refs)
		}
		if cli.debug_mapper {
			log.debug("mtun: set our_refs  %v  ->  %v  ->  %v", gw, &ref, ip)
		}
		our_refs.(*b.Tree).Set(ref, IpRec{ip, oid, mark})

	} else {
		log.err("mtun: invalid address record, %v %v %v %v, dropping record", ea, ip, gw, &ref)
	}
}

func (mtun *MapTun) set_new_address_records(pb *PktBuf) int {

	pkt := pb.pkt[pb.iphdr:pb.tail]
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

	pkt := pb.pkt[pb.iphdr:pb.tail]

	if err := pb.validate_v1_header(len(pkt)); err != nil {
		log.err("mtun: invalid GET_EA pkt from %v: %v", pb.peer, err)
		return DROP
	}

	if cli.debug_mapper {
		log.debug("mtun: in from %v: %v", pb.peer, pb.pp_pkt())
	}
	if cli.trace {
		pb.pp_raw("mtun in:  ")
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
		pb.tail = pb.iphdr + V1_HDR_LEN
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

	pkt := pb.pkt[pb.iphdr:pb.tail]
	if len(pkt) != V1_HDR_LEN+V1_MARK_LEN || pkt[V1_CMD] != V1_SET_MARK {
		log.err("mtun: invalid SET_MARK packet: PKT %08x data/tail(%v/%v), dropping",
			be.Uint32(pb.pkt[pb.data:pb.data+4]), pb.data, pb.tail)
		return DROP
	}
	off := V1_HDR_LEN
	oid := O32(be.Uint32(pkt[off+V1_OID : off+V1_OID+4]))
	mark := M32(be.Uint32(pkt[off+V1_MARK : off+V1_MARK+4]))
	if cli.debug_mapper {
		log.debug("mtun: set mark %v(%v): %v", owners.name(oid), oid, mark)
	}
	mtun.set_cur_mark(oid, mark)

	return DROP
}

func (mtun *MapTun) query_expired_eas(pb *PktBuf) int {

	pkt := pb.pkt[pb.iphdr:pb.tail]
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

		their_refs, ok := mtun.our_ea.Get(arec.gw)

		if !ok {
			if cli.debug_mapper {
				log.debug("mtun: removed expired ea(%v): %v + %v gw not found",
					arec.ea, arec.gw, &arec.ref)
			}
			continue
		}

		iprec, ok := their_refs.(*b.Tree).Get(arec.ref)

		if !ok {
			if cli.debug_mapper {
				log.debug("mtun: removed expired ea(%v): %v + %v record not found",
					arec.ea, arec.gw, &arec.ref)
			}
			continue
		}

		rec := iprec.(IpRec)

		if rec.oid != oid {
			if cli.debug_mapper {
				log.debug("mtun: removed expired ea(%v): %v + %v rec.oid(%v) does not match oid(%v)",
					arec.ea, arec.gw, &arec.ref, rec.oid, oid)
			}
			continue
		}

		if rec.ip != arec.ea {
			if cli.debug_mapper {
				log.debug("mtun: removed expired ea(%v): %v + %v rec.ea(%v) does not match",
					arec.ea, arec.gw, &arec.ref, oid, rec.ip)
			}
			continue
		}

		if !(rec.mark < mtun.cur_mark[rec.oid]) {
			be.PutUint32(pkt[off+V1_AREC_EA:off+V1_AREC_EA+4], 0)
			if cli.debug_mapper {
				log.debug("mtun: keeping non-expired ea(%v): %v + %v rec.mark(%v) not less than mark(%v)",
					arec.ea, arec.gw, &arec.ref, rec.mark, mtun.cur_mark[rec.oid])
			}
			continue
		}

		their_refs.(*b.Tree).Delete(arec.ref)
		if cli.debug_mapper {
			log.debug("mtun: removed expired ea(%v): %v + %v rec.mark(%v) less than mark(%v)",
				arec.ea, arec.gw, &arec.ref, rec.mark, mtun.cur_mark[rec.oid])
		}
	}

	pb.peer = "mtun"
	recv_tun <- pb

	return ACCEPT
}

/* func (mtun *MapTun) check_for_expired_refs(pb *PktBuf) int {

	pkt := pb.pkt[pb.iphdr:pb.tail]
	pktlen := len(pkt)

	off := V1_HDR_LEN

	if off+4 > pktlen {
		log.err("mtun: ref expiration query pkt too short")
		return DROP
	}

	oid := O32(be.Uint32(pkt[off : off+4]))

	if oid != mtun.oid {
		log.err("mtun: ref expiration query oid(%v) does not match mtun oid(%v)", oid, mtun.oid)
		return DROP
	}

	off += 4

	if (pktlen-off)%20 != 0 {
		log.err("mtun: corrupted ref expiration query packet")
		return DROP
	}

	our_refs, ok := mtun.our_ip.Get(cli.gw_ip)
	if !ok {
		log.err("mtun: ref expiration: local gw not in the map: %v", cli.gw_ip)
		return DROP
	}

	var ref rff.Ref

	for ; off < pktlen; off += 20 {

		ref.H = be.Uint64(pkt[off+4 : off+4+8])
		ref.L = be.Uint64(pkt[off+4+8 : off+4+8+8])

		iprec, ok := our_refs.(*b.Tree).Get(ref)
		if !ok {
			// not found, treat as expired
			copy(pkt[off:off+4], []byte{0, 0, 0, 0})
			continue
		}

		rec := iprec.(IpRec)

		if rec.oid != oid {
			// oid mismatch, clear ref
			copy(pkt[off+4:off+4+8], []byte{0, 0, 0, 0, 0, 0, 0, 0})
			copy(pkt[off+4+8:off+4+8+8], []byte{0, 0, 0, 0, 0, 0, 0, 0})
			continue
		}

		if rec.mark < mtun.cur_mark[rec.oid] {
			// expired
			copy(pkt[off:off+4], []byte{0, 0, 0, 0})
			continue
		}

		// in use

		be.PutUint32(pkt[off:off+4], uint32(rec.mark))
	}

	pkt[V1_CMD] &= 0x3f
	pkt[V1_CMD] |= V1_ACK

	pb.peer = "mtun"
	pb.schan <- pb

	return ACCEPT
}
*/

// -----------------------------------------------------------------------------
