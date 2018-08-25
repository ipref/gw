/* Copyright (c) 2018 Waldemar Augustyn */

package main

import (
	"fmt"
	"github.com/cznic/b"
	"math/bits"
	"net"
	"strings"
)

/* Data organization

    ea  - encoding address
    ip  - real ip address of a host
    gw  - geteway representing a local network (our or their)
    ref - reference assigned by related local network (our or their)

Conceptualy, every address record is a relation between four elements:

    (ea, ip, gw, ref)

In the meadow implementation of IPREF, where local network host addresses are
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

IPREF maintains soft state describing status of peer gateways. In the meadow
implementation of IPREF, where local network has only one gateway, soft state
is implemented as a simple map:

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

type IP32 uint32

func (ip IP32) String() string {
	addr := []byte{0, 0, 0, 0}
	be.PutUint32(addr, uint32(ip))
	return net.IP(addr).String()
}

type Ref struct {
	h uint64
	l uint64
}

func (ref *Ref) isZero() bool {
	return ref.h == 0 && ref.l == 0
}

// print ref as dash separated hex quads: 2f-4883-0005-2a1b
func (ref *Ref) String() string {

	var sb strings.Builder

	var writequads = func(word uint64) {
		for ii := 0; ii < 4; ii++ {
			word = bits.RotateLeft64(word, 16)
			if sb.Len() == 0 {
				if quad := word & 0xffff; quad != 0 {
					sb.WriteString(fmt.Sprintf("%x", quad))
				}
			} else {
				sb.WriteString(fmt.Sprintf("-%04x", word&0xffff))
			}
		}
	}

	writequads(ref.h)
	writequads(ref.l)

	return sb.String()
}

type AddrRec struct {
	ea  IP32
	ip  IP32
	gw  IP32
	ref Ref
}

type IpRefRec struct {
	ip   IP32
	ref  Ref
	oid  uint32 // owner id
	mark uint32 // time offset or revision (which could be time offset, too)
}

type IpRec struct {
	ip   IP32
	oid  uint32
	mark uint32
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
	sft.mtu = uint16(cli.gw_mtu)
	sft.ttl = 1
	sft.hops = 1
}

func ref_cmp(a, b interface{}) int {

	if a.(Ref).h < b.(Ref).h {
		return -1
	} else if a.(Ref).h > b.(Ref).h {
		return 1
	} else if a.(Ref).l < b.(Ref).l {
		return -1
	} else if a.(Ref).l > b.(Ref).l {
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

// -- Variables ----------------------------------------------------------------

var map_gw MapGw   // exclusively owned by fwd_to_gw
var map_tun MapTun // exclusively owned by fwd_to_tun

// -- MapGw --------------------------------------------------------------------

type MapGw struct {
	their_ipref *b.Tree  // map[uint32]IpRefRec		our_ea -> (their_gw, their_ref)
	our_ipref   *b.Tree  // map[uint32]IpRefRec		our_ip -> (our_gw,   our_ref)
	oid         uint32   // must be the same for both mgw and mtun
	cur_mark    []uint32 // current mark per oid
	soft        map[IP32]SoftRec
	purge_mark  uint32 // mark for the current purge run
}

func (mgw *MapGw) init(oid uint32) {

	mgw.oid = owners.new_oid("mgw")
	mgw.their_ipref = b.TreeNew(b.Cmp(addr_cmp))
	mgw.our_ipref = b.TreeNew(b.Cmp(addr_cmp))
	mgw.oid = oid
	mgw.cur_mark = make([]uint32, 2)
	mgw.soft = make(map[IP32]SoftRec)
	mgw.purge_mark = 0
}

func (mgw *MapGw) set_cur_mark(oid, mark uint32) {

	if oid == 0 || mark == 0 {
		log.fatal("mgw: unexpected invalid oid(%v) or mark(%v)", oid, mark)
	}
	if oid >= uint32(len(mgw.cur_mark)) {
		mgw.cur_mark = append(mgw.cur_mark, make([]uint32, oid-uint32(len(mgw.cur_mark))+1)...)
	}
	mgw.cur_mark[oid] = mark
}

func (mgw *MapGw) get_dst_ipref(dst IP32) IpRefRec {

	iprefrec, ok := mgw.their_ipref.Get(dst)

	if !ok || iprefrec.(IpRefRec).mark < mgw.cur_mark[mgw.oid] {

		iprefrec = interface{}(IpRefRec{0, Ref{0, 0}, 0, 0}) // not found

	} else if iprefrec.(IpRefRec).oid == mgw.oid && iprefrec.(IpRefRec).mark-mgw.cur_mark[mgw.oid] < MAPPER_REFRESH {

		rec := iprefrec.(IpRefRec)
		rec.mark = mgw.cur_mark[mgw.oid] + MAPPER_TMOUT
		mgw.their_ipref.Set(dst, rec) // bump up expiration
	}

	return iprefrec.(IpRefRec)
}

func (mgw *MapGw) get_src_ipref(src IP32) IpRefRec {

	iprefrec, ok := mgw.our_ipref.Get(src)
	if ok {
		if iprefrec.(IpRefRec).oid == mgw.oid && iprefrec.(IpRefRec).mark-mgw.cur_mark[mgw.oid] < MAPPER_REFRESH {

			rec := iprefrec.(IpRefRec)
			rec.mark = mgw.cur_mark[mgw.oid] + MAPPER_TMOUT
			mgw.our_ipref.Set(src, rec) // bump up expiration
		}
	} else {

		// local host ip does not have a map to ipref, create it

		ref := <-random_mapper_ref
		if ref.isZero() {
			return IpRefRec{0, Ref{0, 0}, 0, 0} // cannot get new reference
		}
		iprefrec = interface{}(IpRefRec{
			cli.gw_ip,
			ref,
			mgw.oid,
			mgw.cur_mark[mgw.oid] + MAPPER_TMOUT,
		})
		mgw.our_ipref.Set(src, iprefrec)

		// tell mtun about it

		pb := <-getbuf

		if len(pb.pkt)-pb.data < V1_HDR_LEN+4+V1_AREC_LEN {
			log.fatal("mgw: not enough space for an address record") // paranoia
		}

		pb.set_v1hdr()
		pb.write_v1_header(V1_SIG, V1_SET_AREC, mgw.oid, iprefrec.(IpRefRec).mark)

		pkt := pb.pkt[pb.v1hdr:]
		pkt[V1_VER] = 0
		pkt[V1_CMD] = V1_SET_AREC
		off := V1_HDR_LEN

		pkt[off+V1_AREC_HDR_RSVD] = 0
		pkt[off+V1_AREC_HDR_ITEM_TYPE] = V1_AREC
		be.PutUint16(pkt[off+V1_AREC_HDR_NUM_ITEMS:off+V1_AREC_HDR_NUM_ITEMS+2], 1)
		off += V1_AREC_HDR_LEN

		be.PutUint32(pkt[off+V1_EA:off+V1_EA+4], 0)
		be.PutUint32(pkt[off+V1_IP:off+V1_IP+4], uint32(src))
		be.PutUint32(pkt[off+V1_GW:off+V1_GW+4], uint32(cli.gw_ip))
		be.PutUint64(pkt[off+V1_REFH:off+V1_REFH+8], ref.h)
		be.PutUint64(pkt[off+V1_REFL:off+V1_REFL+8], ref.l)
		off += V1_AREC_LEN

		pb.tail = off

		<-recv_gw
	}
	return iprefrec.(IpRefRec)

}

func (mgw *MapGw) set_new_address_records(pb *PktBuf) int {

	pkt := pb.pkt[pb.v1hdr:pb.tail]
	if len(pkt) < V1_HDR_LEN+V1_AREC_HDR_LEN+V1_AREC_LEN {
		log.err("mgw: SET_AREC packet too short, dropping")
		return DROP
	}
	oid := be.Uint32(pkt[V1_OID : V1_OID+4])
	mark := be.Uint32(pkt[V1_MARK : V1_MARK+4])

	off := V1_HDR_LEN

	if pkt[off+V1_AREC_HDR_ITEM_TYPE] != V1_AREC {
		log.err("mgw: unexpected item type: %v, dropping", pkt[off+V1_AREC_HDR_ITEM_TYPE])
		return DROP
	}
	num_items := int(be.Uint16(pkt[off+V1_AREC_HDR_NUM_ITEMS : off+V1_AREC_HDR_NUM_ITEMS+2]))

	off += V1_AREC_HDR_LEN

	if num_items == 0 || int(num_items*V1_AREC_LEN) != (pb.len()-off) {
		log.err("mgw: mismatch between number of items (%v) and packet length (%v), dropping",
			num_items, pb.len())
	}

	for ii := 0; ii < num_items; ii, off = ii+1, off+V1_AREC_LEN {

		var ref Ref
		ea := IP32(be.Uint32(pkt[off+V1_EA : off+V1_EA+4]))
		ip := IP32(be.Uint32(pkt[off+V1_IP : off+V1_IP+4]))
		gw := IP32(be.Uint32(pkt[off+V1_GW : off+V1_GW+4]))
		ref.h = be.Uint64(pkt[off+V1_REFH : off+V1_REFH+8])
		ref.l = be.Uint64(pkt[off+V1_REFL : off+V1_REFL+8])

		if gw == 0 || ref.isZero() {
			log.err("mgw: unexpected null gw + ref, %v %v %v %v, dropping record", ea, ip, gw, &ref)
			continue
		}

		if ea != 0 && ip == 0 {

			if pkt[off+V1_EA+2] >= SECOND_BYTE {
				log.err("mgw: second byte rule violation(ea), %v %v %v %v, dropping record", ea, ip, gw, &ref)
				continue
			}

			log.debug("mgw: set their_ipref  %v  ->  %v + %v", ea, gw, &ref)
			mgw.their_ipref.Set(ea, IpRefRec{gw, ref, oid, mark})

		} else if ea == 0 && ip != 0 {

			if pkt[off+V1_REFL+6] >= SECOND_BYTE {
				log.err("mgw: second byte rule violation(ref), %v %v %v %v, dropping record", ea, ip, gw, &ref)
				continue
			}

			log.debug("mgw: set our_ipref  %v  ->  %v + %v", ip, gw, &ref)
			mgw.our_ipref.Set(ip, IpRefRec{gw, ref, oid, mark})

		} else {
			log.err("mgw: invalid address record, %v %v %v %v, dropping record", ea, ip, gw, &ref)
		}
	}

	return DROP
}

func (mgw *MapGw) set_new_mark(pb *PktBuf) int {

	pkt := pb.pkt[pb.v1hdr:pb.tail]
	if len(pkt) != V1_HDR_LEN || pkt[V1_CMD] != V1_SET_MARK {
		log.err("mgw: invalid SET_MARK packet: PKT %08x data/tail(%v/%v), dropping",
			be.Uint32(pb.pkt[pb.data:pb.data+4]), pb.data, pb.tail)
		return DROP
	}
	oid := be.Uint32(pkt[V1_OID : V1_OID+4])
	mark := be.Uint32(pkt[V1_MARK : V1_MARK+4])
	mgw.set_cur_mark(oid, mark)

	return DROP
}

func (mgw *MapGw) update_soft(pb *PktBuf) int {

	pkt := pb.pkt[pb.v1hdr:pb.tail]
	if len(pkt) != V1_HDR_LEN+V1_SOFT_LEN || pkt[V1_CMD] != V1_SET_SOFT {
		log.err("mgw: invalid SET_SOFT packet: PKT %08x data/tail(%v/%v), dropping",
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
		mgw.soft[soft.gw] = soft
	} else {
		delete(mgw.soft, soft.gw)
	}

	return DROP
}

func (mgw *MapGw) timer(pb *PktBuf) int {

	mark := be.Uint32(pb.pkt[pb.v1hdr+V1_MARK : pb.v1hdr+V1_MARK+4])

	log.debug("mgw: purge expired: %v", mark)

	if mark == mgw.purge_mark {
		mgw_timer_done <- true
	} else {
		mgw.purge_mark = mark
	}
	return DROP
}

// -- MapTun -------------------------------------------------------------------

type MapTun struct {
	our_ip     *b.Tree  // map[uint32]map[Ref]IpRec		our_gw   -> our_ref   -> our_ip
	our_ea     *b.Tree  // map[uint32]map[Ref]IpRec		their_gw -> their_ref -> our_ea
	oid        uint32   // must be the same for both mgw and mtun
	cur_mark   []uint32 // current mark per oid
	soft       map[IP32]SoftRec
	purge_mark uint32 // mark for the current purge run
}

func (mtun *MapTun) init(oid uint32) {

	mtun.our_ip = b.TreeNew(b.Cmp(addr_cmp))
	mtun.our_ea = b.TreeNew(b.Cmp(addr_cmp))
	mtun.oid = oid
	mtun.cur_mark = make([]uint32, 2)
	mtun.soft = make(map[IP32]SoftRec)
	mtun.purge_mark = 0
}

func (mtun *MapTun) set_cur_mark(oid, mark uint32) {

	if oid == 0 || mark == 0 {
		log.fatal("mtun: unexpected invalid oid(%v) or mark(%v)", oid, mark)
	}
	if oid >= uint32(len(mtun.cur_mark)) {
		mtun.cur_mark = append(mtun.cur_mark, make([]uint32, oid-uint32(len(mtun.cur_mark))+1)...)
	}
	mtun.cur_mark[oid] = mark
}

func (mtun *MapTun) get_dst_ip(gw IP32, ref Ref) IP32 {

	our_refs, ok := mtun.our_ip.Get(gw)
	if !ok {
		return 0 // our gateway is not in the map, very weird, probably a bug
	}

	iprec, ok := our_refs.(*b.Tree).Get(ref)
	if !ok {
		return 0 // unknown local host
	}

	return iprec.(IpRec).ip
}

func (mtun *MapTun) get_src_ea(gw IP32, ref Ref) IP32 {

	their_refs, ok := mtun.our_ea.Get(gw)
	if !ok {
		// looks like we haven't seen this remote gw, allocate a map for it
		their_refs = interface{}(b.TreeNew(b.Cmp(ref_cmp)))
		mtun.our_ea.Set(gw, their_refs)
	}

	iprec, ok := their_refs.(*b.Tree).Get(ref)
	if !ok {
		// no ea for this remote host, allocate one
		ea := <-random_mapper_ea
		if ea == 0 {
			return ea // cannot get new ea
		}
		iprec = interface{}(IpRec{ea, mtun.oid, mtun.cur_mark[mtun.oid]})
		their_refs.(*b.Tree).Set(ref, iprec)
	}

	return iprec.(IpRec).ip
}

func (mtun *MapTun) set_new_address_records(pb *PktBuf) int {

	pkt := pb.pkt[pb.v1hdr:pb.tail]
	if len(pkt) < V1_HDR_LEN+V1_AREC_HDR_LEN+V1_AREC_LEN {
		log.err("mtun: SET_AREC packet too short, dropping")
		return DROP
	}
	oid := be.Uint32(pkt[V1_OID : V1_OID+4])
	mark := be.Uint32(pkt[V1_MARK : V1_MARK+4])

	off := V1_HDR_LEN

	if pkt[off+V1_AREC_HDR_ITEM_TYPE] != V1_AREC {
		log.err("mtun: unexpected item type: %v, dropping", pkt[off+V1_AREC_HDR_ITEM_TYPE])
		return DROP
	}
	num_items := int(be.Uint16(pkt[off+V1_AREC_HDR_NUM_ITEMS : off+V1_AREC_HDR_NUM_ITEMS+2]))

	off += V1_AREC_HDR_LEN

	if num_items == 0 || num_items*V1_AREC_LEN != (pb.len()-off) {
		log.err("mtun: mismatch between number of items (%v) and packet length (%v), dropping",
			num_items, pb.len())
		return DROP
	}

	for ii := 0; ii < num_items; ii, off = ii+1, off+V1_AREC_LEN {

		var ref Ref
		ea := IP32(be.Uint32(pkt[off+V1_EA : off+V1_EA+4]))
		ip := IP32(be.Uint32(pkt[off+V1_IP : off+V1_IP+4]))
		gw := IP32(be.Uint32(pkt[off+V1_GW : off+V1_GW+4]))
		ref.h = be.Uint64(pkt[off+V1_REFH : off+V1_REFH+8])
		ref.l = be.Uint64(pkt[off+V1_REFL : off+V1_REFL+8])

		if gw == 0 || ref.isZero() {
			log.err("mtun: unexpected null gw + ref, %v %v %v %v, dropping record", ea, ip, gw, &ref)
			continue
		}

		if ea != 0 && ip == 0 {

			if pkt[off+V1_EA+2] >= SECOND_BYTE {
				log.err("mtun: second byte rule violation(ea), %v %v %v %v, dropping record", ea, ip, gw, &ref)
				continue
			}

			their_refs, ok := mtun.our_ea.Get(gw)
			if !ok {
				their_refs = interface{}(b.TreeNew(b.Cmp(ref_cmp)))
				mtun.our_ea.Set(gw, their_refs)
			}
			log.debug("mtun: set their_refs  %v  ->  %v  ->  %v", gw, &ref, ea)
			their_refs.(*b.Tree).Set(ref, IpRec{ea, oid, mark})

		} else if ea == 0 && ip != 0 {

			if pkt[off+V1_REFL+6] >= SECOND_BYTE {
				log.err("mtun: second byte rule violation(ref), %v %v %v %v, dropping record", ea, ip, gw, &ref)
				continue
			}

			our_refs, ok := mtun.our_ip.Get(gw)
			if !ok {
				our_refs = interface{}(b.TreeNew(b.Cmp(ref_cmp)))
				mtun.our_ip.Set(gw, our_refs)
			}
			log.debug("mtun: set our_refs  %v  ->  %v  ->  %v", gw, &ref, ip)
			our_refs.(*b.Tree).Set(ref, IpRec{ip, oid, mark})

		} else {
			log.err("mtun: invalid address record, %v %v %v %v, dropping record", ea, ip, gw, &ref)
		}
	}

	return DROP
}

func (mtun *MapTun) set_new_mark(pb *PktBuf) int {

	pkt := pb.pkt[pb.v1hdr:pb.tail]
	if len(pkt) != V1_HDR_LEN || pkt[V1_CMD] != V1_SET_MARK {
		log.err("mtun: invalid SET_MARK packet: PKT %08x data/tail(%v/%v), dropping",
			be.Uint32(pb.pkt[pb.data:pb.data+4]), pb.data, pb.tail)
		return DROP
	}
	oid := be.Uint32(pkt[V1_OID : V1_OID+4])
	mark := be.Uint32(pkt[V1_MARK : V1_MARK+4])
	log.debug("mtun: set mark %v(%v): %v", owners.name(oid), oid, mark)
	mtun.set_cur_mark(oid, mark)

	return DROP
}

func (mtun *MapTun) timer(pb *PktBuf) int {

	mark := be.Uint32(pb.pkt[pb.v1hdr+V1_MARK : pb.v1hdr+V1_MARK+4])

	log.debug("mtun: purge expired: %v", mark)

	if mark == mtun.purge_mark {
		mtun_timer_done <- true
	} else {
		mtun.purge_mark = mark
	}
	return DROP
}

// -- Mapper helpers -----------------------------------------------------------
