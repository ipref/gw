/* Copyright (c) 2018 Waldemar Augustyn */

package main

import (
	"fmt"
	"github.com/cznic/b"
	"sync"
	"time"
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

const (
	MAPPER_REC_TMOUT  = 1800 // 30min
	MAPPER_REC_UPDATE = MAPPER_REC_TMOUT - MAPPER_REC_TMOUT/4
)

type Owners struct {
	oids []string
	mtx  sync.Mutex
}

func (o *Owners) init() {
	o.oids = make([]string, 1, 16)
	o.oids[0] = "none"
}

func (o *Owners) new_oid(name string) uint32 {

	if len(name) == 0 {
		log.fatal("mapper: missing owner name")
	}

	o.mtx.Lock()
	oid := uint32(len(o.oids))
	o.oids = append(o.oids, name)
	o.mtx.Unlock()
	return oid
}

type Ref struct {
	h uint64
	l uint64
}

func (ref *Ref) isZero() bool {
	return ref.h == 0 && ref.l == 0
}

func (ref *Ref) String() string {
	if ref.h == 0 {
		return fmt.Sprintf("%x", ref.l)
	}
	return fmt.Sprintf("%x-%016x", ref.h, ref.l)
}

type AddrRec struct {
	ea  uint32
	ip  uint32
	gw  uint32
	ref Ref
}

type IpRefRec struct {
	ip   uint32
	ref  Ref
	oid  uint32 // owner id
	mark uint32 // time offset or revision (which could be time offset, too)
}

type IpRec struct {
	ip   uint32
	oid  uint32
	mark uint32
}

type Mark struct {
	base time.Time
}

func (m *Mark) init() {

	m.base = time.Now().Add(-time.Second) // make sure marker.now() is always > 0
}

func (m *Mark) now() uint32 {

	return uint32(time.Now().Sub(m.base) / time.Second)

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

	if a.(uint32) < b.(uint32) {
		return -1
	} else if a.(uint32) > b.(uint32) {
		return 1
	} else {
		return 0
	}
}

// -- MapGw --------------------------------------------------------------------

type MapGw struct {
	their_ipref *b.Tree  // map[uint32]IpRefRec		our_ea -> (their_gw, their_ref)
	our_ipref   *b.Tree  // map[uint32]IpRefRec		our_ip -> (our_gw,   our_ref)
	oid         uint32   // must be the same for both mgw and mtun
	cur_mark    []uint32 // current mark per oid
}

func (mgw *MapGw) get_dst_ipref(dst uint32) IpRefRec {

	iprefrec, ok := mgw.their_ipref.Get(dst)

	if !ok || iprefrec.(IpRefRec).mark < mgw.cur_mark[mgw.oid] {

		iprefrec = interface{}(IpRefRec{0, Ref{0, 0}, 0, 0}) // not found

	} else if iprefrec.(IpRefRec).oid == mgw.oid && iprefrec.(IpRefRec).mark-mgw.cur_mark[mgw.oid] < MAPPER_REC_UPDATE {

		rec := iprefrec.(IpRefRec)
		rec.mark = mgw.cur_mark[mgw.oid] + MAPPER_REC_TMOUT
		mgw.their_ipref.Set(dst, rec) // bump up expiration
	}

	return iprefrec.(IpRefRec)
}

func (mgw *MapGw) get_src_ipref(src uint32) IpRefRec {

	iprefrec, ok := mgw.our_ipref.Get(src)
	if ok {
		if iprefrec.(IpRefRec).oid == mgw.oid && iprefrec.(IpRefRec).mark-mgw.cur_mark[mgw.oid] < MAPPER_REC_UPDATE {

			rec := iprefrec.(IpRefRec)
			rec.mark = mgw.cur_mark[mgw.oid] + MAPPER_REC_TMOUT
			mgw.our_ipref.Set(src, rec) // bump up expiration
		}
	} else {

		// local host ip does not have a map to ipref, create it

		ref := <-random_mapper_ref
		iprefrec = interface{}(IpRefRec{
			cli.gw_ip,
			ref,
			mgw.oid,
			mgw.cur_mark[mgw.oid] + MAPPER_REC_TMOUT,
		})
		mgw.our_ipref.Set(src, iprefrec)

		// tell mtun about it

		pb := <-getbuf
		if uint(len(pb.pkt))-pb.data < V1_HDRLEN+4+V1_AREC_LEN {
			log.fatal("mgw: not enough space for an address record") // paranoia
		}
		pb.set_arechdr()
		pb.write_v1_header(V1_PKT_AREC, V1_SET_AREC, mgw.oid, iprefrec.(IpRefRec).mark)

		pkt := pb.pkt
		off := pb.arechdr + V1_HDRLEN
		pkt[0] = 0
		pkt[1] = V1_SET_AREC
		be.PutUint32(pkt[off+2:off+4], 1)
		off += 4
		be.PutUint32(pkt[off+0:off+4], 0)
		be.PutUint32(pkt[off+4:off+8], src)
		be.PutUint32(pkt[off+8:off+12], cli.gw_ip)
		be.PutUint64(pkt[off+12:off+20], ref.h)
		be.PutUint64(pkt[off+20:off+28], ref.l)
		pb.tail = off + V1_AREC_LEN

		<-recv_gw
	}
	return iprefrec.(IpRefRec)

}

func (mgw *MapGw) init(oid uint32) {

	mgw.oid = owners.new_oid("mgw")
	mgw.their_ipref = b.TreeNew(b.Cmp(addr_cmp))
	mgw.our_ipref = b.TreeNew(b.Cmp(addr_cmp))
	mgw.oid = oid
	mgw.cur_mark = make([]uint32, 2)
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

func (mgw *MapGw) set_new_address_records(pb *PktBuf) int {

	pkt := pb.pkt
	oid := be.Uint32(pkt[pb.arechdr+V1_OID : pb.arechdr+V1_OID+4])
	mark := be.Uint32(pkt[pb.arechdr+V1_MARK : pb.arechdr+V1_MARK+4])

	switch pkt[pb.arechdr+V1_CMD] {
	case V1_SET_AREC:

		if pb.len() < 16+4+V1_AREC_LEN {
			log.fatal("mgw: address records packet unexpectedly too short")
		}

		off := int(pb.arechdr + 16)

		if pkt[off+1] != V1_AREC {
			log.fatal("mgw: unexpected item type: %v", pkt[off+1])
		}
		num_items := be.Uint16(pkt[off+2 : off+4])

		off += 4

		if num_items == 0 || int(num_items*V1_AREC_LEN) != (pb.len()-off) {
			log.fatal("mgw: mismatch between number (%v) of items and packet length (%v)", num_items, pb.len())
		}

		for ii := 0; ii < int(num_items); ii, off = ii+1, off+V1_AREC_LEN {

			var ref Ref
			ea := be.Uint32(pkt[off+0 : off+4])
			ip := be.Uint32(pkt[off+4 : off+8])
			gw := be.Uint32(pkt[off+8 : off+12])
			ref.h = be.Uint64(pkt[off+12 : off+20])
			ref.l = be.Uint64(pkt[off+10 : off+28])

			if gw == 0 || ref.isZero() {
				log.fatal("mgw: unexpected null gw + ref")
			}

			if ea != 0 && ip == 0 {

				if pkt[off+2] >= SECOND_BYTE {
					log.err("mgw: second byte rule violation, %08x %08x %08x %v", ea, ip, gw, ref)
					continue
				}

				mgw.their_ipref.Set(ea, IpRefRec{gw, ref, oid, mark})

			} else if ea == 0 && ip != 0 {

				if pkt[off+26] >= SECOND_BYTE {
					log.err("mgw: second byte rule violation, %08x %08x %08x %v", ea, ip, gw, ref)
					continue
				}

				mgw.our_ipref.Set(ip, IpRefRec{gw, ref, oid, mark})

			} else {
				log.fatal("mgw: unexpected invalid address record ea: %08x ip: %08x", ea, ip)
			}
		}

	default:
		log.fatal("mgw: unexpected address records command: %v", pkt[pb.arechdr+V1_CMD])
	}
	return DROP
}

func (mgw *MapGw) set_new_mark(pb *PktBuf) int {

	pkt := pb.pkt
	oid := be.Uint32(pkt[pb.arechdr+V1_OID : pb.arechdr+V1_OID+4])
	mark := be.Uint32(pkt[pb.arechdr+V1_MARK : pb.arechdr+V1_MARK+4])
	mgw.set_cur_mark(oid, mark)

	return DROP
}

func (mgw *MapGw) timer(pb *PktBuf) int {
	return DROP
}

// -- MapTun -------------------------------------------------------------------

type MapTun struct {
	our_ip   *b.Tree  // map[uint32]map[Ref]IpRec		our_gw   -> our_ref   -> our_ip
	our_ea   *b.Tree  // map[uint32]map[Ref]IpRec		their_gw -> their_ref -> our_ea
	oid      uint32   // must be the same for both mgw and mtun
	cur_mark []uint32 // current mark per oid
}

func (mtun *MapTun) init(oid uint32) {

	mtun.our_ip = b.TreeNew(b.Cmp(addr_cmp))
	mtun.our_ea = b.TreeNew(b.Cmp(addr_cmp))
	mtun.oid = oid
	mtun.cur_mark = make([]uint32, 2)
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

func (mtun *MapTun) set_new_address_records(pb *PktBuf) int {

	pkt := pb.pkt
	oid := be.Uint32(pkt[pb.arechdr+V1_OID : pb.arechdr+V1_OID+4])
	mark := be.Uint32(pkt[pb.arechdr+V1_MARK : pb.arechdr+V1_MARK+4])

	switch pkt[pb.arechdr+V1_CMD] {
	case V1_SET_AREC:

		if pb.len() < 16+4+V1_AREC_LEN {
			log.fatal("mtun: address records packet unexpectedly too short")
		}

		off := int(pb.arechdr + 16)

		if pkt[off+1] != V1_AREC {
			log.fatal("mtun: unexpected item type: %v", pkt[off+1])
		}
		num_items := be.Uint16(pkt[off+2 : off+4])

		off += 4

		if num_items == 0 || int(num_items*V1_AREC_LEN) != (pb.len()-off) {
			log.fatal("mtun: mismatch between number (%v) of items and packet length (%v)", num_items, pb.len())
		}

		for ii := 0; ii < int(num_items); ii, off = ii+1, off+V1_AREC_LEN {

			var ref Ref
			ea := be.Uint32(pkt[off+0 : off+4])
			ip := be.Uint32(pkt[off+4 : off+8])
			gw := be.Uint32(pkt[off+8 : off+12])
			ref.h = be.Uint64(pkt[off+12 : off+20])
			ref.l = be.Uint64(pkt[off+10 : off+28])

			if gw == 0 || ref.isZero() {
				log.fatal("mtun: unexpected null gw + ref")
			}

			if ea != 0 && ip == 0 {

				if pkt[off+2] >= SECOND_BYTE {
					log.err("mtun: second byte rule violation, %08x %08x %08x %v", ea, ip, gw, ref)
					continue
				}

				their_refs, ok := mtun.our_ea.Get(gw)
				if !ok {
					their_refs = interface{}(b.TreeNew(b.Cmp(ref_cmp)))
					mtun.our_ea.Set(gw, their_refs)
				}
				their_refs.(*b.Tree).Set(ref, IpRec{ea, oid, mark})

			} else if ea == 0 && ip != 0 {

				if pkt[off+26] >= SECOND_BYTE {
					log.err("mtun: second byte rule violation, %08x %08x %08x %v", ea, ip, gw, ref)
					continue
				}

				our_refs, ok := mtun.our_ip.Get(gw)
				if !ok {
					our_refs = interface{}(b.TreeNew(b.Cmp(ref_cmp)))
					mtun.our_ip.Set(gw, our_refs)
				}
				our_refs.(*b.Tree).Set(ref, IpRec{ip, oid, mark})

			} else {
				log.fatal("mtun: unexpected invalid address record ea: %08x ip: %08x", ea, ip)
			}
		}

	default:
		log.fatal("mtun: unexpected address records command: %v", pkt[pb.arechdr+V1_CMD])
	}
	return DROP
}

func (mtun *MapTun) set_new_mark(pb *PktBuf) int {

	pkt := pb.pkt
	oid := be.Uint32(pkt[pb.arechdr+V1_OID : pb.arechdr+V1_OID+4])
	mark := be.Uint32(pkt[pb.arechdr+V1_MARK : pb.arechdr+V1_MARK+4])
	mtun.set_cur_mark(oid, mark)

	return DROP
}

// -- Variables ----------------------------------------------------------------

var marker Mark
var owners Owners

var map_gw MapGw   // exclusively owned by fwd_to_gw
var map_tun MapTun // exclusively owned by fwd_to_tun

// -- Mapper helpers -----------------------------------------------------------
