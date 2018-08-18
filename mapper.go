/* Copyright (c) 2018 Waldemar Augustyn */

package main

import (
	"fmt"
	"github.com/cznic/b"
	"net"
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

func (ref *Ref) String() string {
	if ref.h == 0 {
		return fmt.Sprintf("%x", ref.l)
	}
	return fmt.Sprintf("%x-%016x", ref.h, ref.l)
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

// -- MapGw --------------------------------------------------------------------

type MapGw struct {
	their_ipref *b.Tree  // map[uint32]IpRefRec		our_ea -> (their_gw, their_ref)
	our_ipref   *b.Tree  // map[uint32]IpRefRec		our_ip -> (our_gw,   our_ref)
	oid         uint32   // must be the same for both mgw and mtun
	cur_mark    []uint32 // current mark per oid
	soft        map[IP32]SoftRec
}

func (mgw *MapGw) init(oid uint32) {

	mgw.oid = owners.new_oid("mgw")
	mgw.their_ipref = b.TreeNew(b.Cmp(addr_cmp))
	mgw.our_ipref = b.TreeNew(b.Cmp(addr_cmp))
	mgw.oid = oid
	mgw.cur_mark = make([]uint32, 2)
	mgw.soft = make(map[IP32]SoftRec)
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
		iprefrec = interface{}(IpRefRec{
			cli.gw_ip,
			ref,
			mgw.oid,
			mgw.cur_mark[mgw.oid] + MAPPER_TMOUT,
		})
		mgw.our_ipref.Set(src, iprefrec)

		// tell mtun about it

		pb := <-getbuf
		if uint(len(pb.pkt))-pb.data < V1_HDR_LEN+4+V1_AREC_LEN {
			log.fatal("mgw: not enough space for an address record") // paranoia
		}
		pb.set_arechdr()
		pb.write_v1_header(V1_PKT_AREC, V1_SET_AREC, mgw.oid, iprefrec.(IpRefRec).mark)

		pkt := pb.pkt
		off := pb.arechdr + V1_HDR_LEN
		pkt[0] = 0
		pkt[1] = V1_SET_AREC
		be.PutUint32(pkt[off+2:off+4], 1)
		off += 4
		be.PutUint32(pkt[off+0:off+4], 0)
		be.PutUint32(pkt[off+4:off+8], uint32(src))
		be.PutUint32(pkt[off+8:off+12], uint32(cli.gw_ip))
		be.PutUint64(pkt[off+12:off+20], ref.h)
		be.PutUint64(pkt[off+20:off+28], ref.l)
		pb.tail = off + V1_AREC_LEN

		<-recv_gw
	}
	return iprefrec.(IpRefRec)

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

	pkt := pb.pkt[pb.arechdr:pb.tail]
	if len(pkt) < V1_HDR_LEN+4+V1_AREC_LEN {
		log.err("mgw: SET_AREC packet too short, dropping")
		return DROP
	}
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
			ea := IP32(be.Uint32(pkt[off+0 : off+4]))
			ip := IP32(be.Uint32(pkt[off+4 : off+8]))
			gw := IP32(be.Uint32(pkt[off+8 : off+12]))
			ref.h = be.Uint64(pkt[off+12 : off+20])
			ref.l = be.Uint64(pkt[off+10 : off+28])

			if gw == 0 || ref.isZero() {
				log.fatal("mgw: unexpected null gw + ref")
			}

			if ea != 0 && ip == 0 {

				if pkt[off+2] >= SECOND_BYTE {
					log.err("mgw: second byte rule violation(ea), %v %v %v %v", ea, ip, gw, &ref)
					continue
				}

				mgw.their_ipref.Set(ea, IpRefRec{gw, ref, oid, mark})

			} else if ea == 0 && ip != 0 {

				if pkt[off+26] >= SECOND_BYTE {
					log.err("mgw: second byte rule violation(ref), %v %v %v %v", ea, ip, gw, &ref)
					continue
				}

				mgw.our_ipref.Set(ip, IpRefRec{gw, ref, oid, mark})

			} else {
				log.fatal("mgw: invalid address record, %v %v %v %v", ea, ip, gw, &ref)
			}
		}

	default:
		log.fatal("mgw: unexpected address records command: %v", pkt[pb.arechdr+V1_CMD])
	}
	return DROP
}

func (mgw *MapGw) set_new_mark(pb *PktBuf) int {

	pkt := pb.pkt[pb.arechdr:pb.tail]
	if len(pkt) != V1_HDR_LEN {
		log.err("mgw: SET_MARK packet too short, dropping")
		return DROP
	}
	oid := be.Uint32(pkt[V1_OID : V1_OID+4])
	mark := be.Uint32(pkt[V1_MARK : V1_MARK+4])
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
	soft     map[IP32]SoftRec
}

func (mtun *MapTun) init(oid uint32) {

	mtun.our_ip = b.TreeNew(b.Cmp(addr_cmp))
	mtun.our_ea = b.TreeNew(b.Cmp(addr_cmp))
	mtun.oid = oid
	mtun.cur_mark = make([]uint32, 2)
	mtun.soft = make(map[IP32]SoftRec)
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

	pkt := pb.pkt[pb.arechdr:pb.tail]
	if len(pkt) < V1_HDR_LEN+4+V1_AREC_LEN || pkt[V1_CMD] != V1_SET_AREC {
		log.err("mtun: invalid SET_AREC packet, dropping")
		return DROP
	}
	oid := be.Uint32(pkt[V1_OID : V1_OID+4])
	mark := be.Uint32(pkt[V1_MARK : V1_MARK+4])

	off := int(V1_HDR_LEN)

	if pkt[off+V1_ITEM_TYPE] != V1_AREC {
		log.err("mtun: unexpected item type: %v, dropping", pkt[off+V1_ITEM_TYPE])
		return DROP
	}
	num_items := be.Uint16(pkt[off+V1_NUM_ITEMS : off+V1_NUM_ITEMS+2])

	off += V1_AREC_HDR_LEN

	if num_items == 0 || int(num_items*V1_AREC_LEN) != (pb.len()-off) {
		log.err("mtun: mismatch between number of items (%v) and packet length (%v), dropping",
			num_items, pb.len())
		return DROP
	}

	for ii := 0; ii < int(num_items); ii, off = ii+1, off+V1_AREC_LEN {

		var ref Ref
		ea := IP32(be.Uint32(pkt[off+V1_EA : off+V1_EA+4]))
		ip := IP32(be.Uint32(pkt[off+V1_IP : off+V1_IP+4]))
		gw := IP32(be.Uint32(pkt[off+V1_GW : off+V1_GW+4]))
		ref.h = be.Uint64(pkt[off+V1_REFH : off+V1_REFH+8])
		ref.l = be.Uint64(pkt[off+V1_REFL : off+V1_REFL+8])

		if gw == 0 || ref.isZero() {
			log.err("mtun: unexpected null gw + ref, dropping item")
			continue
		}

		if ea != 0 && ip == 0 {

			if pkt[off+V1_EA+2] >= SECOND_BYTE {
				log.err("mtun: second byte rule violation(ea), %v %v %v %v, dropping item", ea, ip, gw, &ref)
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
				log.err("mtun: second byte rule violation(ref), %v %v %v %v, dropping item", ea, ip, gw, &ref)
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
			log.fatal("mtun: invalid address record, %v %v %v %v, dropping item", ea, ip, gw, &ref)
		}
	}

	return DROP
}

func (mtun *MapTun) set_new_mark(pb *PktBuf) int {

	pkt := pb.pkt[pb.arechdr:pb.tail]
	if len(pkt) != V1_HDR_LEN || pkt[V1_CMD] != V1_SET_MARK {
		log.err("mtun: invalid SET_MARK packet, dropping")
		return DROP
	}
	oid := be.Uint32(pkt[V1_OID : V1_OID+4])
	mark := be.Uint32(pkt[V1_MARK : V1_MARK+4])
	mtun.set_cur_mark(oid, mark)

	return DROP
}

// -- Variables ----------------------------------------------------------------

var map_gw MapGw   // exclusively owned by fwd_to_gw
var map_tun MapTun // exclusively owned by fwd_to_tun

// -- Mapper helpers -----------------------------------------------------------
