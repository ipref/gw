/* Copyright (c) 2018 Waldemar Augustyn */

package main

import (
	"fmt"
	"github.com/cznic/b"
	"io"
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

// send soft record to the fwd_to_gw forwarder
func send_soft_rec(soft SoftRec) {

	pb := <-getbuf

	pb.set_v1hdr()
	pb.write_v1_header(V1_SIG, V1_SET_SOFT, 0, 0)

	pkt := pb.pkt[pb.v1hdr:]
	off := V1_HDR_LEN

	be.PutUint32(pkt[off+V1_SOFT_GW:off+V1_SOFT_GW+4], uint32(soft.gw))
	be.PutUint16(pkt[off+V1_SOFT_MTU:off+V1_SOFT_MTU+2], soft.mtu)
	be.PutUint16(pkt[off+V1_SOFT_PORT:off+V1_SOFT_PORT+2], soft.port)
	pkt[off+V1_SOFT_TTL] = soft.ttl
	pkt[off+V1_SOFT_HOPS] = soft.hops
	be.PutUint16(pkt[off+V1_SOFT_RSVD:off+V1_SOFT_RSVD+2], 0)

	pb.tail = pb.v1hdr + V1_HDR_LEN + V1_SOFT_LEN

	recv_tun <- pb
}

// send an address record
func send_arec(mm *Map, ea, ip, gw IP32, ref Ref, -> pktq chan *PktBuf) {

	pb := <-getbuf

	if len(pb.pkt)-pb.data < V1_HDR_LEN+4+V1_AREC_LEN {
		log.fatal("%v: not enough space for an address record", mm.pfx()) // paranoia
	}

	oid := mm.get_oid()
	mark := mm.get_cur_mark(oid) + MAPPER_TMOUT

	pb.set_v1hdr()
	pb.write_v1_header(V1_SIG, V1_SET_AREC, oid, mark)

	pkt := pb.pkt[pb.v1hdr:]
	pkt[V1_VER] = 0
	pkt[V1_CMD] = V1_SET_AREC
	off := V1_HDR_LEN

	pkt[off+V1_AREC_HDR_RSVD] = 0
	pkt[off+V1_AREC_HDR_ITEM_TYPE] = V1_AREC
	be.PutUint16(pkt[off+V1_AREC_HDR_NUM_ITEMS:off+V1_AREC_HDR_NUM_ITEMS+2], 1)
	off += V1_AREC_HDR_LEN

	be.PutUint32(pkt[off+V1_EA:off+V1_EA+4], uint32(ea))
	be.PutUint32(pkt[off+V1_IP:off+V1_IP+4], uint32(ip))
	be.PutUint32(pkt[off+V1_GW:off+V1_GW+4], uint32(gw))
	be.PutUint64(pkt[off+V1_REFH:off+V1_REFH+8], ref.h)
	be.PutUint64(pkt[off+V1_REFL:off+V1_REFL+8], ref.l)
	off += V1_AREC_LEN

	pb.tail = off

	<-pktq
}

// -- mapper variables ---------------------------------------------------------

type Map interface {
	get_pfx() string
	get_oid() uint32
	get_cur_mark(uint32) uint32
}

const (
	MAPPER_TMOUT     = 1800                          // [s] mapper record timeout
	MAPPER_REFRESH   = MAPPER_TMOUT - MAPPER_TMOUT/4 // [s] when to refresh
	MAPPER_PURGE_MIN = 15                            // min items to purge at a time
)

var map_gw MapGw   // exclusively owned by fwd_to_gw
var map_tun MapTun // exclusively owned by fwd_to_tun

// -- MapGw --------------------------------------------------------------------

const ( // purge states
	MGW_PURGE_START = iota + 1
	MGW_PURGE_THEIR_IPREF_SEEK
	MGW_PURGE_THEIR_IPREF
	MGW_PURGE_OUR_IPREF_SEEK
	MGW_PURGE_OUR_IPREF
	MGW_PURGE_STOP
)

type MapGw struct {
	their_ipref *b.Tree  // map[uint32]IpRefRec		our_ea -> (their_gw, their_ref)
	our_ipref   *b.Tree  // map[uint32]IpRefRec		our_ip -> (our_gw,   our_ref)
	oid         uint32   // must be the same for both mgw and mtun
	cur_mark    []uint32 // current mark per oid
	soft        map[IP32]SoftRec
	pfx         string // prefix for printing messages
	purge       struct {
		state     int
		btree_enu *b.Enumerator
	}
}

func (mgw *MapGw) init(oid uint32) {

	mgw.pfx = "mgw"
	mgw.their_ipref = b.TreeNew(b.Cmp(addr_cmp))
	mgw.our_ipref = b.TreeNew(b.Cmp(addr_cmp))
	mgw.oid = oid
	mgw.cur_mark = make([]uint32, 2)
	mgw.soft = make(map[IP32]SoftRec)
	mgw.purge.state = MGW_PURGE_START
}

func (mgw *MapGw) get_pfx() string {
	return mgw.pfx
}

func (mgw *MapGw) get_oid() uint32 {
	return mgw.oid
}

// return current mark for a given oid
func (mgw *MapGw) get_cur_mark(oid uint32) uint32 {

	if oid < len(mgw.cur_mark) {
		if mark, ok := mgw.cur_mark[oid]; ok {
			return mark
		}
	}
	return 0
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

		send_arec(mgw, 0, src, cli.gw_ip, ref, recv_gw)
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
	log.debug("mgw: set mark %v(%v): %v", owners.name(oid), oid, mark)
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
		log.debug("mgw: update soft %v:%v mtu(%v) ttl/hops %v/%v", soft.gw, soft.port,
			soft.mtu, soft.ttl, soft.hops)
		mgw.soft[soft.gw] = soft
	} else {
		log.debug("mgw: remove soft %v", soft.gw)
		delete(mgw.soft, soft.gw)
	}

	return DROP
}

func (mgw *MapGw) timer(pb *PktBuf) int {

	var key interface{}
	var val interface{}
	var err error

	mark := be.Uint32(pb.pkt[pb.v1hdr+V1_MARK : pb.v1hdr+V1_MARK+4])

	switch mgw.purge.state {
	case MGW_PURGE_START:

		//log.debug("mgw: purge START mark(%v)", mark)
		mgw.purge.state = MGW_PURGE_THEIR_IPREF_SEEK
		fallthrough

	case MGW_PURGE_THEIR_IPREF_SEEK:

		//log.debug("mgw: purge THEIR_IPREF_SEEK mark(%v)", mark)
		mgw.purge.btree_enu, err = mgw.their_ipref.SeekFirst()
		if err != nil {
			log.err("mgw: cannot get enumerator for their_ipref")
			return DROP
		}

		mgw.purge.state = MGW_PURGE_THEIR_IPREF
		fallthrough

	case MGW_PURGE_THEIR_IPREF:

		//log.debug("mgw: purge THEIR_IPREF mark(%v)", mark)
		num := mgw.their_ipref.Len() / ((MAPPER_TMOUT * 1000) / (FWD_TIMER_IVL + FWD_TIMER_FUZZ/2))
		if num < MAPPER_PURGE_MIN {
			num = MAPPER_PURGE_MIN
		}

		for ii := 0; ii < num; ii++ {

			key, val, err = mgw.purge.btree_enu.Next()
			if err != nil {
				break // error or no more items
			}
			oid := val.(IpRefRec).oid
			if int(oid) >= len(mgw.cur_mark) {
				log.err("mgw: invalid oid(%v) in their_ipref, deleting record", oid)
				mgw.their_ipref.Delete(key)
			} else if val.(IpRefRec).mark < mgw.cur_mark[oid] {
				if cli.debug["mapper"] || cli.debug["all"] {
					rec := val.(IpRefRec)
					log.debug("mgw: purge THEIR_IPREF mark(%v), removing %v %v %v(%v) %v",
						mark, rec.ip, &rec.ref, owners.name(oid), oid, rec.mark)
				}
				mgw.their_ipref.Delete(key)
			}
		}

		if err != io.EOF {
			return DROP
		}

		mgw.purge.btree_enu.Close()

		mgw.purge.state = MGW_PURGE_OUR_IPREF_SEEK
		fallthrough

	case MGW_PURGE_OUR_IPREF_SEEK:

		//log.debug("mgw: purge OUR_IPREF_SEEK mark(%v)", mark)
		mgw.purge.btree_enu, err = mgw.our_ipref.SeekFirst()
		if err != nil {
			log.err("mgw: cannot get enumerator for our_ipref")
			return DROP
		}

		mgw.purge.state = MGW_PURGE_OUR_IPREF
		fallthrough

	case MGW_PURGE_OUR_IPREF:

		//log.debug("mgw: purge OUR_IPREF mark(%v)", mark)
		num := mgw.our_ipref.Len() / ((MAPPER_TMOUT * 1000) / (FWD_TIMER_IVL + FWD_TIMER_FUZZ/2))
		if num < MAPPER_PURGE_MIN {
			num = MAPPER_PURGE_MIN
		}

		for ii := 0; ii < num; ii++ {

			key, val, err = mgw.purge.btree_enu.Next()
			if err != nil {
				break // error or no more items
			}
			oid := val.(IpRefRec).oid
			if int(oid) >= len(mgw.cur_mark) {
				log.err("mgw: invalid oid(%v) in our_ipref, deleting record", oid)
				mgw.our_ipref.Delete(key)
			} else if val.(IpRefRec).mark < mgw.cur_mark[oid] {
				if cli.debug["mapper"] || cli.debug["all"] {
					rec := val.(IpRefRec)
					log.debug("mgw: purge OUR_IPREF mark(%v), removing %v %v %v(%v) %v",
						mark, rec.ip, &rec.ref, owners.name(oid), oid, rec.mark)
				}
				mgw.our_ipref.Delete(key)
			}
		}

		if err != io.EOF {
			return DROP
		}

		mgw.purge.btree_enu.Close()

		mgw.purge.state = MGW_PURGE_STOP
		fallthrough

	case MGW_PURGE_STOP:

		//log.debug("mgw: purge STOP mark(%v)", mark)
		mgw_timer_done <- true
		mgw.purge.state = MGW_PURGE_START
		return DROP
	}

	log.err("mgw: unknown purge state: %v", mgw.purge.state)
	return DROP
}

// -- MapTun -------------------------------------------------------------------

const ( // purge states
	MTUN_PURGE_START = iota + 1
	MTUN_PURGE_OUR_IP_SEEK
	MTUN_PURGE_OUR_IP
	MTUN_PURGE_OUR_IP_SUB_SEEK
	MTUN_PURGE_OUR_IP_SUB
	MTUN_PURGE_OUR_EA_SEEK
	MTUN_PURGE_OUR_EA
	MTUN_PURGE_OUR_EA_SUB_SEEK
	MTUN_PURGE_OUR_EA_SUB
	MTUN_PURGE_STOP
)

type MapTun struct {
	our_ip   *b.Tree  // map[uint32]map[Ref]IpRec		our_gw   -> our_ref   -> our_ip
	our_ea   *b.Tree  // map[uint32]map[Ref]IpRec		their_gw -> their_ref -> our_ea
	oid      uint32   // must be the same for both mgw and mtun
	cur_mark []uint32 // current mark per oid
	soft     map[IP32]SoftRec
	pfx      string
	purge    struct {
		state      int
		btree_enu  *b.Enumerator // first level btree enumerator
		sbtree     *b.Tree       // second level btree
		sbtree_enu *b.Enumerator // second level btree enumerator
	}
}

func (mtun *MapTun) init(oid uint32) {

	mtun.pfx = "mtun"
	mtun.our_ip = b.TreeNew(b.Cmp(addr_cmp))
	mtun.our_ea = b.TreeNew(b.Cmp(addr_cmp))
	mtun.oid = oid
	mtun.cur_mark = make([]uint32, 2)
	mtun.soft = make(map[IP32]SoftRec)
	mtun.purge.state = MTUN_PURGE_START
}

func (mtun *MapTun) get_pfx() string {
	return mtun.pfx
}

func (mtun *MapTun) get_oid() uint32 {
	return mtun.oid
}

// return current mark for a given oid
func (mtun *MapTun) get_cur_mark(oid uint32) uint32 {

	if oid < len(mtun.cur_mark) {
		if mark, ok := mtun.cur_mark[oid]; ok {
			return mark
		}
	}
	return 0
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

func (mtun *MapTun) set_soft(src IP32, soft SoftRec) {

	log.debug("mtun: set soft %v:%v mtu(%v) ttl/hops %v/%v", soft.gw, soft.port,
		soft.mtu, soft.ttl, soft.hops)

	mtun.soft[src] = soft

	send_soft_rec(soft) // tel mgw about new or changed soft record
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

	var key interface{}
	var val interface{}
	var oid uint32
	var err error

	mark := be.Uint32(pb.pkt[pb.v1hdr+V1_MARK : pb.v1hdr+V1_MARK+4])

	// no easy way to count number of records, we estimate instead as 4 x ea
	num := mtun.our_ea.Len() * 4 / ((MAPPER_TMOUT * 1000) / (FWD_TIMER_IVL + FWD_TIMER_FUZZ/2))
	if num < MAPPER_PURGE_MIN {
		num = MAPPER_PURGE_MIN
	}

	for ii := 0; ii < num; ii++ {

		switch mtun.purge.state {
		case MTUN_PURGE_START:

			//log.debug("mtun: purge START mark(%v)", mark)
			mtun.purge.state = MTUN_PURGE_OUR_IP_SEEK
			fallthrough

		case MTUN_PURGE_OUR_IP_SEEK:

			//log.debug("mtun: purge OUR_IP_SEEK mark(%v)", mark)
			mtun.purge.btree_enu, err = mtun.our_ip.SeekFirst()
			if err != nil {
				log.err("mtun: cannot get enumerator for our_ip")
				return DROP
			}

			mtun.purge.state = MTUN_PURGE_OUR_IP
			fallthrough

		case MTUN_PURGE_OUR_IP:

			//log.debug("mtun: purge OUR_IP mark(%v)", mark)

			key, val, err = mtun.purge.btree_enu.Next()
			if err != nil {
				if err == io.EOF {
					mtun.purge.btree_enu.Close()
					mtun.purge.state = MTUN_PURGE_OUR_EA_SEEK
					continue
				}
				log.err("mtun: error getting OUR_IP subtree")
				return DROP
			}

			mtun.purge.sbtree = val.(*b.Tree)
			if mtun.purge.sbtree.Len() == 0 {
				log.debug("mtun: purge OUR_IP empty subtree for gw %v, removing gw", key.(IP32))
				mtun.our_ip.Delete(key)
				continue
			}
			mtun.purge.state = MTUN_PURGE_OUR_IP_SUB_SEEK
			fallthrough

		case MTUN_PURGE_OUR_IP_SUB_SEEK:

			//log.debug("mtun: purge OUR_IP_SUB_SEEK mark(%v)", mark)

			mtun.purge.sbtree_enu, err = mtun.purge.sbtree.SeekFirst()
			if err != nil {
				log.err("mtun: cannot get enumerator for our_ip subtree")
				return DROP
			}

			mtun.purge.state = MTUN_PURGE_OUR_IP_SUB
			fallthrough

		case MTUN_PURGE_OUR_IP_SUB:

			//log.debug("mtun: purge OUR_IP_SUB mark(%v)", mark)

			key, val, err = mtun.purge.sbtree_enu.Next()
			if err != nil {
				if err == io.EOF {
					mtun.purge.sbtree_enu.Close()
					mtun.purge.state = MTUN_PURGE_OUR_IP // go back to first level
					continue
				}
				log.err("mtun: error getting OUR_IP_SUB record")
				return DROP
			}

			oid = val.(IpRec).oid
			rec := val.(IpRec)
			if int(oid) >= len(mtun.cur_mark) {
				log.err("mtun: invalid oid(%v) in our_ip, removing  %v %v(%v) %v",
					oid, rec.ip, "invalid", oid, rec.mark)
				mtun.purge.sbtree.Delete(key)
			} else if val.(IpRec).mark < mtun.cur_mark[oid] {
				if cli.debug["mapper"] || cli.debug["all"] {
					log.debug("mtun: purge OUR_IP_SUB mark(%v), removing %v %v(%v) %v",
						mark, rec.ip, owners.name(oid), oid, rec.mark)
				}
				mtun.purge.sbtree.Delete(key)
			}

			continue

		case MTUN_PURGE_OUR_EA_SEEK:

			//log.debug("mtun: purge OUR_EA_SEEK mark(%v)", mark)
			mtun.purge.btree_enu, err = mtun.our_ea.SeekFirst()
			if err != nil {
				log.err("mtun: cannot get enumerator for our_ea")
				return DROP
			}

			mtun.purge.state = MTUN_PURGE_OUR_EA
			fallthrough

		case MTUN_PURGE_OUR_EA:

			//log.debug("mtun: purge OUR_EA mark(%v)", mark)

			key, val, err = mtun.purge.btree_enu.Next()
			if err != nil {
				if err == io.EOF {
					mtun.purge.btree_enu.Close()
					mtun.purge.state = MTUN_PURGE_STOP
					continue
				}
				log.err("mtun: error getting OUR_EA subtree")
				return DROP
			}

			mtun.purge.sbtree = val.(*b.Tree)
			if mtun.purge.sbtree.Len() == 0 {
				log.debug("mtun: purge OUR_EA empty subtree for gw %v, removing gw and its soft record", key.(IP32))
				gw := key.(IP32)
				// remove soft, tell mgw about it, then remove the key as the last step
				delete(mtun.soft, gw)
				send_soft_rec(SoftRec{gw, 0, 0, 0, 0}) // port == 0 means remove record
				mtun.our_ea.Delete(key)
				continue
			}
			mtun.purge.state = MTUN_PURGE_OUR_EA_SUB_SEEK
			fallthrough

		case MTUN_PURGE_OUR_EA_SUB_SEEK:

			//log.debug("mtun: purge OUR_EA_SUB_SEEK mark(%v)", mark)

			mtun.purge.sbtree_enu, err = mtun.purge.sbtree.SeekFirst()
			if err != nil {
				log.err("mtun: cannot get enumerator for our_ea subtree")
				return DROP
			}

			mtun.purge.state = MTUN_PURGE_OUR_EA_SUB
			fallthrough

		case MTUN_PURGE_OUR_EA_SUB:

			//log.debug("mtun: purge OUR_EA_SUB mark(%v)", mark)

			key, val, err = mtun.purge.sbtree_enu.Next()
			if err != nil {
				if err == io.EOF {
					mtun.purge.sbtree_enu.Close()
					mtun.purge.state = MTUN_PURGE_OUR_EA // go back to first level
					continue
				}
				log.err("mtun: error getting OUR_EA_SUB record")
				return DROP
			}

			oid = val.(IpRec).oid
			rec := val.(IpRec)
			if int(oid) >= len(mtun.cur_mark) {
				log.err("mtun: invalid oid(%v) in our_ea, removing %v %v(%v) %v",
					oid, rec.ip, "invalid", oid, rec.mark)
				mtun.purge.sbtree.Delete(key)
			} else if val.(IpRec).mark < mtun.cur_mark[oid] {
				if cli.debug["mapper"] || cli.debug["all"] {
					log.debug("mtun: purge OUR_EA_SUB mark(%v), removing %v %v(%v) %v",
						mark, rec.ip, owners.name(oid), oid, rec.mark)
				}
				mtun.purge.sbtree.Delete(key)
			}

			continue

		case MTUN_PURGE_STOP:

			//log.debug("mtun: purge STOP mark(%v)", mark)
			mtun_timer_done <- true
			mtun.purge.state = MTUN_PURGE_START
			return DROP
		}

		log.err("mtun: unknown purge state: %v", mtun.purge.state)
	}

	return DROP
}

// -- Mapper helpers -----------------------------------------------------------
