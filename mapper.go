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

type M32 int32   // mark, a monotonic counter
type O32 int32   // owner id, an index into array
type IP32 uint32 // ip address

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

// send soft record to fwd_to_gw forwarder
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
func send_arec(pfx string, ea, ip, gw IP32, ref Ref, oid O32, mark M32, pktq chan<- *PktBuf) {

	pb := <-getbuf

	if len(pb.pkt)-pb.data < V1_HDR_LEN+4+V1_AREC_LEN {
		log.fatal("%v: not enough space for an address record", pfx) // paranoia
	}

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

	pktq <- pb
}

// -- mapper variables ---------------------------------------------------------

const (
	MAPPER_TMOUT     = 1800                          // [s] mapper record timeout
	MAPPER_REFRESH   = MAPPER_TMOUT - MAPPER_TMOUT/4 // [s] when to refresh
	MAPPER_PURGE_MIN = 15                            // min items to purge at a time
)

var mapper_oid O32
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
	their_ipref *b.Tree // map[uint32]IpRefRec		our_ea -> (their_gw, their_ref)
	our_ipref   *b.Tree // map[uint32]IpRefRec		our_ip -> (our_gw,   our_ref)
	oid         O32     // must be the same for both mgw and mtun
	cur_mark    []M32   // current mark per oid
	soft        map[IP32]SoftRec
	pfx         string // prefix for printing messages
	purge       struct {
		state     int
		btree_enu *b.Enumerator
	}
}

func (mgw *MapGw) init(oid O32) {

	mgw.pfx = "mgw"
	mgw.their_ipref = b.TreeNew(b.Cmp(addr_cmp))
	mgw.our_ipref = b.TreeNew(b.Cmp(addr_cmp))
	mgw.oid = oid
	mgw.cur_mark = make([]M32, 2)
	mgw.soft = make(map[IP32]SoftRec)
	mgw.purge.state = MGW_PURGE_START
}

func (mgw *MapGw) set_cur_mark(oid O32, mark M32) {

	if oid == 0 || mark == 0 {
		log.fatal("mgw: unexpected invalid oid(%v) or mark(%v)", oid, mark)
	}
	if int(oid) >= len(mgw.cur_mark) {
		mgw.cur_mark = append(mgw.cur_mark, make([]M32, int(oid)-len(mgw.cur_mark)+1)...)
	}
	mgw.cur_mark[oid] = mark
}

func (mgw *MapGw) get_dst_ipref(dst IP32) IpRefRec {

	iprefrec, ok := mgw.their_ipref.Get(dst)
	if !ok {
		log.debug("mgw: dst ipref not found for: %v", dst)
		return IpRefRec{0, Ref{0, 0}, 0, 0} // not found
	}

	rec := iprefrec.(IpRefRec)

	if int(rec.oid) >= len(mgw.cur_mark) {
		log.err("mgw: invalid oid(%v) in their_ipref, ignoring record", rec.oid)
		return IpRefRec{0, Ref{0, 0}, 0, 0}
	}

	if rec.mark < mgw.cur_mark[rec.oid] {
		log.debug("mgw: dst ipref expired for: %v", dst)
		return IpRefRec{0, Ref{0, 0}, 0, 0} // expired
	}

	if rec.oid == mgw.oid && rec.mark-mgw.cur_mark[mgw.oid] < MAPPER_REFRESH {

		log.debug("mgw: refreshing dst ipref for: %v", dst)
		mark := mgw.cur_mark[mgw.oid] + MAPPER_TMOUT
		rec.mark = mark
		mgw.their_ipref.Set(dst, rec)                                           // bump up expiration
		send_arec(mgw.pfx, dst, 0, rec.ip, rec.ref, rec.oid, rec.mark, recv_gw) // tell mtun
	}

	return rec
}

func (mgw *MapGw) get_src_ipref(src IP32) IpRefRec {

	iprefrec, ok := mgw.our_ipref.Get(src)

	if ok {

		rec := iprefrec.(IpRefRec)

		if int(rec.oid) >= len(mgw.cur_mark) {
			log.err("mgw: invalid oid(%v) in our_ipref, ignoring record", rec.oid)
			return IpRefRec{0, Ref{0, 0}, 0, 0}
		}

		if rec.mark < mgw.cur_mark[rec.oid] {

			log.debug("mgw: src ipref expired for: %v, reallocating", src)

		} else {

			if rec.oid == mgw.oid && rec.mark-mgw.cur_mark[mgw.oid] < MAPPER_REFRESH {

				log.debug("mgw: refreshing src ipref for: %v", src)
				mark := mgw.cur_mark[mgw.oid] + MAPPER_TMOUT
				rec.mark = mark
				mgw.our_ipref.Set(src, rec)                                             // bump up expiration
				send_arec(mgw.pfx, 0, src, rec.ip, rec.ref, rec.oid, rec.mark, recv_gw) // tell mtun
			}

			return rec
		}
	}

	// local host's ip does not have a map to ipref, create one

	ref := <-random_mapper_ref
	if ref.isZero() {
		log.err("mgw: cannot get new reference for %v, ignoring record", src)
		return IpRefRec{0, Ref{0, 0}, 0, 0}
	}
	mark := mgw.cur_mark[mgw.oid] + MAPPER_TMOUT
	rec := IpRefRec{cli.gw_ip, ref, mgw.oid, mark}
	mgw.our_ipref.Set(src, rec)                                             // add new record
	send_arec(mgw.pfx, 0, src, rec.ip, rec.ref, rec.oid, rec.mark, recv_gw) // tell mtun

	return rec
}

func (mgw *MapGw) set_new_address_records(pb *PktBuf) int {

	pkt := pb.pkt[pb.v1hdr:pb.tail]
	if len(pkt) < V1_HDR_LEN+V1_AREC_HDR_LEN+V1_AREC_LEN {
		log.err("mgw: SET_AREC packet too short, dropping")
		return DROP
	}
	oid := O32(be.Uint32(pkt[V1_OID : V1_OID+4]))
	mark := M32(be.Uint32(pkt[V1_MARK : V1_MARK+4]))

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
	oid := O32(be.Uint32(pkt[V1_OID : V1_OID+4]))
	mark := M32(be.Uint32(pkt[V1_MARK : V1_MARK+4]))
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

	num := mgw.their_ipref.Len() / ((MAPPER_TMOUT * 1000) / (FWD_TIMER_IVL + FWD_TIMER_FUZZ/2))
	if num < MAPPER_PURGE_MIN {
		num = MAPPER_PURGE_MIN
	}

	for ii := 0; ii < num; ii++ {

		switch mgw.purge.state {
		case MGW_PURGE_START:

			mgw.purge.state = MGW_PURGE_THEIR_IPREF_SEEK
			fallthrough

		case MGW_PURGE_THEIR_IPREF_SEEK:

			mgw.purge.btree_enu, err = mgw.their_ipref.SeekFirst()
			if err != nil {
				log.err("mgw: cannot get enumerator for their_ipref: %v", err)
				return DROP
			}

			mgw.purge.state = MGW_PURGE_THEIR_IPREF
			fallthrough

		case MGW_PURGE_THEIR_IPREF:

			key, val, err = mgw.purge.btree_enu.Next()

			if err == nil {

				rec := val.(IpRefRec)
				if int(rec.oid) >= len(mgw.cur_mark) {
					log.err("mgw: invalid oid(%v) in their_ipref, removing %v %v %v(%v) %v",
						rec.oid, rec.ip, &rec.ref, "invalid", rec.oid, rec.mark)
					mgw.their_ipref.Delete(key)
				} else if rec.mark < mgw.cur_mark[rec.oid] {
					if cli.debug["mapper"] || cli.debug["all"] {
						log.debug("mgw: purge THEIR_IPREF mark(%v), removing %v %v %v(%v) %v",
							mgw.cur_mark[rec.oid], rec.ip, &rec.ref, owners.name(rec.oid),
							rec.oid, rec.mark)
					}
					mgw.their_ipref.Delete(key)
				}
				continue

			} else if err != io.EOF {
				log.err("mgw: cannot get val from their_ipref: %v", err)
				return DROP
			}

			mgw.purge.btree_enu.Close()

			mgw.purge.state = MGW_PURGE_OUR_IPREF_SEEK
			fallthrough

		case MGW_PURGE_OUR_IPREF_SEEK:

			mgw.purge.btree_enu, err = mgw.our_ipref.SeekFirst()
			if err != nil {
				log.err("mgw: cannot get enumerator for our_ipref: %v", err)
				return DROP
			}

			mgw.purge.state = MGW_PURGE_OUR_IPREF
			fallthrough

		case MGW_PURGE_OUR_IPREF:

			key, val, err = mgw.purge.btree_enu.Next()

			if err == nil {

				rec := val.(IpRefRec)
				if int(rec.oid) >= len(mgw.cur_mark) {
					log.err("mgw: invalid oid(%v) in our_ipref, removing %v %v %v(%v) %v",
						rec.oid, rec.ip, &rec.ref, "invalid", rec.oid, rec.mark)
					mgw.our_ipref.Delete(key)
				} else if rec.mark < mgw.cur_mark[rec.oid] {
					if cli.debug["mapper"] || cli.debug["all"] {
						log.debug("mgw: purge OUR_IPREF mark(%v), removing %v %v %v(%v) %v",
							mgw.cur_mark[rec.oid], rec.ip, &rec.ref, owners.name(rec.oid),
							rec.oid, rec.mark)
					}
					mgw.our_ipref.Delete(key)
				}
				continue

			} else if err != io.EOF {
				log.err("mgw: cannot get val from our_ipref: %v", err)
				return DROP
			}

			mgw.purge.btree_enu.Close()

			mgw.purge.state = MGW_PURGE_STOP
			fallthrough

		case MGW_PURGE_STOP:

			mgw.purge.state = MGW_PURGE_START
			mgw_timer_done <- true
			return DROP
		}

		log.err("mgw: unknown purge state: %v", mgw.purge.state)
	}

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
	our_ip   *b.Tree // map[uint32]map[Ref]IpRec		our_gw   -> our_ref   -> our_ip
	our_ea   *b.Tree // map[uint32]map[Ref]IpRec		their_gw -> their_ref -> our_ea
	oid      O32     // must be the same for both mgw and mtun
	cur_mark []M32   // current mark per oid
	soft     map[IP32]SoftRec
	pfx      string
	purge    struct {
		state      int
		btree_enu  *b.Enumerator // first level btree enumerator
		sbtree     *b.Tree       // second level btree
		sbtree_enu *b.Enumerator // second level btree enumerator
	}
}

func (mtun *MapTun) init(oid O32) {

	mtun.pfx = "mtun"
	mtun.our_ip = b.TreeNew(b.Cmp(addr_cmp))
	mtun.our_ea = b.TreeNew(b.Cmp(addr_cmp))
	mtun.oid = oid
	mtun.cur_mark = make([]M32, 2)
	mtun.soft = make(map[IP32]SoftRec)
	mtun.purge.state = MTUN_PURGE_START
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

	log.debug("mtun: set soft %v:%v mtu(%v) ttl/hops %v/%v", soft.gw, soft.port,
		soft.mtu, soft.ttl, soft.hops)

	mtun.soft[src] = soft

	send_soft_rec(soft) // tel mgw about new or changed soft record
}

func (mtun *MapTun) get_dst_ip(gw IP32, ref Ref) IP32 {

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
		log.debug("mtun: dst ip expired for: %v + %v", gw, &ref)
		return 0 // expired
	}

	if rec.oid == mtun.oid && rec.mark-mtun.cur_mark[mtun.oid] < MAPPER_REFRESH {

		log.debug("mtun: refreshing dst ip for: %v + %v", gw, &ref)
		mark := mtun.cur_mark[mtun.oid] + MAPPER_TMOUT
		rec.mark = mark
		our_refs.(*b.Tree).Set(ref, rec)                                     // bump up expiration
		send_arec(mtun.pfx, 0, rec.ip, gw, ref, rec.oid, rec.mark, recv_tun) // tell mgw
	}

	return rec.ip
}

func (mtun *MapTun) get_src_ea(gw IP32, ref Ref) IP32 {

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
			return 0
		}

		if rec.mark < mtun.cur_mark[rec.oid] {

			log.debug("mtun: src ea expired for: %v + %v, reallocating", gw, &ref)

		} else {

			if rec.oid == mtun.oid && rec.mark-mtun.cur_mark[mtun.oid] < MAPPER_REFRESH {

				log.debug("mtun: refreshing src ea for: %v + %v", gw, ref)
				mark := mtun.cur_mark[mtun.oid] + MAPPER_TMOUT
				rec.mark = mark
				their_refs.(*b.Tree).Set(ref, rec)                                   // bump up expiration
				send_arec(mtun.pfx, rec.ip, 0, gw, ref, rec.oid, rec.mark, recv_tun) // tell mgw
			}

			return rec.ip
		}
	}

	// no ea for this remote host, allocate one

	ea := <-random_mapper_ea
	if ea == 0 {
		log.err("mtun: cannot get new ea for %v + %v, ignoring record", gw, &ref)
		return 0 // cannot get new ea
	}
	mark := mtun.cur_mark[mtun.oid] + MAPPER_TMOUT
	rec := IpRec{ea, mtun.oid, mark}
	their_refs.(*b.Tree).Set(ref, rec)
	send_arec(mtun.pfx, rec.ip, 0, gw, ref, rec.oid, rec.mark, recv_tun) // tell mgw

	return rec.ip
}

func (mtun *MapTun) set_new_address_records(pb *PktBuf) int {

	pkt := pb.pkt[pb.v1hdr:pb.tail]
	if len(pkt) < V1_HDR_LEN+V1_AREC_HDR_LEN+V1_AREC_LEN {
		log.err("mtun: SET_AREC packet too short, dropping")
		return DROP
	}
	oid := O32(be.Uint32(pkt[V1_OID : V1_OID+4]))
	mark := M32(be.Uint32(pkt[V1_MARK : V1_MARK+4]))

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
	oid := O32(be.Uint32(pkt[V1_OID : V1_OID+4]))
	mark := M32(be.Uint32(pkt[V1_MARK : V1_MARK+4]))
	log.debug("mtun: set mark %v(%v): %v", owners.name(oid), oid, mark)
	mtun.set_cur_mark(oid, mark)

	return DROP
}

func (mtun *MapTun) timer(pb *PktBuf) int {

	var key interface{}
	var val interface{}
	var oid O32
	var err error

	// no easy way to count number of records, we estimate instead as 4 x ea
	num := mtun.our_ea.Len() * 4 / ((MAPPER_TMOUT * 1000) / (FWD_TIMER_IVL + FWD_TIMER_FUZZ/2))
	if num < MAPPER_PURGE_MIN {
		num = MAPPER_PURGE_MIN
	}

	for ii := 0; ii < num; ii++ {

		switch mtun.purge.state {
		case MTUN_PURGE_START:

			mtun.purge.state = MTUN_PURGE_OUR_IP_SEEK
			fallthrough

		case MTUN_PURGE_OUR_IP_SEEK:

			mtun.purge.btree_enu, err = mtun.our_ip.SeekFirst()
			if err != nil {
				log.err("mtun: cannot get enumerator for our_ip: %v", err)
				return DROP
			}

			mtun.purge.state = MTUN_PURGE_OUR_IP
			fallthrough

		case MTUN_PURGE_OUR_IP:

			key, val, err = mtun.purge.btree_enu.Next()
			if err != nil {
				if err == io.EOF {
					mtun.purge.btree_enu.Close()
					mtun.purge.state = MTUN_PURGE_OUR_EA_SEEK
					continue
				}
				log.err("mtun: error getting OUR_IP subtree: %v", err)
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

			mtun.purge.sbtree_enu, err = mtun.purge.sbtree.SeekFirst()
			if err != nil {
				log.err("mtun: cannot get enumerator for our_ip subtree: %v", err)
				return DROP
			}

			mtun.purge.state = MTUN_PURGE_OUR_IP_SUB
			fallthrough

		case MTUN_PURGE_OUR_IP_SUB:

			key, val, err = mtun.purge.sbtree_enu.Next()
			if err != nil {
				if err == io.EOF {
					mtun.purge.sbtree_enu.Close()
					mtun.purge.state = MTUN_PURGE_OUR_IP // go back to first level
					continue
				}
				log.err("mtun: error getting OUR_IP_SUB record: %v", err)
				return DROP
			}

			rec := val.(IpRec)
			if int(rec.oid) >= len(mtun.cur_mark) {
				log.err("mtun: invalid oid(%v) in our_ip, removing  %v %v(%v) %v",
					rec.oid, rec.ip, "invalid", rec.oid, rec.mark)
				mtun.purge.sbtree.Delete(key)
			} else if rec.mark < mtun.cur_mark[rec.oid] {
				if cli.debug["mapper"] || cli.debug["all"] {
					log.debug("mtun: purge OUR_IP_SUB mark(%v), removing %v %v(%v) %v",
						mtun.cur_mark[rec.oid], rec.ip, owners.name(rec.oid), rec.oid, rec.mark)
				}
				mtun.purge.sbtree.Delete(key)
			}

			continue

		case MTUN_PURGE_OUR_EA_SEEK:

			mtun.purge.btree_enu, err = mtun.our_ea.SeekFirst()
			if err != nil {
				log.err("mtun: cannot get enumerator for our_ea: %v", err)
				return DROP
			}

			mtun.purge.state = MTUN_PURGE_OUR_EA
			fallthrough

		case MTUN_PURGE_OUR_EA:

			key, val, err = mtun.purge.btree_enu.Next()
			if err != nil {
				if err == io.EOF {
					mtun.purge.btree_enu.Close()
					mtun.purge.state = MTUN_PURGE_STOP
					continue
				}
				log.err("mtun: error getting OUR_EA subtree: %v", err)
				return DROP
			}

			mtun.purge.sbtree = val.(*b.Tree)
			if mtun.purge.sbtree.Len() == 0 {
				gw := key.(IP32)
				log.debug("mtun: purge OUR_EA empty subtree for gw %v, removing gw and its soft record", gw)
				// remove soft, tell mgw about it, then remove the key last
				delete(mtun.soft, gw)
				send_soft_rec(SoftRec{gw, 0, 0, 0, 0}) // port == 0 means remove record
				mtun.our_ea.Delete(key)
				continue
			}
			mtun.purge.state = MTUN_PURGE_OUR_EA_SUB_SEEK
			fallthrough

		case MTUN_PURGE_OUR_EA_SUB_SEEK:

			mtun.purge.sbtree_enu, err = mtun.purge.sbtree.SeekFirst()
			if err != nil {
				log.err("mtun: cannot get enumerator for our_ea subtree: %v", err)
				return DROP
			}

			mtun.purge.state = MTUN_PURGE_OUR_EA_SUB
			fallthrough

		case MTUN_PURGE_OUR_EA_SUB:

			key, val, err = mtun.purge.sbtree_enu.Next()
			if err != nil {
				if err == io.EOF {
					mtun.purge.sbtree_enu.Close()
					mtun.purge.state = MTUN_PURGE_OUR_EA // go back to first level
					continue
				}
				log.err("mtun: error getting OUR_EA_SUB record: %v", err)
				return DROP
			}

			rec := val.(IpRec)
			if int(rec.oid) >= len(mtun.cur_mark) {
				log.err("mtun: invalid oid(%v) in our_ea, removing %v %v(%v) %v",
					rec.oid, rec.ip, "invalid", rec.oid, rec.mark)
				mtun.purge.sbtree.Delete(key)
			} else if rec.mark < mtun.cur_mark[oid] {
				if cli.debug["mapper"] || cli.debug["all"] {
					log.debug("mtun: purge OUR_EA_SUB mark(%v), removing %v %v(%v) %v",
						mtun.cur_mark[oid], rec.ip, owners.name(rec.oid), rec.oid, rec.mark)
				}
				mtun.purge.sbtree.Delete(key)
			}

			continue

		case MTUN_PURGE_STOP:

			mtun.purge.state = MTUN_PURGE_START
			mtun_timer_done <- true
			return DROP
		}

		log.err("mtun: unknown purge state: %v", mtun.purge.state)
	}

	return DROP
}

// -- Mapper helpers -----------------------------------------------------------
