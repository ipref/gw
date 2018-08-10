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
	mark uint32 // time offset or revision (which could be time offset, too)
	oid  int32  // owner id
}

type IpRec struct {
	ip   uint32
	mark uint32
	oid  int32
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
	their_ipref *b.Tree // map[uint32]IpRefRec		our_ea -> (their_gw, their_ref)
	our_ipref   *b.Tree // map[uint32]IpRefRec		our_ip -> (our_gw,   our_ref)
}

func (mgw *MapGw) init() {

	mgw.their_ipref = b.TreeNew(b.Cmp(addr_cmp))
	mgw.our_ipref = b.TreeNew(b.Cmp(addr_cmp))
}

func (mgw *MapGw) timer(pb *PktBuf) int {
	return DROP
}

func (mgw *MapGw) address_records(pb *PktBuf) int {
	return DROP
}

// -- MapTun -------------------------------------------------------------------

type MapTun struct {
	our_ip *b.Tree // map[uint32]map[Ref]IpRec		our_gw   -> our_ref   -> our_ip
	our_ea *b.Tree // map[uint32]map[Ref]IpRec		their_gw -> their_ref -> our_ea
}

func (mtun *MapTun) init() {

	mtun.our_ip = b.TreeNew(b.Cmp(addr_cmp))
	mtun.our_ea = b.TreeNew(b.Cmp(addr_cmp))
}

// -- Variables ----------------------------------------------------------------

var marker Mark
var owners Owners

var map_gw MapGw   // exclusively owned by fwd_to_gw
var map_tun MapTun // exclusively owned by fwd_to_tun
