/* Copyright (c) 2018-2020 Waldemar Augustyn */

package main

import (
	"crypto/rand"
	rff "github.com/ipref/ref"
	"io"
	"modernc.org/b"
	"sync"
)

/* Address and reference allocation

Local network encoded addresses and references may be allocated by the mapper
or by a local DNS server. To avoid conflicts, this implementation imposes
a rule where the second to last byte of an allocated IP address or the second
to last byte of an allocated reference must be 100 or higher if allocated
by the mapper and it must be less than 100 if allocated by DNS server or
listed in /etc/hosts.
*/

const (
	GENQLEN     = 2
	SECOND_BYTE = 100
	MIN_REF     = 256 // low ref values are reserved
	MAXTRIES    = 10  // num of tries to get unique random value before giving up

	RECOVERY_CHECK_TICK = TIMER_TICK * 5  // [ms] avg 84.055 [s]
	RECOVERY_TICK       = TIMER_TICK / 11 // [ms] avg  1.528 [s]
	RECOVERY_NUM        = 11              // items at a time
	RECOVERY_THRESHOLD  = 80              // % of used allocation to trigger ea recovery
)

// -- ea gen -------------------------------------------------------------------

type GenEA struct {
	allocated *b.Tree
	mtx       sync.Mutex
	bcast     IP32
}

var gen_ea GenEA
var recover_ea chan *PktBuf
var random_mapper_ea chan IP32

// query for expired eas
func (gen *GenEA) check_for_expired() {

	var pktid uint16

	threshold := (RECOVERY_THRESHOLD * int(cli.ea_mask^0xffffffff)) / 100

	for ; ; sleep(RECOVERY_CHECK_TICK, RECOVERY_CHECK_TICK/TIMER_FUZZ) {

		gen.mtx.Lock()
		num_allocated := gen.allocated.Len()
		gen.mtx.Unlock()

		if num_allocated < threshold {
			continue
		}

		log.info("gen ea: recovery threshold reached: %v ea allocated, recovering expired ea addresses", num_allocated)

		gen.mtx.Lock()
		enu, err := gen.allocated.SeekFirst()
		gen.mtx.Unlock()

		if err != nil {
			continue // empty tree
		}

		for err := error(nil); err == nil; sleep(RECOVERY_TICK, RECOVERY_TICK/TIMER_FUZZ) {

			var key interface{}
			//var val interface{}

			pktid++
			if pktid == 0 {
				pktid++
			}

			pb := <-getbuf
			pb.write_v1_header(V1_REQ|V1_RECOVER_EA, pktid)
			pkt := pb.pkt[pb.iphdr:]

			off := V1_HDR_LEN

			be.PutUint32(pkt[off:off+4], uint32(mapper_oid))

			off += 4

			for ix := 0; ix < RECOVERY_NUM; ix++ {

				gen.mtx.Lock()
				key, _, err = enu.Next() //  err is defined in the outer loop
				gen.mtx.Unlock()

				if err != nil {
					if err != io.EOF {
						log.err("gen ea: cannot read ea from 'allocated': %v", err)
					}
					break
				}

				copy(pkt[off:off+4], []byte{0, 0, 0, 0})
				be.PutUint32(pkt[off+4:off+4+4], uint32(key.(IP32)))
				off += 4
			}

			pb.tail = pb.iphdr + off
			be.PutUint16(pkt[V1_PKTLEN:V1_PKTLEN+2], uint16(off/4))
			pb.peer = "gen_ea"
			pb.schan = recover_ea
			recv_tun <- pb
		}
	}
}

func (gen *GenEA) remove_expired_eas(pb *PktBuf) {

	pkt := pb.pkt[pb.iphdr:pb.tail]
	pktlen := len(pkt)

	off := V1_HDR_LEN

	if off+4 > pktlen {
		log.err("recover ea: pkt too short")
		return
	}

	oid := O32(be.Uint32(pkt[off : off+4]))

	if oid != mapper_oid {
		log.err("reocver ea: oid(%v) does not match mapper oid(%v)", oid, mapper_oid)
		return
	}

	off += 4

	if (pktlen-off)%8 != 0 {
		log.err("recover ea: corrupted packet")
		return
	}

	for ; off < pktlen; off += 8 {

		mark := M32(be.Uint32(pkt[off : off+4]))

		if mark == 0 {
			ea := IP32(be.Uint32(pkt[off+4 : off+4+4]))
			gen.mtx.Lock()
			ok := gen.allocated.Delete(ea)
			gen.mtx.Unlock()
			log.debug("recover ea: removed %v (%v)", ea, ok)
		}
	}
}

// listen to messages sent in response to queries for expired eas
func (gen *GenEA) recover_expired() {

	for pb := range recover_ea {

		if err := pb.validate_v1_header(pb.len()); err != nil {

			log.err("recover ea: invalid v1 packet from %v:  %v", pb.peer, err)
			retbuf <- pb
			continue
		}

		pkt := pb.pkt[pb.iphdr:pb.tail]

		cmd := pkt[V1_CMD]

		if cli.trace {
			pb.pp_raw("recover ea:  ")
		}

		switch cmd {

		case V1_DATA | V1_NOOP:

		case V1_ACK | V1_RECOVER_EA:
			gen.remove_expired_eas(pb)
		default:
			log.err("recover ea: invalid v1 pkt: %02x", cmd)
		}

		retbuf <- pb
	}
}

/*
// generate random eas with second to last byte < SECOND_BYTE
func (gen *GenEA) gen_dns_eas() {

	var ea IP32
	creep := make([]byte, 4)
	var err error

	for {
		// clear ea before incrementing ii
		for ii := 0; ii < MAXTRIES; ii, ea = ii+1, 0 {

			_, err = rand.Read(creep[1:])
			if err != nil {
				continue // cannot get random number
			}

			creep[2] %= SECOND_BYTE
			ea = IP32(be.Uint32(creep))

			ea &^= cli.ea_mask
			if ea == 0 || ea == gen.bcast {
				continue // zero address or broadcast address, try another
			}
			ea |= cli.ea_ip
			_, ok := gen.allocated[ea]
			if ok {
				continue // already allocated
			}
			gen.allocated[ea] = true
			break
		}
		random_dns_ea <- ea
	}
}
*/

// generate random eas with second to last byte >= SECOND_BYTE
func (gen *GenEA) gen_mapper_eas() {

	var ea IP32
	creep := make([]byte, 4)
	var err error
	var added bool

	for {
		// clear ea before incrementing ii
		for ii := 0; ii < MAXTRIES; ii, ea = ii+1, 0 {

			_, err = rand.Read(creep[1:])
			if err != nil {
				continue // cannot get random number
			}

			creep[2] %= 256 - SECOND_BYTE
			creep[2] += SECOND_BYTE
			ea = IP32(be.Uint32(creep))

			ea &^= cli.ea_mask
			if ea == 0 || ea == gen.bcast {
				continue // zero address or broadcast address, try another
			}

			ea |= cli.ea_ip

			gen.mtx.Lock()

			_, added = gen.allocated.Put(ea, func(old interface{}, exists bool) (interface{}, bool) {
				return M32(0), !exists
			})

			gen.mtx.Unlock()

			if added {
				break // allocated new ea
			}
		}
		random_mapper_ea <- ea
	}
}

func (gen *GenEA) start() {

	//go gen.gen_dns_eas()
	go gen.gen_mapper_eas()
	go gen.check_for_expired()
	go gen.recover_expired()
}

func (gen *GenEA) init() {
	gen.bcast = 0xffffffff &^ cli.ea_mask
	gen.allocated = b.TreeNew(b.Cmp(addr_cmp))
	recover_ea = make(chan *PktBuf, PKTQLEN)
	//random_dns_ea = make(chan IP32, GENQLEN)
	random_mapper_ea = make(chan IP32, GENQLEN)
}

// -- ref gen ------------------------------------------------------------------

type GenREF struct {
	allocated *b.Tree
	mtx       sync.Mutex
}

var gen_ref GenREF
var recover_ref chan *PktBuf
var random_mapper_ref chan rff.Ref

func (gen *GenREF) check_for_expired() {

	var pktid uint16

	threshold := 7 // arbitrary initial allocations

	for ; ; sleep(RECOVERY_CHECK_TICK, RECOVERY_CHECK_TICK/TIMER_FUZZ) {

		gen.mtx.Lock()
		num_allocated := gen.allocated.Len()
		gen.mtx.Unlock()

		if num_allocated <= threshold {
			continue
		}
		threshold = num_allocated // we recover when allocations exceeds previously detected allocations

		log.info("gen ref: recovery threshold reached: %v ref allocated, recovering expired refs", num_allocated)

		gen.mtx.Lock()
		enu, err := gen.allocated.SeekFirst()
		gen.mtx.Unlock()

		if err != nil {
			continue // empty tree
		}

		for err := error(nil); err == nil; sleep(RECOVERY_TICK, RECOVERY_TICK/TIMER_FUZZ) {

			var key interface{}
			//var val interface{}

			pktid++
			if pktid == 0 {
				pktid++
			}

			pb := <-getbuf
			pb.write_v1_header(V1_REQ|V1_RECOVER_REF, pktid)
			pkt := pb.pkt[pb.iphdr:]

			off := V1_HDR_LEN

			be.PutUint32(pkt[off:off+4], uint32(mapper_oid))

			off += 4

			for ix := 0; ix < RECOVERY_NUM; ix++ {

				gen.mtx.Lock()
				key, _, err = enu.Next() //  err is defined in the outer loop
				gen.mtx.Unlock()

				if err != nil {
					if err != io.EOF {
						log.err("gen ref: cannot read ref from 'allocated': %v", err)
					}
					break
				}

				copy(pkt[off:off+4], []byte{0, 0, 0, 0})
				be.PutUint64(pkt[off+4:off+4+8], key.(rff.Ref).H)
				be.PutUint64(pkt[off+4+8:off+4+8+8], key.(rff.Ref).L)
				off += 20
			}

			pb.tail = pb.iphdr + off
			be.PutUint16(pkt[V1_PKTLEN:V1_PKTLEN+2], uint16(off/4))
			pb.peer = "gen_ref"
			pb.schan = recover_ref
			recv_tun <- pb
		}
	}
}

func (gen *GenREF) remove_expired_refs(pb *PktBuf) {

	pkt := pb.pkt[pb.iphdr:pb.tail]
	pktlen := len(pkt)

	off := V1_HDR_LEN

	if off+4 > pktlen {
		log.err("recover ref: pkt too short")
		return
	}

	oid := O32(be.Uint32(pkt[off : off+4]))

	if oid != mapper_oid {
		log.err("recover ref: oid(%v) does not match mapper oid(%v)", oid, mapper_oid)
		return
	}

	off += 4

	if (pktlen-off)%20 != 0 {
		log.err("recover ref: corrupted packet")
		return
	}

	var ref rff.Ref

	for ; off < pktlen; off += 20 {

		mark := M32(be.Uint32(pkt[off : off+4]))

		if mark == 0 {
			ref.H = be.Uint64(pkt[off+4 : off+4+8])
			ref.L = be.Uint64(pkt[off+4+8 : off+4+8+8])
			gen.mtx.Lock()
			ok := gen.allocated.Delete(ref)
			gen.mtx.Unlock()
			log.debug("recover ref: removed %v (%v)", &ref, ok)
		}
	}
}

// listen to messages sent in response to queries for expired refs
func (gen *GenREF) recover_expired() {

	for pb := range recover_ref {

		if err := pb.validate_v1_header(pb.len()); err != nil {

			log.err("recover ref: invalid v1 packet from %v:  %v", pb.peer, err)
			retbuf <- pb
			continue
		}

		pkt := pb.pkt[pb.iphdr:pb.tail]

		cmd := pkt[V1_CMD]

		if cli.trace {
			pb.pp_raw("recover ref:  ")
		}

		switch cmd {

		case V1_DATA | V1_NOOP:

		case V1_ACK | V1_RECOVER_REF:
			gen.remove_expired_refs(pb)
		default:
			log.err("recover ref: invalid v1 pkt: %02x", cmd)
		}

		retbuf <- pb
	}
}

// generate random refs with second to last byte >= SECOND_BYTE
func (gen *GenREF) gen_mapper_refs() {

	var ref rff.Ref
	var refzero rff.Ref // constant rff.Ref{0,0}
	creep := make([]byte, 16)
	var err error
	var added bool

	for {
		// clear ref before incrementing ii
		for ii := 0; ii < MAXTRIES; ii, ref = ii+1, refzero {

			_, err = rand.Read(creep[7:])
			if err != nil {
				continue // cannot get random number
			}

			creep[14] %= 256 - SECOND_BYTE
			creep[14] += SECOND_BYTE
			creep[7] >>= 4 // make 64 bit refs happen more often
			ref.H = be.Uint64(creep[:8])
			ref.L = be.Uint64(creep[8:])

			if ref.H == 0 && ref.L < MIN_REF {
				continue // reserved ref
			}

			gen.mtx.Lock()

			_, added = gen.allocated.Put(ref, func(old interface{}, exists bool) (interface{}, bool) {
				return refzero, !exists
			})

			gen.mtx.Unlock()

			if added {
				break // allocated new ref
			}
		}
		random_mapper_ref <- ref
	}
}

func (gen *GenREF) start() {
	go gen.gen_mapper_refs()
	go gen.check_for_expired()
	go gen.recover_expired()
}

func (gen *GenREF) init() {
	gen.allocated = b.TreeNew(b.Cmp(ref_cmp))
	recover_ref = make(chan *PktBuf, PKTQLEN)
	random_mapper_ref = make(chan rff.Ref, GENQLEN)
}
