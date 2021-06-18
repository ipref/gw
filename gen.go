/* Copyright (c) 2018-2021 Waldemar Augustyn */

package main

import (
	"crypto/rand"
	rff "github.com/ipref/ref"
	prng "math/rand" // where crypto/rand would be an overkill
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

	RCVY_MAX    = 7                      // max records to recover at a time
	RCVY_EXPIRE = (MAPPER_TMOUT * 3) / 2 // extra time before attempting recovery
)

// -- ea gen -------------------------------------------------------------------

type GenEA struct {
	allocated map[IP32]bool
	bcast     IP32
	ea        chan IP32 // mapper random ea
	recv      chan *PktBuf
}

var gen_ea GenEA

// trigger recovery of expired eas
func (gen *GenEA) recover_expired_eas() {

	const PAUSE = 257 // [ms]

	recover_ea := make(chan *PktBuf, PKTQLEN)
	pktid := uint16(prng.Intn(0xffff)) + 1 // make sure it's not zero

	// initiate ea recovery scan

	pb := <-getbuf
	pb.write_v1_header(V1_REQ|V1_RECOVER_EA, pktid)
	pkt := pb.pkt[pb.iphdr:]

	off := V1_HDR_LEN

	be.PutUint32(pkt[off+V1_OID:off+V1_OID+4], uint32(mapper_oid))
	be.PutUint32(pkt[off+V1_MARK:off+V1_MARK+4], 0)

	off += V1_MARK_LEN

	be.PutUint32(pkt[off:off+4], 0) // find first address after 0.0.0.0

	off += 4

	pb.tail = pb.iphdr + off
	be.PutUint16(pkt[V1_PKTLEN:V1_PKTLEN+2], uint16(off/4))
	pb.peer = "recover_ea"
	pb.schan = recover_ea
	db.recv <- pb

	// recover eas

loop:
	for pb = range recover_ea {

		if err := pb.validate_v1_header(pb.len()); err != nil {

			log.err("recover ea: invalid v1 packet from %v:  %v", pb.peer, err)
			break loop
		}

		pkt := pb.pkt[pb.iphdr:pb.tail]

		cmd := pkt[V1_CMD]

		if cli.trace {
			pb.pp_raw("recover ea:  ")
		}

		switch cmd {

		case V1_ACK | V1_RECOVER_EA:

			// pass the list to forwarders

			pbf := <-getbuf
			pbf.copy_from(pb)

			pbf.pkt[pbf.iphdr+V1_CMD] = V1_DATA | V1_RECOVER_EA
			pbf.peer = "recover_ea"
			recv_tun <- pbf

			// ask db for more

			pkt = pb.pkt[pb.iphdr:pb.tail]
			off = pb.len() - 4 // last returned ip address
			if off < V1_HDR_LEN+V1_MARK_LEN {
				break loop // no more eas
			}

			ip := be.Uint32(pkt[off : off+4])

			off = V1_HDR_LEN + V1_MARK_LEN
			be.PutUint32(pkt[off:off+4], ip+1) // next IP address

			off += 4

			pkt[V1_CMD] = V1_DATA | V1_RECOVER_EA

			pktid = be.Uint16(pkt[V1_PKTID:V1_PKTID+2]) + 1
			if pktid == 0 {
				pktid++
			}
			be.PutUint16(pkt[V1_PKTID:V1_PKTID+2], pktid)

			pb.tail = pb.iphdr + off
			be.PutUint16(pkt[V1_PKTLEN:V1_PKTLEN+2], uint16(off/4))
			pb.peer = "recover_ea"
			pb.schan = recover_ea

			sleep(PAUSE, PAUSE/4) // pause a little

			db.recv <- pb

		case V1_NACK | V1_RECOVER_EA:
			break loop
		default:
			log.err("recover ea: unrecognized v1 cmd: 0x%x from %v", cmd, pb.peer)
			break loop
		}
	}

	retbuf <- pb
}

// generate a random ea with second to last byte >= SECOND_BYTE
func (gen *GenEA) next_ea() IP32 {

	var ea IP32
	creep := make([]byte, 4)
	var err error

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

		if gen.allocated[ea] {
			continue // already allocated, try another
		}
		gen.allocated[ea] = true

		return ea
	}

	log.err("gen_ea: cannot allocate ea")
	return 0
}

func (gen *GenEA) receive(pb *PktBuf) {

	retbuf <- pb
}

func (gen *GenEA) start() {

	// generate eas

	go func(gen *GenEA) {
		ea := gen.next_ea()
		for {
			select {
			case gen.ea <- ea:
				ea = gen.next_ea()
			case pb := <-gen.recv:
				gen.receive(pb)
			}
		}
	}(gen)

	// recover expired eas

	go func(gen *GenEA) {

		const DELAY = (MAPPER_TMOUT * 1000) / 3 // [ms]

		for {
			sleep(DELAY, DELAY/8)
			gen.recover_expired_eas()
		}

	}(gen)
}

func (gen *GenEA) init() {
	gen.allocated = make(map[IP32]bool)
	gen.bcast = 0xffffffff &^ cli.ea_mask
	gen.ea = make(chan IP32, GENQLEN)
	gen.recv = make(chan *PktBuf, PKTQLEN)
}

// -- ref gen ------------------------------------------------------------------

type GenREF struct {
	allocated map[rff.Ref]bool
	ref       chan rff.Ref // mapper random ref
	recv      chan *PktBuf
}

var gen_ref GenREF

// generate random refs with second to last byte >= SECOND_BYTE
func (gen *GenREF) next_ref() rff.Ref {

	var ref rff.Ref
	var refzero rff.Ref // constant rff.Ref{0,0}
	creep := make([]byte, 16)

	// clear ref before incrementing ii
	for ii := 0; ii < MAXTRIES; ii, ref = ii+1, refzero {

		_, err := rand.Read(creep[7:])
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

		if gen.allocated[ref] {
			continue // already allocated, try another
		}
		gen.allocated[ref] = true

		return ref
	}

	log.err("gen_ref: cannot allocate ref")
	return refzero
}

func (gen *GenREF) receive(pb *PktBuf) {

	retbuf <- pb
}

func (gen *GenREF) start() {

	go func(gen *GenREF) {
		ref := gen.next_ref()
		for {
			select {
			case gen.ref <- ref:
				ref = gen.next_ref()
			case pb := <-gen.recv:
				gen.receive(pb)
			}
		}
	}(gen)
}

func (gen *GenREF) init() {
	gen.allocated = make(map[rff.Ref]bool)
	gen.ref = make(chan rff.Ref, GENQLEN)
	gen.recv = make(chan *PktBuf, PKTQLEN)
}
