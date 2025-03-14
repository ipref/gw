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

	RCVY_INTERVAL = (MAPPER_TMOUT * 1000) / 3 // [ms] interval between recovery attempts
	RCVY_PAUSE    = 257                       // [ms] pause between recovery batches
	RCVY_MAX      = 7                         // max records to recover at a time
	RCVY_EXPIRE   = (MAPPER_TMOUT * 3) / 2    // [s] extra time before attempting recovery
)

var refzero rff.Ref // constant rff.Ref{0,0}

// -- ea gen -------------------------------------------------------------------

type GenEA struct {
	allocated map[IP32]bool
	bcast     IP32
	ea        chan IP32 // mapper random ea
	recv      chan *PktBuf
	rcvy      chan IP32
}

var gen_ea GenEA

// trigger recovery of expired eas
func (gen *GenEA) recover_expired_eas() {

	pktid := uint16(prng.Intn(0x10000))

	go func() {
		sleep(prng.Intn(MAPPER_TMOUT/3)*1000, (MAPPER_TMOUT/8)*1000) // random start point
		for {
			sleep(RCVY_INTERVAL, RCVY_INTERVAL/8)
			gen.rcvy <- 0
		}
	}()

	for search_ea := range gen.rcvy {

		sleep(RCVY_PAUSE, RCVY_PAUSE/5) // small delay between recovery batches

		if pktid += 1; pktid == 0 {
			pktid++
		}

		pb := <-getbuf
		pb.write_v1_header(V1_REQ|V1_RECOVER_EA, pktid)
		pkt := pb.pkt[pb.data:]

		off := V1_HDR_LEN

		be.PutUint32(pkt[off+V1_OID:off+V1_OID+4], uint32(mapper_oid))
		be.PutUint32(pkt[off+V1_MARK:off+V1_MARK+4], 0)

		off += V1_MARK_LEN

		for ii := off; ii < V1_AREC_LEN; ii++ {
			pkt[off+ii] = 0
		}

		be.PutUint32(pkt[off+V1_AREC_EA:off+V1_AREC_EA+4], uint32(search_ea))

		off += V1_AREC_LEN

		pb.tail = pb.data + off
		be.PutUint16(pkt[V1_PKTLEN:V1_PKTLEN+2], uint16(off/4))
		pb.peer = "recover ea"
		pb.schan = gen.recv
		log.debug("gen ea:  recover eas starting from: %v", search_ea)
		db.recv <- pb
	}
}

func (gen *GenEA) receive(pb *PktBuf) int {

	if err := pb.validate_v1_header(pb.len()); err != nil {

		log.err("gen ea:  invalid v1 packet from %v:  %v", pb.peer, err)
		return DROP
	}

	pkt := pb.pkt[pb.data:pb.tail]

	cmd := pkt[V1_CMD]

	if cli.trace {
		pb.pp_raw("gen ea:  ")
	}

	pktlen := len(pkt)

	switch cmd {

	case V1_ACK | V1_RECOVER_EA:

		last_off := pktlen - V1_AREC_LEN

		if last_off < V1_HDR_LEN+V1_MARK_LEN {
			break // paranoia, should never happen
		}

		// trigger next batch

		ea := IP32(be.Uint32(pkt[last_off+V1_AREC_EA : last_off+V1_AREC_EA+4]))
		gen.rcvy <- ea + 1

		// pass the list to fwd_to_tun

		pkt[V1_CMD] = V1_DATA | V1_RECOVER_EA
		pb.peer = "recover ea"
		pb.schan = retbuf
		recv_gw <- pb

		return ACCEPT

	case V1_NACK | V1_RECOVER_EA:

		log.debug("gen ea:  no more eas to recover")

	case V1_DATA | V1_RECOVER_EA:

		if pktlen < V1_HDR_LEN+V1_MARK_LEN+V1_AREC_LEN {
			log.err("gen ea:  packet too short, ignoring")
			break
		}

		off := V1_HDR_LEN + V1_MARK_LEN

		if (pktlen-off)%V1_AREC_LEN != 0 {
			log.err("gen ea:  corrupted packet, ignoring")
			break
		}

		for ; off < pktlen; off += V1_AREC_LEN {

			ea := IP32(be.Uint32(pkt[off+V1_AREC_EA : off+V1_AREC_EA+4]))

			if ea != 0 {
				delete(gen.allocated, ea)
				if cli.debug["gen"] {
					var gw IP32
					var ref rff.Ref
					gw = IP32(be.Uint32(pkt[off+V1_AREC_GW : off+V1_AREC_GW+4]))
					ref.H = be.Uint64(pkt[off+V1_AREC_REFH : off+V1_AREC_REFH+8])
					ref.L = be.Uint64(pkt[off+V1_AREC_REFL : off+V1_AREC_REFL+8])
					log.debug("gen ea:  deleted allocated ea(%v): %v + %v", ea, gw, &ref)
				}
			}
		}

	default:
		log.err("gen ea:  unrecognized v1 cmd[%02x] from %v", cmd, pb.peer)
	}

	return DROP
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
		log.debug("gen ea:  allocated ea(%v)", ea)

		return ea
	}

	log.err("gen ea:  cannot allocate ea")
	return 0
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
				if gen.receive(pb) == DROP {
					retbuf <- pb
				}
			}
		}
	}(gen)

	// recover expired eas

	go gen.recover_expired_eas()
}

func (gen *GenEA) init() {
	gen.allocated = make(map[IP32]bool)
	gen.bcast = 0xffffffff &^ cli.ea_mask
	gen.ea = make(chan IP32, GENQLEN)
	gen.recv = make(chan *PktBuf, PKTQLEN)
	gen.rcvy = make(chan IP32, PKTQLEN)
}

// -- ref gen ------------------------------------------------------------------

type GenREF struct {
	allocated map[rff.Ref]bool
	ref       chan rff.Ref // mapper random ref
	recv      chan *PktBuf
	rcvy      chan rff.Ref
}

var gen_ref GenREF

// trigger recovery of expired refs
func (gen *GenREF) recover_expired_refs() {

	pktid := uint16(prng.Intn(0x10000))

	go func() {
		sleep(prng.Intn(MAPPER_TMOUT/3)*1000, (MAPPER_TMOUT/8)*1000) // random start point
		for {
			sleep(RCVY_INTERVAL, RCVY_INTERVAL/8)
			gen.rcvy <- refzero
		}
	}()

	for search_ref := range gen.rcvy {

		sleep(RCVY_PAUSE, RCVY_PAUSE/5) // small delay between recovery batches

		if pktid += 1; pktid == 0 {
			pktid++
		}

		pb := <-getbuf
		pb.write_v1_header(V1_REQ|V1_RECOVER_REF, pktid)
		pkt := pb.pkt[pb.data:]

		off := V1_HDR_LEN

		be.PutUint32(pkt[off+V1_OID:off+V1_OID+4], uint32(mapper_oid))
		be.PutUint32(pkt[off+V1_MARK:off+V1_MARK+4], 0)

		off += V1_MARK_LEN

		for ii := off; ii < V1_AREC_LEN; ii++ {
			pkt[off+ii] = 0
		}

		be.PutUint64(pkt[off+V1_AREC_REFH:off+V1_AREC_REFH+8], search_ref.H)
		be.PutUint64(pkt[off+V1_AREC_REFL:off+V1_AREC_REFL+8], search_ref.L)

		off += V1_AREC_LEN

		pb.tail = pb.data + off
		be.PutUint16(pkt[V1_PKTLEN:V1_PKTLEN+2], uint16(off/4))
		pb.peer = "recover ref"
		pb.schan = gen.recv
		log.debug("gen ref: recover refs starting from: %v", &search_ref)
		db.recv <- pb
	}
}

func (gen *GenREF) receive(pb *PktBuf) int {

	if pb.typ != PKT_V1 {
		log.fatal("gen ref: invalid packet type")
	}

	if err := pb.validate_v1_header(pb.len()); err != nil {

		log.err("gen ref: invalid v1 packet from %v:  %v", pb.peer, err)
		return DROP
	}

	pkt := pb.pkt[pb.data:pb.tail]

	cmd := pkt[V1_CMD]

	if cli.trace {
		pb.pp_raw("gen ref: ")
	}

	pktlen := len(pkt)

	var ref rff.Ref

	switch cmd {

	case V1_ACK | V1_RECOVER_REF:

		last_off := pktlen - V1_AREC_LEN

		if last_off < V1_HDR_LEN+V1_MARK_LEN {
			break // paranoia, should never happen
		}

		// trigger next batch

		ref.H = be.Uint64(pkt[last_off+V1_AREC_REFH : last_off+V1_AREC_REFH+8])
		ref.L = be.Uint64(pkt[last_off+V1_AREC_REFL : last_off+V1_AREC_REFL+8])

		if ref.L == 0xffffffffffffffff {
			ref.H++
			ref.L = 0
		} else {
			ref.L++
		}

		gen.rcvy <- ref

		// pass the list to fwd_to_gw

		pkt[V1_CMD] = V1_DATA | V1_RECOVER_REF
		pb.peer = "recover ref"
		pb.schan = retbuf
		recv_tun <- pb

		return ACCEPT

	case V1_NACK | V1_RECOVER_REF:

		log.debug("gen ref: no more refs to recover")

	case V1_DATA | V1_RECOVER_REF:

		if pktlen < V1_HDR_LEN+V1_MARK_LEN+V1_AREC_LEN {
			log.err("gen ref: packet too short, ignoring")
			break
		}

		off := V1_HDR_LEN + V1_MARK_LEN

		if (pktlen-off)%V1_AREC_LEN != 0 {
			log.err("gen ref: corrupted packet, ignoring")
			break
		}

		for ; off < pktlen; off += V1_AREC_LEN {

			ref.H = be.Uint64(pkt[off+V1_AREC_REFH : off+V1_AREC_REFH+8])
			ref.L = be.Uint64(pkt[off+V1_AREC_REFL : off+V1_AREC_REFL+8])

			if !ref.IsZero() {
				delete(gen.allocated, ref)
				if cli.debug["gen"] {
					var ip IP32
					var gw IP32
					ip = IP32(be.Uint32(pkt[off+V1_AREC_IP : off+V1_AREC_IP+4]))
					gw = IP32(be.Uint32(pkt[off+V1_AREC_GW : off+V1_AREC_GW+4]))
					log.debug("gen ref:  deleted allocated gw+ref(%v + %v) -> %v", gw, &ref, ip)
				}
			}
		}

	default:
		log.err("gen ref:  unrecognized v1 cmd: 0x%x from %v", cmd, pb.peer)
	}

	return DROP
}

// generate random refs with second to last byte >= SECOND_BYTE
func (gen *GenREF) next_ref() rff.Ref {

	var ref rff.Ref
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
		log.debug("gen ref: allocated ref(%v)", &ref)

		return ref
	}

	log.err("gen_ref: cannot allocate ref")
	return refzero
}

func (gen *GenREF) start() {

	go func(gen *GenREF) {
		ref := gen.next_ref()
		for {
			select {
			case gen.ref <- ref:
				ref = gen.next_ref()
			case pb := <-gen.recv:
				if gen.receive(pb) == DROP {
					retbuf <- pb
				}
			}
		}
	}(gen)

	// recover expired refs

	go gen.recover_expired_refs()
}

func (gen *GenREF) init() {
	gen.allocated = make(map[rff.Ref]bool)
	gen.ref = make(chan rff.Ref, GENQLEN)
	gen.recv = make(chan *PktBuf, PKTQLEN)
	gen.rcvy = make(chan rff.Ref, PKTQLEN)
}
