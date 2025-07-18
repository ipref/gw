/* Copyright (c) 2018-2021 Waldemar Augustyn */

package main

import (
	"crypto/rand"
	. "github.com/ipref/common"
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
	SECOND_BYTE = 16
	MIN_REF     = 256 // low ref values are reserved
	MAXTRIES    = 10  // num of tries to get unique random value before giving up

	RCVY_INTERVAL = (MAPPER_TMOUT * 1000) / 3 // [ms] interval between recovery attempts
	RCVY_PAUSE    = 257                       // [ms] pause between recovery batches
	RCVY_MAX      = 7                         // max records to recover at a time
	RCVY_EXPIRE   = (MAPPER_TMOUT * 3) / 2    // [s] extra time before attempting recovery
)

// -- ea gen -------------------------------------------------------------------

type GenEA struct {
	allocated map[IP]bool
	bcast     IP
	ea        chan IP // mapper random ea
	recv      chan *PktBuf
	rcvy      chan IP
}

var gen_ea GenEA

// trigger recovery of expired eas
func (gen *GenEA) recover_expired_eas() {

	pktid := uint16(prng.Intn(0x10000))

	go func() {
		sleep(prng.Intn(MAPPER_TMOUT/3)*1000, (MAPPER_TMOUT/8)*1000) // random start point
		for {
			sleep(RCVY_INTERVAL, RCVY_INTERVAL/8)
			gen.rcvy <- IPNum(ea_iplen, 0)
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

		arec := AddrRecDecode(ea_iplen, gw_iplen, pkt[off:])
		arec.EA = search_ea
		arec.Encode(pkt[off:])

		off += v1_arec_len

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

		last_off := pktlen - v1_arec_len

		if last_off < V1_HDR_LEN+V1_MARK_LEN {
			break // paranoia, should never happen
		}

		// trigger next batch

		arec := AddrRecDecode(ea_iplen, gw_iplen, pkt[last_off:])
		gen.rcvy <- arec.EA.Add(IPNum(ea_iplen, 1))

		// pass the list to fwd_to_tun

		pkt[V1_CMD] = V1_DATA | V1_RECOVER_EA
		pb.peer = "recover ea"
		pb.schan = retbuf
		recv_gw <- pb

		return ACCEPT

	case V1_NACK | V1_RECOVER_EA:

		log.debug("gen ea:  no more eas to recover")

	case V1_DATA | V1_RECOVER_EA:

		if pktlen < V1_HDR_LEN+V1_MARK_LEN+v1_arec_len {
			log.err("gen ea:  packet too short, ignoring")
			break
		}

		off := V1_HDR_LEN + V1_MARK_LEN

		if (pktlen-off)%v1_arec_len != 0 {
			log.err("gen ea:  corrupted packet, ignoring")
			break
		}

		for ; off < pktlen; off += v1_arec_len {

			arec := AddrRecDecode(ea_iplen, gw_iplen, pkt[off:])

			if !arec.EA.IsZeroAddr() {
				delete(gen.allocated, arec.EA)
				if cli.debug["gen"] {
					log.debug("gen ea:  deleted allocated ea(%v): %v + %v", arec.EA, arec.GW, &arec.Ref)
				}
			}
		}

	default:
		log.err("gen ea:  unrecognized v1 cmd[%02x] from %v", cmd, pb.peer)
	}

	return DROP
}

// generate a random ea with second to last byte >= SECOND_BYTE
func (gen *GenEA) next_ea() IP {

	creep := make([]byte, ea_iplen)
	var err error

	// clear ea before incrementing ii
	for ii := 0; ii < MAXTRIES; ii = ii+1 {

		_, err = rand.Read(creep[1:])
		if err != nil {
			continue // cannot get random number
		}

		// modulo bias not a problem, it doesn't need to be uniformly distributed
		creep[len(creep) - 2] %= 256 - SECOND_BYTE
		creep[len(creep) - 2] += SECOND_BYTE
		ea := IPFromSlice(creep)

		ea = ea.And(gen.bcast)
		if ea.IsZeroAddr() || ea == gen.bcast {
			continue // zero address or broadcast address, try another
		}

		ea = ea.Or(IP(cli.ea_net.Addr()))

		if gen.allocated[ea] {
			continue // already allocated, try another
		}
		gen.allocated[ea] = true
		log.debug("gen ea:  allocated ea(%v)", ea)

		return ea
	}

	log.err("gen ea:  cannot allocate ea")
	return IP{}
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
	gen.allocated = make(map[IP]bool)
	gen.bcast = IPBits(len(cli.ea_ip.AsSlice()), cli.ea_net.Bits()).Not()
	gen.ea = make(chan IP, GENQLEN)
	gen.recv = make(chan *PktBuf, PKTQLEN)
	gen.rcvy = make(chan IP, PKTQLEN)
}

// -- ref gen ------------------------------------------------------------------

type GenREF struct {
	allocated map[Ref]bool
	ref       chan Ref // mapper random ref
	recv      chan *PktBuf
	rcvy      chan Ref
}

var gen_ref GenREF

// trigger recovery of expired refs
func (gen *GenREF) recover_expired_refs() {

	pktid := uint16(prng.Intn(0x10000))

	go func() {
		sleep(prng.Intn(MAPPER_TMOUT/3)*1000, (MAPPER_TMOUT/8)*1000) // random start point
		for {
			sleep(RCVY_INTERVAL, RCVY_INTERVAL/8)
			gen.rcvy <- Ref{}
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

		arec := AddrRecDecode(ea_iplen, gw_iplen, pkt[off:])
		arec.Ref = search_ref
		arec.Encode(pkt[off:])

		off += v1_arec_len

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

	var ref Ref

	switch cmd {

	case V1_ACK | V1_RECOVER_REF:

		last_off := pktlen - v1_arec_len

		if last_off < V1_HDR_LEN+V1_MARK_LEN {
			break // paranoia, should never happen
		}

		// trigger next batch

		arec := AddrRecDecode(ea_iplen, gw_iplen, pkt[last_off:])

		if ^arec.Ref.L == 0 {
			arec.Ref.H++
			arec.Ref.L = 0
		} else {
			arec.Ref.L++
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

		if pktlen < V1_HDR_LEN+V1_MARK_LEN+v1_arec_len {
			log.err("gen ref: packet too short, ignoring")
			break
		}

		off := V1_HDR_LEN + V1_MARK_LEN

		if (pktlen-off)%v1_arec_len != 0 {
			log.err("gen ref: corrupted packet, ignoring")
			break
		}

		for ; off < pktlen; off += v1_arec_len {

			arec := AddrRecDecode(ea_iplen, gw_iplen, pkt[off:])

			if !arec.Ref.IsZero() {
				delete(gen.allocated, arec.Ref)
				if cli.debug["gen"] {
					log.debug("gen ref:  deleted allocated gw+ref(%v + %v) -> %v",
						arec.GW, &arec.Ref, arec.IP)
				}
			}
		}

	default:
		log.err("gen ref:  unrecognized v1 cmd: 0x%x from %v", cmd, pb.peer)
	}

	return DROP
}

// generate random refs with second to last byte >= SECOND_BYTE
func (gen *GenREF) next_ref() Ref {

	var ref Ref
	creep := make([]byte, 16)

	// clear ref before incrementing ii
	for ii := 0; ii < MAXTRIES; ii, ref = ii+1, (Ref{}) {

		_, err := rand.Read(creep[7:])
		if err != nil {
			continue // cannot get random number
		}

		// modulo bias not a problem, it doesn't need to be uniformly distributed
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
	return Ref{}
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
	gen.allocated = make(map[Ref]bool)
	gen.ref = make(chan Ref, GENQLEN)
	gen.recv = make(chan *PktBuf, PKTQLEN)
	gen.rcvy = make(chan Ref, PKTQLEN)
}
