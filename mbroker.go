/* Copyright (c) 2018-2021 Waldemar Augustyn */

package main

import (
	"errors"
	. "github.com/ipref/common"
	"math/rand"
	"net"
	"os"
	"path"
	"strings"
	"time"
)

const (
	GET_EA_WAIT = 359 * time.Millisecond // we love prime numbers
)

type Eaq struct {
	pb   *PktBuf
	wait *time.Timer
}

type DnsSrc struct {
	source string
	oid    O32
	hash   uint64
	recs   map[AddrRec]bool // count, deduplicated
	mark   M32
	xmark  M32
}

type MB struct {
	// ipref-plugin
	cur_mark []M32
	eacache  map[IpRef]IpRec
	eaq      map[uint16]Eaq
	// dns sources
	dnssources map[string]DnsSrc
	// base
	recv chan *PktBuf
}

var mb MB

// send NACK after wait time expires
// normally, expected packet arrives before wait time and the timer is cancelled
func (mb *MB) delayed_nack(cmd byte, pktid uint16) {

	pb := <-getbuf
	pb.write_v1_header(V1_NACK|cmd, pktid)
	pb.tail = pb.data + V1_HDR_LEN
	be.PutUint16(pb.pkt[V1_PKTLEN:V1_PKTLEN+2], V1_HDR_LEN/4)
	pb.peer = "delayed NACK"
	mb.recv <- pb
}

// get ea response from forwarders
func (mb *MB) get_ea(rpb *PktBuf) int {

	rpkt := rpb.pkt[rpb.data:rpb.tail]

	// find related originator pkt in eaq

	pktid := be.Uint16(rpkt[V1_PKTID : V1_PKTID+2])

	eaq, exists := mb.eaq[pktid]

	if exists {
		eaq.wait.Stop()
		delete(mb.eaq, pktid)
	} else {
		log.err("mb: get ea pkt: response to unrecognized pktid[%04x], dropping", pktid)
		return DROP
	}

	// send response to the originator

	pb := eaq.pb
	pkt := pb.pkt

	switch rpkt[V1_CMD] {

	case V1_ACK | V1_GET_EA:

		if len(rpkt) < V1_HDR_LEN+V1_MARK_LEN+v1_arec_len {
			log.err("mb: get ea response pkt pktid[%04x]: len(%v) too short, dropping", pktid, len(rpkt))
			retbuf <- pb
			return DROP // rpb
		}

		off := V1_HDR_LEN                // offset to arec in originator's packet
		roff := V1_HDR_LEN + V1_MARK_LEN // offset to arec in response

		arec := AddrRecDecode(ea_iplen, gw_iplen, pkt[off:])
		rarec := AddrRecDecode(ea_iplen, gw_iplen, rpkt[roff:])
		arec.EA = rarec.EA

		if arec != rarec {
			log.err("mb: get ea response pkt pktid[%04x]: request/response mismatch, dropping", pktid)
			retbuf <- pb
			return DROP // rpb
		}

		mb.eacache[IpRef{arec.GW, arec.Ref}] = IpRec{
			ip: rarec.EA,
			oid: O32(be.Uint32(rpkt[roff-V1_MARK_LEN+V1_OID:])),
			mark: M32(be.Uint32(rpkt[roff-V1_MARK_LEN+V1_MARK:])),
		}

		arec.Encode(pkt[off:])
		pkt[V1_CMD] = V1_ACK | V1_MC_GET_EA
		pb.tail = pb.data + V1_HDR_LEN + v1_arec_len

	case V1_NACK | V1_GET_EA:

		pkt[V1_CMD] = V1_NACK | V1_MC_GET_EA
		pb.tail = pb.data + V1_HDR_LEN

	default:
		log.err("mb: get ea pkt: not a response [%02x], dropping", pkt[V1_CMD])
		retbuf <- pb
		return DROP // rpb
	}

	be.PutUint16(pkt[V1_PKTLEN:V1_PKTLEN+2], uint16((pb.tail-pb.data)/4))
	log.debug("mb: out to  %v: %v\n", pb.peer, pb.pp_pkt())
	if cli.trace {
		pb.pp_raw("mbroker out: ")
	}
	pb.schan <- pb
	return DROP // rpb
}

// mc get ea request from ipref plugin
func (mb *MB) mc_get_ea(pb *PktBuf) int {

	pkt := pb.pkt[pb.data:pb.tail]

	if len(pkt) < V1_HDR_LEN+v1_arec_len {
		log.err("mb: mc get ea pkt: len(%v) too short, dropping", len(pkt))
		return DROP
	}

	off := V1_HDR_LEN

	arec := AddrRecDecode(ea_iplen, gw_iplen, pkt[off:])

	ipr := IpRef{arec.GW, arec.Ref}

	// return the ea if found in cache...

	iprec, ok := mb.eacache[ipr]

	if ok {
		if iprec.mark < mb.cur_mark[mapper_oid] {
			delete(mb.eacache, ipr) // expired
		} else {

			// found it

			off := V1_HDR_LEN
			wlen := V1_HDR_LEN + v1_arec_len

			pkt[V1_CMD] = V1_ACK | V1_MC_GET_EA
			arec.EA = iprec.ip
			arec.Encode(pkt[off:])
			be.PutUint16(pkt[V1_PKTLEN:V1_PKTLEN+2], uint16((wlen / 4)))
			pb.tail = pb.data + wlen

			log.debug("mb: out to  %v: %v\n", pb.peer, pb.pp_pkt())
			if cli.trace {
				pb.pp_raw("mbroker out: ")
			}

			pb.schan <- pb
			return ACCEPT
		}
	}

	// ...otherwise pass the request to forwarders

	pktid := be.Uint16(pkt[V1_PKTID : V1_PKTID+2])

	if _, exists := mb.eaq[pktid]; exists {

		log.err("mb: mc get ea pkt: pktid[%04x] already queued, dropping", pktid)
		return DROP
	}

	rpb := <-getbuf
	rpb.write_v1_header(V1_REQ|V1_GET_EA, pktid)
	rpkt := rpb.pkt[rpb.data:]

	off = V1_HDR_LEN

	be.PutUint32(rpkt[off+V1_OID:off+V1_OID+4], uint32(mapper_oid))
	copy(rpkt[off+V1_MARK:off+V1_MARK+4], []byte{0, 0, 0, 0})

	off += V1_MARK_LEN

	copy(rpkt[off:off+v1_arec_len], pkt[V1_HDR_LEN:V1_HDR_LEN+v1_arec_len])

	// don't wait too long

	wait := time.AfterFunc(GET_EA_WAIT, func() { mb.delayed_nack(V1_GET_EA, pktid) })
	mb.eaq[pktid] = Eaq{pb, wait}

	// send to fwd_to_tun

	rpb.tail = rpb.data + V1_HDR_LEN + V1_MARK_LEN + v1_arec_len
	be.PutUint16(rpkt[V1_PKTLEN:V1_PKTLEN+2], uint16(V1_HDR_LEN+V1_MARK_LEN+v1_arec_len)/4)
	rpb.peer = "mbroker"
	rpb.schan = mb.recv
	recv_gw <- rpb
	return ACCEPT
}

func (mb *MB) set_mark(pb *PktBuf) int {

	pkt := pb.pkt[pb.data:pb.tail]

	if len(pkt) < V1_HDR_LEN+V1_MARK_LEN {
		log.err("mb: set mark pkt: len(%v) too short, dropping", len(pkt))
		return DROP
	}

	off := V1_HDR_LEN

	oid := O32(be.Uint32(pkt[off+V1_OID : off+V1_OID+4]))
	mark := M32(be.Uint32(pkt[off+V1_MARK : off+V1_MARK+4]))

	if oid == 0 || mark == 0 {
		log.fatal("mb: unexpected invalid oid(%v) or mark(%v)", oid, mark)
	}
	if int(oid) >= len(mb.cur_mark) {
		mb.cur_mark = append(mb.cur_mark, make([]M32, int(oid)-len(mb.cur_mark)+1)...)
	}
	mb.cur_mark[oid] = mark
	//log.debug("mb: set mark %v(%v): %v", owners.name(oid), oid, mark)

	return DROP
}

// helper function, pkt space must be guaranteed by the caller
func (mb *MB) insert_source(source string, pkt []byte) int {

	off := 0

	for _, src := range strings.Split(source, ":") {

		dnm := []byte(src)
		dnmlen := len(dnm)

		if 0 < dnmlen && dnmlen < 256 { // should be true since DNS names are shorter than 255 chars

			pkt[off] = V1_TYPE_STRING
			pkt[off+1] = byte(dnmlen)
			copy(pkt[off+2:], dnm)

			for off += dnmlen + 2; off&3 != 0; off++ {
				pkt[off] = 0
			}

		} else {
			log.fatal("mb: insert source: dns name too long(%v): %v", dnmlen, src)
		}
	}

	return off
}

func (mb *MB) save_dnssource(dnssrc DnsSrc) {

	// we skip oid and recs fields because they will be deduced when restoring from db

	pb := <-getbuf
	pb.peer = dnssrc.source

	pb.write_v1_header(V1_DATA|V1_SAVE_DNSSOURCE, 0)
	pkt := pb.pkt[pb.data:]
	off := V1_HDR_LEN

	be.PutUint32(pkt[off+V1_DNSSOURCE_MARK:off+V1_DNSSOURCE_MARK+4], uint32(dnssrc.mark))
	be.PutUint32(pkt[off+V1_DNSSOURCE_XMARK:off+V1_DNSSOURCE_XMARK+4], uint32(dnssrc.xmark))
	be.PutUint64(pkt[off+V1_DNSSOURCE_HASH:off+V1_DNSSOURCE_HASH+8], dnssrc.hash)

	off += V1_DNSSOURCE_SOURCE
	off += mb.insert_source(dnssrc.source, pkt[off:])

	be.PutUint16(pkt[V1_PKTLEN:V1_PKTLEN+2], uint16(off/4))
	pb.tail = pb.data + off

	db.recv <- pb
}

// helper function, caller must validate packet
func (mb *MB) parse_source(pkt []byte) (string, int, error) {

	off := 0
	source := ""
	rlen := len(pkt)

	for ix := 0; ix < 2; ix++ {

		if rlen <= off+4 {
			return "", 0, errors.New("invalid source string")
		}

		if pkt[off] != V1_TYPE_STRING || rlen < (off+int(pkt[off+1])+5)&^3 {
			return "", 0, errors.New("invalid source string length")
		}

		source += string(pkt[off+2:off+2+int(pkt[off+1])]) + ":"

		off += (int(pkt[off+1]) + 5) &^ 3
	}

	source = source[:len(source)-1] // strip right colon

	return source, off, nil
}

func (mb *MB) mc_host_data(pb *PktBuf) int {

	if cli.devmode && rand.Intn(10) < 3 { // in devmode, drop packets randomly
		return DROP
	}

	pkt := pb.pkt[pb.data:pb.tail]

	pktlen := len(pkt)

	if pktlen < V1_HDR_LEN+V1_HOST_DATA_SOURCE {
		log.err("mb: mc host data pkt: len(%v) too short, dropping", pktlen)
		return DROP
	}

	off := V1_HDR_LEN

	// batch id and hash

	batch := be.Uint32(pkt[off+V1_HOST_DATA_BATCHID : off+V1_HOST_DATA_BATCHID+4])
	hash := be.Uint64(pkt[off+V1_HOST_DATA_HASH : off+V1_HOST_DATA_HASH+8])

	off += V1_HOST_DATA_SOURCE

	// extract source

	source, soff, err := mb.parse_source(pkt[off:])

	if err != nil {
		log.err("mb: mc host data pkt: %v, dropping", err)
		return DROP
	}

	off += soff

	wlen := off // length of the ACK pkt to send back

	// prepare SET_AREC packet

	pba := <-getbuf
	pba.write_v1_header(V1_DATA|V1_SET_AREC, 0)

	dnssrc, ok := mb.dnssources[source]
	if !ok {
		dnssrc.source = source
		dnssrc.oid = owners.get_oid(source)
		mb.dnssources[source] = dnssrc
	}
	if dnssrc.hash != hash {
		// new host data
		dnssrc.hash = hash
		dnssrc.recs = make(map[AddrRec]bool)
		dnssrc.mark = marker.now()
		dnssrc.xmark = dnssrc.mark + MAPPER_TMOUT
		mb.dnssources[source] = dnssrc
		mb.save_dnssource(dnssrc)
		// make new records current
		send_marker(dnssrc.mark, dnssrc.oid, dnssrc.source)
	}

	pkta := pba.pkt[pba.data:]
	offa := V1_HDR_LEN

	be.PutUint32(pkta[offa+V1_OID:offa+V1_OID+4], uint32(dnssrc.oid))
	be.PutUint32(pkta[offa+V1_MARK:offa+V1_MARK+4], uint32(dnssrc.mark))

	offa += V1_MARK_LEN

	if len(pkta[offa:]) < len(pkt[off:]) {
		log.fatal("mb: mc host data: agent packet larger than gw packets")
	}

	// extract address mapping

	log.info("source:  %v  hash[%016x]  batch[%08x]", source, hash, batch)

	for ; off <= pktlen-v1_arec_len; off += v1_arec_len {

		arec := AddrRecDecode(ea_iplen, gw_iplen, pkt[off:])

		log.info("   host:  %v + %v -> %v", arec.GW, &arec.Ref, arec.IP)

		copy(pkta[offa:], pkt[off:off+v1_arec_len])
		dnssrc.recs[arec] = true
		offa += v1_arec_len
	}

	if off != pktlen {
		log.err("mb: mc host data pkt: garbage at end of packet")
	}

	// send arec records

	pba.tail = pba.data + offa
	be.PutUint16(pkta[V1_PKTLEN:V1_PKTLEN+2], uint16(offa/4))
	pba.peer = dnssrc.source

	pbb := <-getbuf
	pbb.copy_from(pba)
	pbc := <-getbuf
	pbc.copy_from(pba)

	recv_tun <- pba
	recv_gw <- pbb
	db.recv <- pbc

	// send ACK back

	pkt[V1_CMD] = V1_ACK | (pkt[V1_CMD] & 0x3f)

	pb.tail = pb.data + wlen
	be.PutUint16(pkt[V1_PKTLEN:V1_PKTLEN+2], uint16(wlen/4))
	pb.peer = "mbroker"
	pb.schan <- pb
	return ACCEPT
}

func (mb *MB) mc_host_data_hash(pb *PktBuf) int {

	if cli.devmode && rand.Intn(100) < 7 { // in devmode, drop packets randomly
		return DROP
	}

	pkt := pb.pkt[pb.data:pb.tail]

	pktlen := len(pkt)

	if pktlen < V1_HDR_LEN+V1_HOST_DATA_SOURCE {
		log.err("mb: mc host data hash pkt: len(%v) too short, dropping", pktlen)
		return DROP
	}

	off := V1_HDR_LEN

	// count and hash

	count := be.Uint32(pkt[off+V1_HOST_DATA_COUNT : off+V1_HOST_DATA_COUNT+4])
	hash := be.Uint64(pkt[off+V1_HOST_DATA_HASH : off+V1_HOST_DATA_HASH+8])

	off += V1_HOST_DATA_SOURCE

	// extract source

	source, _, err := mb.parse_source(pkt[off:])

	if err != nil {
		log.err("mb: mc host data hash pkt: %v, dropping", err)
		return DROP
	}

	log.info("hash:  %v  hash(%v)[%016x]", source, count, hash)

	// send response

	pkt[V1_CMD] = V1_NACK | (pkt[V1_CMD] & 0x3f)

	dnssrc, ok := mb.dnssources[source]
	if ok {
		if dnssrc.hash == hash && len(dnssrc.recs) == int(count) {
			// everything matches, bump up expiration
			dnssrc.xmark = marker.now() + MAPPER_TMOUT
			mb.dnssources[source] = dnssrc
			mb.save_dnssource(dnssrc)
			pkt[V1_CMD] = V1_ACK | (pkt[V1_CMD] & 0x3f) // send ACK
		} else {
			// no match, start over, set xmark to expire on next expiration tick
			dnssrc.xmark = marker.now()
			mb.dnssources[source] = dnssrc
			mb.save_dnssource(dnssrc)
		}
	}

	if cli.devmode && rand.Intn(100) < 3 {
		pkt[V1_CMD] = V1_NACK | (pkt[V1_CMD] & 0x3f) // in devmode, send NACK randomly
		log.info("hash mismatch(devmode):  %v  hash(%v)[%016x], request RESEND", source, count, hash)
	}

	pb.peer = "mbroker"
	pb.schan <- pb
	return ACCEPT
}

func (mb *MB) receive() {

	for pb := range mb.recv {

		pkt := pb.pkt[pb.data:pb.tail]

		if err := pb.validate_v1_header(len(pkt)); err != nil {

			log.err("mb: invalid v1 packet from %v:  %v", pb.peer, err)
			retbuf <- pb
			continue
		}

		if cli.ticks || pkt[V1_CMD]&0x3f != V1_SET_MARK {
			log.debug("mb: in from %v: %v", pb.peer, pb.pp_pkt())
		}
		if cli.trace {
			pb.pp_raw("mbroker in:  ")
		}

		verdict := DROP

		switch pkt[V1_CMD] {

		case V1_NOOP:

		case V1_DATA | V1_SET_MARK:

			verdict = mb.set_mark(pb)

		case V1_ACK | V1_GET_EA, V1_NACK | V1_GET_EA:

			verdict = mb.get_ea(pb)

		case V1_REQ | V1_MC_GET_EA:

			verdict = mb.mc_get_ea(pb)

		case V1_REQ | V1_MC_HOST_DATA:

			verdict = mb.mc_host_data(pb)

		case V1_REQ | V1_MC_HOST_DATA_HASH:

			verdict = mb.mc_host_data_hash(pb)

		default:
			log.err("mb: unknown pkt type[%02x]", pkt[V1_CMD])
		}

		if verdict == DROP {
			retbuf <- pb
		}
	}
}

func (mb *MB) connect_recv(inst uint, conn *net.UnixConn, schan chan<- *PktBuf) {

	peer := "unix[" + conn.RemoteAddr().String() + "]"
	log.info("mbroker recv[%v] instance(%v) starting", peer, inst)

	for pb := range getbuf {

		rlen, err := conn.Read(pb.pkt[pb.data:])
		if err != nil {
			log.err("mbroker recv[%v] instance(%v) io error: %v", peer, inst, err)
			conn.Close()
			pb.write_v1_header(V1_NOOP, 0)
			pb.peer = peer
			schan <- pb // force send which will cause connect_send to exit
			break
		}

		// check if packet is sane

		if rlen < MIN_PKT_LEN {
			log.err("mbroker recv[%v] instance(%v): pkt  length(%v) to short", peer, inst, rlen)
			retbuf <- pb
			continue
		}
		if rlen&0x3 != 0 {
			log.err("mbroker recv[%v] instance(%v): pkt length(%v) not on word boundary", peer, inst, rlen)
			retbuf <- pb
			continue
		}

		// send to mbroker

		pb.tail = pb.data + rlen
		pb.peer = peer
		pb.schan = schan
		mb.recv <- pb
	}

	log.info("mbroker recv[%v] instance(%v) exiting", peer, inst)
}

func (mb *MB) connect_send(inst uint, conn *net.UnixConn, schan <-chan *PktBuf) {

	peer := "unix[" + conn.RemoteAddr().String() + "]"
	log.info("mbroker send[%v] instance(%v) starting", peer, inst)

	for pb := range schan {

		//log.info("mbroker send[%v] instance(%v) sending: [%02x]", peer, inst, pb.pkt[pb.data+V1_CMD])

		_, err := conn.Write(pb.pkt[pb.data:pb.tail])

		retbuf <- pb

		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				log.err("mbroker send[%v] instance(%v) io error: %v", peer, inst, err)
			}
			conn.Close() // force connect_recv to exit
			break
		}
	}

	log.info("mbroker send[%v] instance(%v) exiting", peer, inst)
}

func (mb *MB) connect() {

	log.info("mbroker opening socket: %v", cli.sockname)

	os.MkdirAll(path.Dir(cli.sockname), 0775)
	os.Remove(cli.sockname)
	agent, err := net.ListenUnix("unixpacket", &net.UnixAddr{cli.sockname, "unixpacket"})
	if err != nil {
		goexit <- err.Error()
		return
	}
	os.Chmod(cli.sockname, 0660)

	for inst := uint(1); ; inst++ {
		conn, err := agent.AcceptUnix()
		if err != nil {
			log.err("mbroker connection accept error: %v, ignoring", err)
		} else {
			// In go, io is always blocking. To unstuck a go routine, we
			// close conn on io errors which will generate an error causing
			// both go routines to exit. We also need to force a send on
			// the sending go routine so that it can error out.
			schan := make(chan *PktBuf, PKTQLEN)
			go mb.connect_recv(inst, conn, schan)
			go mb.connect_send(inst, conn, schan)
		}
	}
}

func (mb *MB) start() {

	go mb.connect()
}

func (mb *MB) init() {

	// ipref plugin

	mb.eaq = make(map[uint16]Eaq)
	mb.eacache = make(map[IpRef]IpRec)
	mb.cur_mark = make([]M32, int(mapper_oid)+1)

	// dns sources

	mb.dnssources = make(map[string]DnsSrc)

	// base

	mb.recv = make(chan *PktBuf, PKTQLEN)

	go mb.receive()
}
