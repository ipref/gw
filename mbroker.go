/* Copyright (c) 2018-2021 Waldemar Augustyn */

package main

import (
	"bytes"
	"io"
	"net"
	"os"
	"path"
	"time"
)

const (
	GET_EA_WAIT = 359 * time.Millisecond // we love prime numbers
)

type Eaq struct {
	pb   *PktBuf
	wait *time.Timer
}

type MbData struct {
	cur_mark []M32
	eacache  map[IpRef]IpRec
	eaq      map[uint16]Eaq
}

var mbchan chan *PktBuf
var mb MbData

// send NACK after wait time expires
func mb_wait(cmd byte, pktid uint16) {

	pb := <-getbuf
	pb.write_v1_header(V1_NACK|cmd, pktid)
	pb.tail = pb.iphdr + V1_HDR_LEN
	be.PutUint16(pb.pkt[V1_PKTLEN:V1_PKTLEN+2], V1_HDR_LEN/4)
	pb.peer = "mb_wait"
	mbchan <- pb
}

// get ea response from forwarders
func mb_get_ea(rpb *PktBuf) int {

	rpkt := rpb.pkt[rpb.iphdr:rpb.tail]

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

		if len(rpkt) < V1_HDR_LEN+V1_MARK_LEN+V1_AREC_LEN {
			log.err("mb: get ea response pkt pktid[%04x]: len(%v) too short, dropping", pktid, len(rpkt))
			retbuf <- pb
			return DROP // rpb
		}

		off := V1_HDR_LEN                // offset to arec in originator's packet
		roff := V1_HDR_LEN + V1_MARK_LEN // offset to arec in response

		if !bytes.Equal(pkt[off+V1_AREC_IP:off+V1_AREC_IP+24], rpkt[roff+V1_AREC_IP:roff+V1_AREC_IP+24]) {
			log.err("mb: get ea response pkt pktid[%04x]: request/response mismatch, dropping", pktid)
			retbuf <- pb
			return DROP // rpb
		}

		var ipr IpRef

		ipr.ip = IP32(be.Uint32(pkt[off+V1_AREC_GW : off+V1_AREC_GW+4]))
		ipr.ref.H = be.Uint64(pkt[off+V1_AREC_REFH : off+V1_AREC_REFH+8])
		ipr.ref.L = be.Uint64(pkt[off+V1_AREC_REFL : off+V1_AREC_REFL+8])

		var iprec IpRec

		roff = V1_HDR_LEN
		iprec.oid = O32(be.Uint32(rpkt[roff+V1_OID : roff+V1_OID+4]))
		iprec.mark = M32(be.Uint32(rpkt[roff+V1_MARK : roff+V1_MARK+4]))
		roff += V1_MARK_LEN
		iprec.ip = IP32(be.Uint32(rpkt[roff+V1_AREC_EA : roff+V1_AREC_EA+4]))

		mb.eacache[ipr] = iprec

		copy(pkt[off+V1_AREC_EA:off+V1_AREC_EA+4], rpkt[roff+V1_AREC_EA:roff+V1_AREC_EA+4])
		pkt[V1_CMD] = V1_ACK | V1_MC_GET_EA
		pb.tail = pb.iphdr + V1_HDR_LEN + V1_AREC_LEN

	case V1_NACK | V1_GET_EA:

		pkt[V1_CMD] = V1_NACK | V1_MC_GET_EA
		pb.tail = pb.iphdr + V1_HDR_LEN

	default:
		log.err("mb: get ea pkt: not a response [%02x], dropping", pkt[V1_CMD])
		retbuf <- pb
		return DROP // rpb
	}

	be.PutUint16(pkt[V1_PKTLEN:V1_PKTLEN+2], uint16((pb.tail-pb.iphdr)/4))
	log.debug("mb: out to  %v: %v\n", pb.peer, pb.pp_pkt())
	if cli.trace {
		pb.pp_raw("mbroker out: ")
	}
	pb.schan <- pb
	return DROP // rpb
}

// mc get ea request from ipref plugin
func mb_mc_get_ea(pb *PktBuf) int {

	pkt := pb.pkt[pb.iphdr:pb.tail]

	if len(pkt) < V1_HDR_LEN+V1_AREC_LEN {
		log.err("mb: mc get ea pkt: len(%v) too short, dropping", len(pkt))
		return DROP
	}

	if pkt[V1_CMD] != V1_REQ|V1_MC_GET_EA {
		log.err("mb: mc get ea pkt: non REQ mode [%02x], dropping", pkt[V1_CMD])
		return DROP
	}

	off := V1_HDR_LEN

	var ipr IpRef

	ipr.ip = IP32(be.Uint32(pkt[off+V1_AREC_GW : off+V1_AREC_GW+4]))
	ipr.ref.H = be.Uint64(pkt[off+V1_AREC_REFH : off+V1_AREC_REFH+8])
	ipr.ref.L = be.Uint64(pkt[off+V1_AREC_REFL : off+V1_AREC_REFL+8])

	// return the ea if found in cache...

	iprec, ok := mb.eacache[ipr]

	if ok {
		if iprec.mark < mb.cur_mark[mapper_oid] {
			delete(mb.eacache, ipr) // expired
		} else {

			// found it

			off := V1_HDR_LEN
			wlen := V1_HDR_LEN + V1_AREC_LEN

			pkt[V1_CMD] = V1_ACK | V1_MC_GET_EA
			be.PutUint32(pkt[off+V1_AREC_EA:off+V1_AREC_EA+4], uint32(iprec.ip))
			be.PutUint16(pkt[V1_PKTLEN:V1_PKTLEN+2], uint16((wlen / 4)))
			pb.tail = pb.iphdr + wlen

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
	rpkt := rpb.pkt[rpb.iphdr:]

	off = V1_HDR_LEN

	be.PutUint32(rpkt[off+V1_OID:off+V1_OID+4], uint32(mapper_oid))
	copy(rpkt[off+V1_MARK:off+V1_MARK+4], []byte{0, 0, 0, 0})

	off += V1_MARK_LEN

	copy(rpkt[off:off+V1_AREC_LEN], pkt[V1_HDR_LEN:V1_HDR_LEN+V1_AREC_LEN])

	// don't wait too long

	wait := time.AfterFunc(GET_EA_WAIT, func() { mb_wait(V1_GET_EA, pktid) })
	mb.eaq[pktid] = Eaq{pb, wait}

	// send to fwd_to_tun

	rpb.tail = rpb.iphdr + V1_HDR_LEN + V1_MARK_LEN + V1_AREC_LEN
	be.PutUint16(rpkt[V1_PKTLEN:V1_PKTLEN+2], (V1_HDR_LEN+V1_MARK_LEN+V1_AREC_LEN)/4)
	rpb.peer = "mbroker"
	rpb.schan = mbchan
	recv_gw <- rpb
	return ACCEPT
}

func mb_set_mark(pb *PktBuf) int {

	pkt := pb.pkt[pb.iphdr:pb.tail]

	if len(pkt) < V1_HDR_LEN+V1_MARK_LEN {
		log.err("mb: set mark pkt: len(%v) too short, dropping", len(pkt))
		return DROP
	}

	if pkt[V1_CMD] != V1_SET_MARK {
		log.err("mb: set mark pkt: non DATA mode [%02x], dropping", pkt[V1_CMD])
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

func mbroker() {

	mb.eaq = make(map[uint16]Eaq)
	mb.eacache = make(map[IpRef]IpRec)
	mb.cur_mark = make([]M32, int(mapper_oid)+1)

	for pb := range mbchan {

		pkt := pb.pkt[pb.iphdr:pb.tail]

		if err := pb.validate_v1_header(len(pkt)); err != nil {

			log.err("mb: invalid v1 packet from %v:  %v", pb.peer, err)
			retbuf <- pb
			continue
		}

		cmd := pkt[V1_CMD] & 0x3f

		if cli.ticks || cmd != V1_SET_MARK {
			log.debug("mb: in from %v: %v", pb.peer, pb.pp_pkt())
		}
		if cli.trace {
			pb.pp_raw("mbroker in:  ")
		}

		var verdict int

		switch cmd {

		case V1_NOOP:
			verdict = DROP
		case V1_SET_MARK:
			verdict = mb_set_mark(pb)
		case V1_GET_EA:
			verdict = mb_get_ea(pb)
		case V1_MC_GET_EA:
			verdict = mb_mc_get_ea(pb)
		default: // invalid
			log.err("mb: invalid v1 cmd: %v", cmd)
			verdict = DROP
		}

		if verdict == DROP {
			retbuf <- pb
		}
	}
}

func mbroker_recv(conn *net.UnixConn, schan chan<- *PktBuf) {

	peer := "unix[" + conn.RemoteAddr().String() + "]"
	log.info("mbroker recv[%v] starting", peer)

	for pb := range getbuf {

		rlen, err := conn.Read(pb.pkt[pb.iphdr:])
		if err != nil {
			log.err("mbroker recv[%v] io error: %v", peer, err)
			conn.Close()
			pb.write_v1_header(V1_NOOP, 0)
			pb.peer = peer
			schan <- pb // force send which will cause mbroker_send to exit
			break
		}

		// check if packet is sane

		if rlen < MIN_PKT_LEN {
			log.err("mbroker recv[%v]: pkt  length(%v) to short", peer, rlen)
			retbuf <- pb
			continue
		}
		if rlen&0x3 != 0 {
			log.err("mbroker recv[%v]: pkt length(%v) not on word boundary", peer, rlen)
			retbuf <- pb
			continue
		}

		// send to mbroker

		pb.tail = pb.iphdr + rlen
		pb.peer = peer
		pb.schan = schan
		mbchan <- pb
	}

	log.info("mbroker recv[%v] exiting", peer)
}

func mbroker_send(conn *net.UnixConn, schan <-chan *PktBuf) {

	peer := "unix[" + conn.RemoteAddr().String() + "]"
	log.info("mbroker send[%v] starting", peer)

	for pb := range schan {

		_, err := conn.Write(pb.pkt[pb.iphdr:pb.tail])

		retbuf <- pb

		if err != nil && err != io.EOF {
			log.err("mbroker send[%v] io error: %v", peer, err)
			conn.Close() // force mbroker_recv to exit
			break
		}
	}

	log.info("mbroker send[%v] exiting", peer)
}

func mbroker_conn() {

	log.info("mbroker opening socket: %v", cli.sockname)

	os.MkdirAll(path.Dir(cli.sockname), 0775)
	os.Remove(cli.sockname)
	agent, err := net.ListenUnix("unixpacket", &net.UnixAddr{cli.sockname, "unixpacket"})
	if err != nil {
		goexit <- err.Error()
		return
	}
	os.Chmod(cli.sockname, 0660)

	for {
		conn, err := agent.AcceptUnix()
		if err != nil {
			log.err("mbroker connection accept error: %v, ignoring", err)
		} else {
			// In go, io is always blocking. To unstuck a go routine, we
			// close conn on io errors which will generate an error causing
			// both go routines to exit. We also need to force a send on
			// the sending go routine so that it can error out.
			schan := make(chan *PktBuf, PKTQLEN)
			go mbroker_recv(conn, schan)
			go mbroker_send(conn, schan)
		}
	}
}
