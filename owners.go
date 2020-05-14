/* Copyright (c) 2018-2020 Waldemar Augustyn */

package main

import (
	"strings"
	"sync"
)

type Owners struct {
	oids []string
	mtx  sync.Mutex
}

var owners Owners

func (o *Owners) init() {
	o.oids = make([]string, 1, 16)
	o.oids[0] = "none"
}

// return name associated with an oid
func (o *Owners) name(oid O32) string {
	name := "unknown"
	o.mtx.Lock()
	if int(oid) < len(o.oids) {
		name = o.oids[oid]
	}
	o.mtx.Unlock()
	ix := strings.LastIndex(name, "/")
	if ix < 0 {
		return name
	}
	return name[ix+1:]
}

// get oid, create if necessary
func (o *Owners) get_oid(name string) O32 {

	if len(name) == 0 {
		log.fatal("owners: missing owner name")
	}
	if len(name) > 255 {
		log.fatal("owners: name too long: %v", name)
	}

	o.mtx.Lock()
	for ix, oname := range o.oids {
		if oname == name {
			o.mtx.Unlock()
			return O32(ix)
		}
	}

	oid := O32(len(o.oids))
	o.oids = append(o.oids, name)
	o.mtx.Unlock()

	log.debug("owners: new oid: %v(%v)", name, oid)

	// send to db

	pb := <-getbuf
	pb.write_v1_header(V1_SAVE_OID, 0)
	pkt := pb.pkt[pb.iphdr:]

	off := V1_HDR_LEN
	be.PutUint32(pkt[off:off+4], uint32(oid))

	off += 4
	pkt[off] = V1_TYPE_STRING
	pkt[off+1] = byte(len(name))
	copy(pkt[off+2:], name)

	off += (len(name) + 5) &^ 3
	pb.tail = pb.iphdr + off
	be.PutUint16(pkt[V1_PKTLEN:V1_PKTLEN+2], uint16(off/4))

	pb.peer = "owners"
	dbchan <- pb

	return oid
}
