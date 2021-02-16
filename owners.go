/* Copyright (c) 2018-2021 Waldemar Augustyn */

package main

import (
	"fmt"
	"sync"
)

type Owners struct {
	oids []string
	mtx  sync.Mutex
}

var owners Owners
var mapper_oid O32
var arp_oid O32

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
	return name
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
	if err := o.register(oid, name); err != nil {
		log.fatal("%v", err)
	}
	o.mtx.Unlock()

	return oid
}

// register oid (internal function)
func (o *Owners) register(oid O32, name string) error {

	// caller must acquire o.mtx before calling this function

	if oid < 1 || len(name) == 0 {
		return fmt.Errorf("owners: attempting to register an invalid oid: %v(%v)", name, oid)
	}

	if int(oid) >= len(o.oids) {
		o.oids = append(o.oids, make([]string, int(oid)-len(o.oids)+1)...)
	}

	if o.oids[oid] == name {
		return fmt.Errorf("owners: attempting to register a duplicate oid name: %v(%v)", name, oid)
	}

	if o.oids[oid] != "" {
		return fmt.Errorf("owners: attempting to register a duplicate oid: %v(%v)", name, oid)
	}

	o.oids[oid] = name

	log.info("owners: registering new oid: %v(%v)", name, oid)

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
	db.recv <- pb

	return nil
}
