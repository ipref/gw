/* Copyright (c) 2018-2020 Waldemar Augustyn */

package main

import (
	"crypto/rand"
	rff "github.com/ipref/ref"
	"strings"
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
)

type Owners struct {
	oids []string
	mtx  sync.Mutex
}

func (o *Owners) init() {
	o.oids = make([]string, 1, 16)
	o.oids[0] = "none"
	db_restore_owners(o)
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

var owners Owners

var random_dns_ref chan rff.Ref
var random_mapper_ref chan rff.Ref

// generate random refs with second to last byte < SECOND_BYTE
func gen_dns_refs() {

	var ref rff.Ref
	refzero := rff.Ref{0, 0}
	allocated := make(map[rff.Ref]bool)
	creep := make([]byte, 16)
	var err error

	for {
		// clear ref before incrementing ii
		for ii := 0; ii < MAXTRIES; ii, ref = ii+1, refzero {

			_, err = rand.Read(creep[7:])
			if err != nil {
				continue // cannot get random number
			}

			creep[14] %= SECOND_BYTE
			creep[7] >>= 4 // make 64 bit refs happen more often
			ref.H = be.Uint64(creep[:8])
			ref.L = be.Uint64(creep[8:])

			if ref.H == 0 && ref.L < MIN_REF {
				continue // reserved ref
			}

			_, ok := allocated[ref]
			if ok {
				continue // already allocated
			}

			allocated[ref] = true
			break
		}
		random_dns_ref <- ref
	}
}

// generate random refs with second to last byte >= SECOND_BYTE
func gen_mapper_refs() {

	var ref rff.Ref
	refzero := rff.Ref{0, 0}
	allocated := make(map[rff.Ref]bool)
	creep := make([]byte, 16)
	var err error

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

			_, ok := allocated[ref]
			if ok {
				continue // already allocated
			}

			allocated[ref] = true
			break
		}
		random_mapper_ref <- ref
	}
}
