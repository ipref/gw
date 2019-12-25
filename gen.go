/* Copyright (c) 2018 Waldemar Augustyn */

package main

import (
	"crypto/rand"
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

// create new oid
func (o *Owners) new_oid(name string) O32 {

	if len(name) == 0 {
		log.fatal("owners: missing owner name")
	}

	o.mtx.Lock()
	oid := O32(len(o.oids))
	o.oids = append(o.oids, name)
	o.mtx.Unlock()
	log.debug("owners: new oid: %v(%v)", name, oid)
	return oid
}

var owners Owners

var random_dns_ref chan Ref
var random_mapper_ref chan Ref

var random_dns_ea chan IP32
var random_mapper_ea chan IP32

// generate random refs with second to last byte < SECOND_BYTE
func gen_dns_refs() {

	var ref Ref
	refzero := Ref{0, 0}
	allocated := make(map[Ref]bool)
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
			ref.h = be.Uint64(creep[:8])
			ref.l = be.Uint64(creep[8:])

			if ref.h == 0 && ref.l < MIN_REF {
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

	var ref Ref
	refzero := Ref{0, 0}
	allocated := make(map[Ref]bool)
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
			ref.h = be.Uint64(creep[:8])
			ref.l = be.Uint64(creep[8:])

			if ref.h == 0 && ref.l < MIN_REF {
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

// generate random eas with second to last byte < SECOND_BYTE
func gen_dns_eas() {

	var ea IP32
	allocated := make(map[IP32]bool)
	bcast := 0xffffffff &^ cli.ea_mask
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
			if ea == 0 || ea == bcast {
				continue // zero address or broadcast address, try another
			}
			ea |= cli.ea_ip
			_, ok := allocated[ea]
			if ok {
				continue // already allocated
			}
			allocated[ea] = true
			break
		}
		random_dns_ea <- ea
	}
}

// generate random eas with second to last byte >= SECOND_BYTE
func gen_mapper_eas() {

	var ea IP32
	allocated := make(map[IP32]bool)
	bcast := 0xffffffff &^ cli.ea_mask
	creep := make([]byte, 4)
	var err error

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
			if ea == 0 || ea == bcast {
				continue // zero address or broadcast address, try another
			}
			ea |= cli.ea_ip
			_, ok := allocated[ea]
			if ok {
				continue // already allocated
			}
			allocated[ea] = true
			break
		}
		random_mapper_ea <- ea
	}
}
