/* Copyright (c) 2018 Waldemar Augustyn */

package main

import (
	"crypto/rand"
	"strings"
	"sync"
	"time"
)

/* Address and reference allocation

Local network encoded addresses and references may be allocated by the mapper
or by a local DNS server. To avoid conflicts, meadow implementation imposes
a rule where the second to last byte of an allocated IP address or the second
to last byte of an allocated reference must be 100 or higher if allocated
by the mapper and it must be less than 100 if allocated by DNS server or
listed in /etc/hosts.
*/

const (
	GENQLEN     = 2
	SECOND_BYTE = 100
	MIN_REF     = 256 // low ref values are reserved
)

const (
	MAPPER_TMOUT   = 1800                          // [s] mapper record timeout
	MAPPER_REFRESH = MAPPER_TMOUT - MAPPER_TMOUT/4 // [s] when to refresh
	MAPPER_TICK    = 4567                          // [ms] timer tick
)

type Owners struct {
	oids []string
	mtx  sync.Mutex
}

func (o *Owners) init() {
	o.oids = make([]string, 1, 16)
	o.oids[0] = "none"
}

func (o *Owners) name(oid uint32) string {
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

func (o *Owners) new_oid(name string) uint32 {

	if len(name) == 0 {
		log.fatal("owners: missing owner name")
	}

	o.mtx.Lock()
	oid := uint32(len(o.oids))
	o.oids = append(o.oids, name)
	o.mtx.Unlock()
	log.debug("owners: new oid: %v(%v)", name, oid)
	return oid
}

type Mark struct {
	base time.Time
}

func (m *Mark) init() {

	m.base = time.Now().Add(-time.Second) // make sure marker.now() is always > 0
}

func (m *Mark) now() uint32 {

	return uint32(time.Now().Sub(m.base) / time.Second)

}

var marker Mark
var owners Owners

var random_dns_ref chan Ref
var random_mapper_ref chan Ref

var random_dns_ea chan IP32
var random_mapper_ea chan IP32

// generate random refs with second to last byte < SECOND_BYTE
func gen_dns_refs() {

	allocated := make(map[Ref]bool)

	var err error
	ref := Ref{0, 0}
	low := make([]byte, 8)

	for {

		_, err = rand.Read(low)
		if err != nil {
			log.fatal("gen_dns_refs: cannot get random number")
		}

		low[6] %= 100
		ref.l = be.Uint64(low)
		if ref.h == 0 && ref.l < MIN_REF {
			continue // restricted value, try another
		}
		_, ok := allocated[ref]
		if ok {
			continue // already allocated
		}
		allocated[ref] = true

		random_dns_ref <- ref
	}
}

// generate random refs with second to last byte >= SECOND_BYTE
func gen_mapper_refs() {

	allocated := make(map[Ref]bool)

	var err error
	ref := Ref{0, 0}
	low := make([]byte, 8)

	for {

		_, err = rand.Read(low)
		if err != nil {
			log.fatal("gen_mapper_refs: cannot get random number")
		}

		low[6] %= 156
		low[6] += 100
		ref.l = be.Uint64(low)
		_, ok := allocated[ref]
		if ok {
			continue // already allocated
		}
		allocated[ref] = true

		random_mapper_ref <- ref
	}
}

// generate random eas with second to last byte < SECOND_BYTE
func gen_dns_eas() {

	allocated := make(map[IP32]bool)

	var err error
	var ea IP32
	bcast := 0xffffffff &^ cli.ea_mask
	ea_bytes := make([]byte, 4)

	for {

		_, err = rand.Read(ea_bytes)
		if err != nil {
			log.fatal("gen_dns_eas: cannot get random number")
		}

		ea_bytes[2] %= 100
		ea = IP32(be.Uint32(ea_bytes))
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

		random_dns_ea <- ea
	}
}

// generate random eas with second to last byte >= SECOND_BYTE
func gen_mapper_eas() {

	allocated := make(map[IP32]bool)

	var err error
	var ea IP32
	bcast := 0xffffffff &^ cli.ea_mask
	ea_bytes := make([]byte, 4)

	for {

		_, err = rand.Read(ea_bytes)
		if err != nil {
			log.fatal("gen_mapper_eas: cannot get random number")
		}

		ea_bytes[2] %= 156
		ea_bytes[2] += 100
		ea = IP32(be.Uint32(ea_bytes))
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

		random_mapper_ea <- ea
	}
}

func timer() {

	ticker := time.Tick(MAPPER_TICK * time.Millisecond)

	for _ = range ticker {
		// nothing for now
	}
}
