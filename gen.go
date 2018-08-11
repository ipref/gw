/* Copyright (c) 2018 Waldemar Augustyn */

package main

import (
	"crypto/rand"
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
)

// generate random refs with second to last byte < SECOND_BYTE
func gen_dns_refs() {

	random_dns_ref = make(chan Ref, GENQLEN)

	allocated := make(map[Ref]bool)

	var err error
	ref := Ref{0, 0}
	low := make([]byte, 8)

	for {

		_, err = rand.Read(low)
		if err != nil {
			log.fatal("gen_dns_refs: cannot get random number")
		}

		low[6] = uint8(low[6]) % 100
		ref.l = be.Uint64(low)
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

	random_mapper_ref := make(chan Ref, GENQLEN)

	allocated := make(map[Ref]bool)

	var err error
	ref := Ref{0, 0}
	low := make([]byte, 8)

	for {

		_, err = rand.Read(low)
		if err != nil {
			log.fatal("gen_mapper_refs: cannot get random number")
		}

		low[6] = uint8(low[6])%156 + 100
		ref.l = be.Uint64(low)
		_, ok := allocated[ref]
		if ok {
			continue // already allocated
		}
		allocated[ref] = true

		random_mapper_ref <- ref
	}
}

var random_dns_ref chan Ref
var random_mapper_ref chan Ref

//var random_dns_ea chan uint32
//var random_mapper_ea chan uint32
