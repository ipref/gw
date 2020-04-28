/* Copyright (c) 2018-2020 Waldemar Augustyn */

package main

import (
	"crypto/rand"
	"strings"
	"sync"
)


var random_dns_ea chan IP32
var random_mapper_ea chan IP32

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
