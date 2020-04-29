/* Copyright (c) 2018-2020 Waldemar Augustyn */

package main

import (
	"crypto/rand"
	"modernc.org/b"
	"sync"
)

type GenEA struct {
	allocated *b.Tree
	mtx       sync.Mutex
	bcast     IP32
}

var gen_ea GenEA

var recover_ea chan *PktBuf
var random_dns_ea chan IP32
var random_mapper_ea chan IP32

// try to recover allocated eas if expired
func (gea *GenEA) check_for_expired() {
}

// listen to messages sent in response to queries for expired eas
func (gea *GenEA) recover_expired() {
}

// generate random eas with second to last byte < SECOND_BYTE
func (gea *GenEA) gen_dns_eas() {
	/*
		var ea IP32
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
				if ea == 0 || ea == gea.bcast {
					continue // zero address or broadcast address, try another
				}
				ea |= cli.ea_ip
				_, ok := gea.allocated[ea]
				if ok {
					continue // already allocated
				}
				gea.allocated[ea] = true
				break
			}
			random_dns_ea <- ea
		}
	*/
}

// generate random eas with second to last byte >= SECOND_BYTE
func (gea *GenEA) gen_mapper_eas() {

	var ea IP32
	creep := make([]byte, 4)
	var err error
	var added bool

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
			if ea == 0 || ea == gea.bcast {
				continue // zero address or broadcast address, try another
			}

			ea |= cli.ea_ip

			gea.mtx.Lock()

			_, added = gea.allocated.Put(ea, func(old interface{}, exists bool) (interface{}, bool) {
				return M32(0), !exists
			})

			gea.mtx.Unlock()

			if added {
				break // allocated new ea
			}
		}
		random_mapper_ea <- ea
	}
}

func (gea *GenEA) start() {

	go gea.gen_dns_eas()
	go gea.gen_mapper_eas()
	go gea.check_for_expired()
	go gea.recover_expired()
}

func (gea *GenEA) init() {
	gea.bcast = 0xffffffff &^ cli.ea_mask
	gea.allocated = b.TreeNew(b.Cmp(addr_cmp))
	recover_ea = make(chan *PktBuf, PKTQLEN)
	random_dns_ea = make(chan IP32, GENQLEN)
	random_mapper_ea = make(chan IP32, GENQLEN)
	db_restore_eas(gea)
}
