/* Copyright (c) 2018 Waldemar Augustyn */

package main

import (
	"crypto/rand"
	prng "math/rand"
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
	MAXTRIES    = 10  // num of tries to get unique random value before giving up
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

// return name associated with an oid
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

// create new oid
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

	// init prng for non-critical random number use

	creep := make([]byte, 4)
	_, err := rand.Read(creep)
	if err != nil {
		log.fatal("tmr: cannot seed pseudo random number generator")
	}
	prng.Seed(int64(be.Uint32(creep)))

	// init marker making sure it's always > 0

	m.base = time.Now().Add(-time.Second)
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
		random_dns_ea <- ea
	}
}

// -- timer --------------------------------------------------------------------

const (
	TIMER_IVL      = 16789 // [ms] avg 17.961 [s]
	TIMER_FUZZ     = 2345  // [ms]
	FWD_TIMER_IVL  = 1234  // [ms] avg  1.851 [s]
	FWD_TIMER_FUZZ = 1234  // [ms]
)

var mgw_timer_done chan bool
var mtun_timer_done chan bool
var timer_wg sync.WaitGroup

func get_timer_packet(mark uint32) *PktBuf {

	pb := <-getbuf

	pb.set_v1hdr()
	pb.write_v1_header(V1_SIG, V1_PURGE_EXPIRED, 0, mark)

	pb.tail = pb.v1hdr + V1_HDR_LEN

	return pb
}

func mgw_timer(mark uint32) {

	for {
		select {
		case _ = <-mgw_timer_done:
			timer_wg.Done()
			return
		default:
			pb := get_timer_packet(mark)
			recv_tun <- pb
			time.Sleep(time.Duration(FWD_TIMER_IVL+prng.Intn(FWD_TIMER_FUZZ)) * time.Millisecond)
		}
	}
}

func mtun_timer(mark uint32) {

	for {
		select {
		case _ = <-mtun_timer_done:
			timer_wg.Done()
			return
		default:
			pb := get_timer_packet(mark)
			recv_gw <- pb
			time.Sleep(time.Duration(FWD_TIMER_IVL+prng.Intn(FWD_TIMER_FUZZ)) * time.Millisecond)
		}
	}
}

func timer() {

	mgw_timer_done = make(chan bool)
	mtun_timer_done = make(chan bool)

	for {
		time.Sleep(time.Duration(TIMER_IVL+prng.Intn(TIMER_FUZZ)) * time.Millisecond)

		mark := marker.now()

		log.debug("tmr: starting purge run, mark: %v", mark)
		timer_wg.Add(2)
		go mgw_timer(mark)
		go mtun_timer(mark)
		timer_wg.Wait()
		log.debug("tmr: finished purge run, mark: %v", mark)
	}
}
