/* Copyright (c) 2018 Waldemar Augustyn */

package main

import (
	"crypto/rand"
	prng "math/rand" // we don't need crypto rng for time delays
	"sync"
	"time"
)

const (
	TIMER_IVL      = 16789 // [ms] avg 17.961 [s]
	TIMER_FUZZ     = 2345  // [ms]
	FWD_TIMER_IVL  = 1234  // [ms] avg  1.851 [s]
	FWD_TIMER_FUZZ = 1234  // [ms]
)

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

func (m *Mark) now() M32 {

	return M32(time.Now().Sub(m.base) / time.Second)

}

var marker Mark

var mgw_timer_done chan bool
var mtun_timer_done chan bool
var timer_wg sync.WaitGroup

func get_timer_packet(cmd byte, mark M32) *PktBuf {

	pb := <-getbuf

	pb.set_v1hdr()
	pb.write_v1_header(V1_SIG, cmd, mapper_oid, mark)

	pb.tail = pb.v1hdr + V1_HDR_LEN

	return pb
}

func mgw_timer(mark M32) {

	// set time mark...

	pb := get_timer_packet(V1_SET_MARK, mark)
	recv_tun <- pb

	// ...then purge expired records

	for {
		select {
		case _ = <-mgw_timer_done:
			timer_wg.Done()
			return
		default:
			pb := get_timer_packet(V1_PURGE, 0)
			recv_tun <- pb
			time.Sleep(time.Duration(FWD_TIMER_IVL+prng.Intn(FWD_TIMER_FUZZ)) * time.Millisecond)
		}
	}
}

func mtun_timer(mark M32) {

	// set time mark...

	pb := get_timer_packet(V1_SET_MARK, mark)
	recv_gw <- pb

	// ...then purge expired records

	for {
		select {
		case _ = <-mtun_timer_done:
			timer_wg.Done()
			return
		default:
			pb := get_timer_packet(V1_PURGE, 0)
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

		mark := marker.now() // the same mark for both timers

		log.debug("tmr: starting purge run, mark: %v", mark)
		timer_wg.Add(2)
		go mgw_timer(mark)
		go mtun_timer(mark)
		timer_wg.Wait()
		log.debug("tmr: finished purge run, mark: %v", mark)
	}
}
