/* Copyright (c) 2018 Waldemar Augustyn */

package main

import (
	"crypto/rand"
	prng "math/rand" // we don't need crypto rng for time delays
	"time"
)

const (
	TIMER_TICK = 16811           // [ms] avg  16.811 [s]
	TIMER_FUZZ = TIMER_TICK / 7  // [ms]       2.401 [s]
	PURGE_TICK = TIMER_TICK / 11 // [ms] avg   1.528 [s]
	PURGE_FUZZ = PURGE_TICK / 7  // [ms]       0.218 [s]
	PURGE_NUM  = 17              // num of records to purge at a time
)

type Mark struct {
	base time.Time
}

var marker Mark

func (m *Mark) init() {

	// init prng for non-critical random number use

	creep := make([]byte, 4)
	_, err := rand.Read(creep)
	if err != nil {
		log.fatal("mark: cannot seed pseudo random number generator")
	}
	prng.Seed(int64(be.Uint32(creep)))

	// init marker making sure it's always > 0

	m.base = time.Now().Add(-time.Second)
}

func (m *Mark) now() M32 {

	return M32(time.Now().Sub(m.base) / time.Second)

}

func get_timer_packet(cmd byte, mark M32) *PktBuf {

	pb := <-getbuf

	pb.set_v1hdr()
	pb.write_v1_header(V1_SIG, cmd, mapper_oid, mark)

	pb.tail = pb.v1hdr + V1_HDR_LEN

	return pb
}

func purge_tick() {

	for {
		time.Sleep(time.Duration(PURGE_TICK-PURGE_FUZZ/2+prng.Intn(PURGE_FUZZ)) * time.Millisecond)

		pb := get_timer_packet(V1_PURGE, 0)
		pbb := <-getbuf
		pbb.copy_from(pb)

		recv_gw <- pb
		recv_tun <- pbb
	}
}

func timer_tick() {

	for {
		time.Sleep(time.Duration(TIMER_TICK-TIMER_FUZZ/2+prng.Intn(TIMER_FUZZ)) * time.Millisecond)

		mark := marker.now() // the same mark for both timers

		pb := get_timer_packet(V1_SET_MARK, mark)
		pbb := <-getbuf
		pbb.copy_from(pb)

		recv_gw <- pb
		recv_tun <- pbb
	}
}
