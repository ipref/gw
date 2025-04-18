/* Copyright (c) 2018-2021 Waldemar Augustyn */

package main

import (
	"crypto/rand"
	. "github.com/ipref/common"
	prng "math/rand" // we don't need crypto rng for time delays
	"time"
)

/* Markers and owner ids

Every mapper record has a marker and an owner id (oid) associated with it. An
oid is an arbitrary integer identifying the owner of the record.  A marker is
a time value which determines whether a record is active. Each marker has a
corresponding cur_mark value per each oid. A record is active if its mark is
not less than the related cur_mark.

Mapper records that are dynamically created by the forwarders expire after a set
amount of time. This is accomplished by incrementing cur_mark value as time
passes. In this way mark values of dynamic records eventually fall below the
cur_mark values. If a record is used in mapping, its expiration is extended,
ie. its mark is incremented. If a record is not used for an extened amount of
time, it expires.

Mapper records that are created by DNS agents also use mark values to determine
their status. Unlike dynamic mapper records, their curr_mark values are not
incremented with time but with successive updates. Each new update carries a new
mark value which is then set as the new curr_mark. In this way, old records are
immediately expired whenever a new set becomes available.
*/

const (
	TIMER_TICK = 16811 // [ms] avg  16.811 [s]
	TIMER_FUZZ = 7
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

}

func (m *Mark) now() M32 {

	return M32(time.Now().Sub(m.base) / time.Second)

}

func sleep(dly /* [ms] */, fuzz /* [ms] */ int) {
	time.Sleep(time.Duration(dly-fuzz/2+prng.Intn(fuzz)) * time.Millisecond)
}

func send_marker(mark M32, oid O32, from string) {

	pb := <-getbuf
	pb.peer = from

	pb.write_v1_header(V1_DATA|V1_SET_MARK, 0)
	pkt := pb.pkt[pb.data:]
	off := V1_HDR_LEN
	be.PutUint32(pkt[off+V1_OID:off+V1_OID+4], uint32(oid))
	be.PutUint32(pkt[off+V1_MARK:off+V1_MARK+4], uint32(mark))
	be.PutUint16(pkt[V1_PKTLEN:V1_PKTLEN+2], uint16((V1_HDR_LEN+V1_MARK_LEN)/4))
	pb.tail = pb.data + V1_HDR_LEN + V1_MARK_LEN

	switch oid {
	case mapper_oid:

		pbb := <-getbuf
		pbb.copy_from(pb)

		pbc := <-getbuf
		pbc.copy_from(pb)

		pbd := <-getbuf
		pbd.copy_from(pb)

		recv_tun <- pb
		recv_gw <- pbb
		db.recv <- pbc
		mb.recv <- pbd

	default:

		pbb := <-getbuf
		pbb.copy_from(pb)

		pbc := <-getbuf
		pbc.copy_from(pb)

		recv_tun <- pb
		recv_gw <- pbb
		db.recv <- pbc
	}
}

func timer_tick() {

	for {
		sleep(TIMER_TICK, TIMER_TICK/TIMER_FUZZ)
		send_marker(marker.now(), mapper_oid, "mapper_timer")
	}
}
