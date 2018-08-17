/* Copyright (c) 2018 Waldemar Augustyn */

package main

import (
	"sync"
	"time"
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
	return name
}

func (o *Owners) new_oid(name string) uint32 {

	if len(name) == 0 {
		log.fatal("mapper: missing owner name")
	}

	o.mtx.Lock()
	oid := uint32(len(o.oids))
	o.oids = append(o.oids, name)
	o.mtx.Unlock()
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

func timer() {

	ticker := time.Tick(MAPPER_TICK * time.Millisecond)

	for _ = range ticker {
		// nothing for now
	}
}
