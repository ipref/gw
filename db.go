/* Copyright (c) 2018-2021 Waldemar Augustyn */

package main

import (
	rff "github.com/ipref/ref"
	bolt "go.etcd.io/bbolt"
	"os"
	"path"
	"time"
)

/* Persistent store and restore

The DB holds data for restoration on start up. During restoration, two DBs are
open: rdb which holds data from the previous run, and db which is newly created
to hold data for the current run. Packet forwarding is delayed until restoration
completes.
*/

const (
	dbname   = "mapper.db"
	base_bkt = "base" // various base data
	ea_bkt   = "ea"   // ea  -> db_arec
	ref_bkt  = "ref"  // ref -> db_arec
	mark_bkt = "mark" // oid -> mark
	oid_bkt  = "oid"  // oid -> name
)

type DB struct {
	db   *bolt.DB // current DB
	rdb  *bolt.DB // restore DB
	recv chan *PktBuf
}

var db DB

func is_zero(slice []byte) bool {
	for _, val := range slice {
		if val != 0 {
			return false
		}
	}
	return true
}

func (o *Owners) restore_oids() {

	if db.rdb == nil {
		return
	}

	db.rdb.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(oid_bkt))
		if bkt == nil {
			return nil
		}
		log.info("owners: restoring oids")
		bkt.ForEach(func(key, val []byte) error {

			oid := O32(be.Uint32(key))
			name := string(val)

			o.mtx.Lock()
			if err := o.register(oid, name); err != nil {
				log.err("%v", err)
			}
			o.mtx.Unlock()

			return nil
		})
		return nil
	})
}

func (m *Mark) restore_time_base() {

	// restore time base from db

	if db.rdb != nil {
		db.rdb.View(func(tx *bolt.Tx) error {
			bkt := tx.Bucket([]byte(base_bkt))
			if bkt != nil {
				tbase := bkt.Get([]byte("time_base"))
				if tbase != nil {
					err := m.base.UnmarshalText(tbase)
					if err != nil {
						log.err("marker: cannot restore time base: %v", err)
					} else {
						log.info("marker: restoring time base: %v", string(tbase))
					}
				}
			}
			return nil
		})
	}

	// if necessary, init time base such that marks are always > 0

	if m.base.IsZero() {

		m.base = time.Now().Add(-time.Second)
	}

	// save time base

	if tbase, err := m.base.MarshalText(); err != nil {

		log.fatal("marker: cannot marshal time base: %v", err)

	} else {

		pb := <-getbuf
		pb.write_v1_header(V1_SAVE_TIME_BASE, 0)
		pkt := pb.pkt[pb.iphdr:]

		off := V1_HDR_LEN
		pkt[off] = V1_TYPE_STRING
		pkt[off+1] = byte(len(tbase))
		copy(pkt[off+2:], tbase)

		off += (len(tbase) + 5) &^ 3
		pb.tail = pb.iphdr + off
		be.PutUint16(pkt[V1_PKTLEN:V1_PKTLEN+2], uint16(off/4))

		pb.peer = "marker"
		db.recv <- pb

	}
}

func (m *Mark) restore_markers() {

	if db.rdb == nil {
		return
	}

	db.rdb.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(mark_bkt))
		if bkt == nil {
			return nil
		}
		log.info("marker: restoring marks")
		bkt.ForEach(func(key, val []byte) error {

			oid := O32(be.Uint32(key))
			mark := M32(be.Uint32(val))

			if oid == 0 || mark == 0 {
				log.err("marker: invalid restore mark: %v(%v): %v, discarding", owners.name(oid), oid, mark)
			} else {
				log.debug("marker: restore mark: %v(%v): %v", owners.name(oid), oid, mark)
				send_marker(mark, oid, "restore_markers")
			}
			return nil
		})
		return nil
	})
}

func (mgw *MapGw) restore_eas() {

	if db.rdb == nil {
		return
	}

	db.rdb.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(ea_bkt))
		if bkt == nil {
			return nil
		}
		log.info("mgw: restoring ea records")
		bkt.ForEach(func(key, val []byte) error {

			// db_arec is a slice containing: oid + mark + ea + ip + gw + ref

			oid := O32(be.Uint32(val[:4]))
			mark := M32(be.Uint32(val[4:8]))
			ea := IP32(be.Uint32(val[V1_MARK_LEN+V1_AREC_EA : V1_MARK_LEN+V1_AREC_EA+4]))

			if oid == 0 || mark == 0 {
				log.err("mgw: restore ea: %v invalid oid mark: %v(%v): %v, discarding", ea, owners.name(oid), oid, mark)
			} else if oid == mgw.oid && mark < mgw.cur_mark[oid] {
				log.debug("mgw: restore ea: %v expired, discarding", ea)
			} else {

				mgw.insert_record(oid, mark, val[V1_MARK_LEN:])
				map_tun.insert_record(oid, mark, val[V1_MARK_LEN:])
				db.insert_record(val)
				if oid == mapper_oid {
					gen_ea.allocated[ea] = true
				}
			}
			return nil
		})
		return nil
	})
}

func (mtun *MapTun) restore_refs() {

	if db.rdb == nil {
		return
	}

	db.rdb.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(ref_bkt))
		if bkt == nil {
			return nil
		}
		log.info("mtun: restoring ref records")
		bkt.ForEach(func(key, val []byte) error {

			// db_arec is a slice containing: oid + mark + ea + ip + gw + ref

			oid := O32(be.Uint32(val[:4]))
			mark := M32(be.Uint32(val[4:8]))
			var ref rff.Ref
			ref.H = be.Uint64(val[V1_MARK_LEN+V1_AREC_REFH : V1_MARK_LEN+V1_AREC_REFH+8])
			ref.L = be.Uint64(val[V1_MARK_LEN+V1_AREC_REFL : V1_MARK_LEN+V1_AREC_REFL+8])

			if oid == 0 || mark == 0 {
				log.err("mtun: restore ref: %v invalid oid(mark): %v(%v), discarding", ref, owners.name(oid), mark)
			} else if oid == mtun.oid && mark < mtun.cur_mark[oid] {
				log.debug("mtun: restore ref: %v expired, discarding", ref)
			} else {

				mtun.insert_record(oid, mark, val[V1_MARK_LEN:])
				map_gw.insert_record(oid, mark, val[V1_MARK_LEN:])
				db.insert_record(val)
				if oid == mapper_oid {
					gen_ref.allocated[ref] = true
				}
			}
			return nil
		})
		return nil
	})
}

func (db *DB) save_oid(pb *PktBuf) {

	pkt := pb.pkt[pb.iphdr:pb.tail]

	if len(pkt) < V1_HDR_LEN+4+4 {
		log.err("db save oid: pktlen(%v) too short, dropping", len(pkt))
		return
	}

	off := V1_HDR_LEN

	oid := pkt[off : off+4]
	name := pkt[off+4+2 : off+4+2+int(pkt[off+4+1])]

	log.debug("db save oid: %v(%v)", string(name), be.Uint32(oid))

	var err error

	err = db.db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(oid_bkt))
		return err
	})
	if err != nil {
		log.fatal("db save oid: cannot create bucket %v: %v", oid_bkt, err)
	}

	err = db.db.Update(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(oid_bkt))
		err := bkt.Put(oid, name)
		return err
	})
	if err != nil {
		log.err("db save oid: failed to save oid %v(%v): %v", string(name), be.Uint32(oid), err)
	}
}

func (db *DB) save_time_base(pb *PktBuf) {

	pkt := pb.pkt[pb.iphdr:pb.tail]

	if len(pkt) < V1_HDR_LEN+4+4 {
		log.err("db save time base: pktlen(%v) too short, dropping", len(pkt))
		return
	}

	off := V1_HDR_LEN

	tbase := pkt[off+2 : off+2+int(pkt[off+1])]

	log.debug("db save time base: %v", string(tbase))

	var err error

	err = db.db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(base_bkt))
		return err
	})
	if err != nil {
		log.fatal("db save time base: cannot create bucket %v: %v", base_bkt, err)
	}

	err = db.db.Update(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(base_bkt))
		err := bkt.Put([]byte("time_base"), tbase)
		return err
	})
	if err != nil {
		log.err("db failed to save time base %v: %v", string(tbase), err)
	}
}

func (db *DB) save_mark(pb *PktBuf) {

	pkt := pb.pkt[pb.iphdr:pb.tail]

	if len(pkt) < V1_HDR_LEN+V1_MARK_LEN {
		log.err("db save mark: pktlen(%v) too short, dropping", len(pkt))
		return
	}

	off := V1_HDR_LEN

	if is_zero(pkt[off+V1_OID:off+V1_OID+4]) || is_zero(pkt[off+V1_MARK:off+V1_MARK+4]) {
		log.err("db save mark: invalid oid or mark, ignoring")
		return
	}

	var err error

	err = db.db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(mark_bkt))
		return err
	})
	if err != nil {
		log.fatal("db save mark: cannot create bucket %v: %v", mark_bkt, err)
	}

	err = db.db.Update(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(mark_bkt))
		err := bkt.Put(pkt[off+V1_OID:off+V1_OID+4], pkt[off+V1_MARK:off+V1_MARK+4])
		return err
	})
	if err != nil {
		log.err("db save mark: failed to save mark: %v", err)
	}
}

func (db *DB) insert_record(db_arec []byte) {

	if is_zero(db_arec[V1_MARK_LEN+V1_AREC_GW:V1_MARK_LEN+V1_AREC_GW+4]) ||
		is_zero(db_arec[V1_MARK_LEN+V1_AREC_REFH:V1_MARK_LEN+V1_AREC_REFL+8]) {
		log.err("db insert arec: null gw + ref, ignoring")
		return
	}

	var err error
	var mark M32
	var ea IP32
	var ip IP32
	var gw IP32
	var ref rff.Ref

	ea_zero := is_zero(db_arec[V1_MARK_LEN+V1_AREC_EA : V1_MARK_LEN+V1_AREC_EA+4])
	ip_zero := is_zero(db_arec[V1_MARK_LEN+V1_AREC_IP : V1_MARK_LEN+V1_AREC_IP+4])

	if !ea_zero && ip_zero {

		if cli.debug["db"] {
			mark = M32(be.Uint32(db_arec[V1_MARK : V1_MARK+4]))
			ea = IP32(be.Uint32(db_arec[V1_MARK_LEN+V1_AREC_EA : V1_MARK_LEN+V1_AREC_EA+4]))
			gw = IP32(be.Uint32(db_arec[V1_MARK_LEN+V1_AREC_GW : V1_MARK_LEN+V1_AREC_GW+4]))
			ref.H = be.Uint64(db_arec[V1_MARK_LEN+V1_AREC_REFH : V1_MARK_LEN+V1_AREC_REFH+8])
			ref.L = be.Uint64(db_arec[V1_MARK_LEN+V1_AREC_REFL : V1_MARK_LEN+V1_AREC_REFL+8])
			log.debug("db save: mark(%v) %v -> %v + %v", mark, ea, gw, &ref)
		}

		err = db.db.Update(func(tx *bolt.Tx) error {
			_, err := tx.CreateBucketIfNotExists([]byte(ea_bkt))
			return err
		})
		if err != nil {
			log.fatal("db insert arec: cannot create bucket %v: %v", ea_bkt, err)
		}

		err = db.db.Update(func(tx *bolt.Tx) error {
			bkt := tx.Bucket([]byte(ea_bkt))
			err := bkt.Put(db_arec[V1_MARK_LEN+V1_AREC_EA:V1_MARK_LEN+V1_AREC_EA+4], db_arec)
			return err
		})
		if err != nil {
			log.err("db insert arec: failed to save arec: %v", err)
		}

	} else if ea_zero && !ip_zero {

		if cli.debug["db"] {
			mark = M32(be.Uint32(db_arec[V1_MARK : V1_MARK+4]))
			ip = IP32(be.Uint32(db_arec[V1_MARK_LEN+V1_AREC_IP : V1_MARK_LEN+V1_AREC_IP+4]))
			ref.H = be.Uint64(db_arec[V1_MARK_LEN+V1_AREC_REFH : V1_MARK_LEN+V1_AREC_REFH+8])
			ref.L = be.Uint64(db_arec[V1_MARK_LEN+V1_AREC_REFL : V1_MARK_LEN+V1_AREC_REFL+8])
			log.debug("db save: mark(%v) %v -> %v", mark, &ref, ip)
		}

		err = db.db.Update(func(tx *bolt.Tx) error {
			_, err := tx.CreateBucketIfNotExists([]byte(ref_bkt))
			return err
		})
		if err != nil {
			log.fatal("db insert arec: cannot create bucket %v: %v", ref_bkt, err)
		}

		err = db.db.Update(func(tx *bolt.Tx) error {
			bkt := tx.Bucket([]byte(ref_bkt))
			err := bkt.Put(db_arec[V1_MARK_LEN+V1_AREC_REFH:V1_MARK_LEN+V1_AREC_REFL+8], db_arec)
			return err
		})
		if err != nil {
			log.err("db insert arec: failed to save arec: %v", err)
		}

	} else {
		log.err("db save arec: invalid address record, ignoring")
	}
}

func (db *DB) save_arec(pb *PktBuf) {

	pkt := pb.pkt[pb.iphdr:pb.tail]
	pktlen := len(pkt)
	if pktlen < V1_HDR_LEN+V1_MARK_LEN+V1_AREC_LEN {
		log.err("db save arec: packet too short, ignoring")
		return
	}

	off := V1_HDR_LEN

	if is_zero(pkt[off+V1_OID : off+V1_OID+4]) {
		log.err("db save arec: null oid, ignoring packet")
		return
	}

	if is_zero(pkt[off+V1_MARK : off+V1_MARK+4]) {
		log.err("db save arec: null mark, ignoring packet")
		return
	}

	// db_arec is a slice containing: oid + mark + ea + ip + gw + ref

	db_arec := make([]byte, V1_MARK_LEN+V1_AREC_LEN, V1_MARK_LEN+V1_AREC_LEN)
	copy(db_arec, pkt[off+V1_OID:off+V1_MARK+4])

	off += V1_MARK_LEN

	if (pktlen-off)%V1_AREC_LEN != 0 {
		log.err("db save arec: corrupted packet, ignoring")
		return
	}

	for ; off < pktlen; off += V1_AREC_LEN {
		copy(db_arec[V1_MARK_LEN:], pkt[off:off+V1_AREC_LEN])
		db.insert_record(db_arec)
	}
}

func (db *DB) receive(pb *PktBuf) {

	pkt := pb.pkt[pb.iphdr:pb.tail]

	if err := pb.validate_v1_header(len(pkt)); err != nil {

		log.err("db: invalid v1 packet from %v:  %v", pb.peer, err)
		retbuf <- pb
		return
	}

	cmd := pkt[V1_CMD]

	if cli.trace {
		pb.pp_raw("db in:  ")
	}

	switch cmd {

	case V1_DATA | V1_NOOP:
	case V1_DATA | V1_SET_AREC:
		db.save_arec(pb)
	case V1_DATA | V1_SET_MARK:
		db.save_mark(pb)
	case V1_DATA | V1_SAVE_OID:
		db.save_oid(pb)
	case V1_DATA | V1_SAVE_TIME_BASE:
		db.save_time_base(pb)
	default: // invalid
		log.err("db: unrecognized v1 cmd: 0x%x from %v", cmd, pb.peer)
	}

	retbuf <- pb
}

func (db *DB) open_db() {

	rdbname := dbname + "~"
	dbpath := path.Join(cli.datadir, dbname)
	rdbpath := path.Join(cli.datadir, rdbname)

	// if restore DB exists then we restore from it regardless of whether DB exists
	// or not presuming this is a result of a previously failed or aborted startup

	if fd, err := os.Open(rdbpath); os.IsNotExist(err) {

		if err := os.Rename(dbpath, rdbpath); err != nil {
			if os.IsNotExist(err) {
				db.rdb = nil
			} else {
				log.fatal("cannot rename DB %v to %v: %v", dbname, rdbname, err)
			}
		} else {
			log.info("opening existing DB %v as restore DB renamed to %v", dbname, rdbname)
			frdb, err := bolt.Open(rdbpath, 0440, &bolt.Options{Timeout: 1 * time.Second, ReadOnly: true})
			if err != nil {
				log.fatal("cannot open restore DB %v: %v", rdbname, err)
			}
			db.rdb = frdb
		}

	} else {

		fd.Close()

		os.Remove(dbpath)
		log.info("opening existing restore DB %v", rdbname)

		frdb, err := bolt.Open(rdbpath, 0440, &bolt.Options{Timeout: 1 * time.Second, ReadOnly: true})
		if err != nil {
			log.fatal("cannot open existing restore DB %v: %v", rdbname, err)
		}
		db.rdb = frdb
	}

	log.info("creating DB %v", dbname)

	os.MkdirAll(cli.datadir, 0770)
	fdb, err := bolt.Open(dbpath, 0660, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		log.fatal("cannot create %v: %v", dbname, err)
	}
	db.db = fdb
}

func (db *DB) stop_restore() {

	if db.rdb != nil {
		log.info("closing restore DB: %v", dbname+"~")
		db.rdb.Close()
		db.rdb = nil
	}
	rdbpath := path.Join(cli.datadir, dbname+"~")
	os.Remove(rdbpath)
}

func (db *DB) stop() {

	if db.db != nil {
		log.info("closing DB: %v", dbname)
		db.db.Close()
		db.db = nil
	}
	db.stop_restore()
}

func (db *DB) start() {

	db.open_db()

	go func(db *DB) {
		for pb := range db.recv {
			db.receive(pb)
		}
	}(db)
}

func (db *DB) init() {
	db.recv = make(chan *PktBuf, PKTQLEN)
}
