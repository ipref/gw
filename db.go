/* Copyright (c) 2018-2020 Waldemar Augustyn */

package main

import (
	rff "github.com/ipref/ref"
	bolt "go.etcd.io/bbolt"
	"os"
	"path"
	"time"
)

/* Persistent store and restore

The DB holds data for restoration on start up. The restoration is performed
directly without locking. In contrast, storing data in DB is accomplished by
sending v1 packets to DB channel.
*/

const (
	dbname  = "mapper.db"
	basebkt = "base" // various base data
	eabkt   = "ea"   // ea  -> db_arec
	refbkt  = "ref"  // ref -> db_arec
	markbkt = "mark" // oid -> mark
	oidbkt  = "oid"  // oid -> name
)

var db *bolt.DB  // current DB
var rdb *bolt.DB // restore DB
var dbchan chan *PktBuf

func zero(slice []byte) bool {
	for _, val := range slice {
		if val != 0 {
			return false
		}
	}
	return true
}

func (o *Owners) db_restore_oids() {

	if rdb == nil {
		return
	}

	rdb.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(oidbkt))
		if bkt == nil {
			return nil
		}
		log.info("db: restoring oids")
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

func (m *Mark) db_restore_time_base() {

	// restore time base from db

	if rdb != nil {
		rdb.View(func(tx *bolt.Tx) error {
			bkt := tx.Bucket([]byte(basebkt))
			if bkt != nil {
				tbase := bkt.Get([]byte("time_base"))
				if tbase != nil {
					err := m.base.UnmarshalText(tbase)
					if err != nil {
						log.err("db: cannot restore time base: %v", err)
					} else {
						log.info("db: restoring time base: %v", string(tbase))
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
		dbchan <- pb

	}
}

func (m *Mark) db_restore_markers() {

	if rdb == nil {
		return
	}

	rdb.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(markbkt))
		if bkt == nil {
			return nil
		}
		log.info("db: restoring marks")
		bkt.ForEach(func(key, val []byte) error {

			oid := O32(be.Uint32(key))
			mark := M32(be.Uint32(val))

			if oid == 0 || mark == 0 {
				log.err("db: invalid mark: %v(%v): %v, discarding", owners.name(oid), oid, mark)
			} else {
				log.debug("db: restore mark: %v(%v): %v", owners.name(oid), oid, mark)
				send_marker(mark, oid, "restore_markers")
			}
			return nil
		})
		return nil
	})
}

// restore address records from the ea bucket
func (mgw *MapGw) db_restore() {

	if rdb == nil {
		return
	}

	rdb.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(eabkt))
		if bkt == nil {
			return nil
		}
		log.info("db restoring ea records")
		bkt.ForEach(func(key, val []byte) error {

			// db_arec is a slice containing: oid + mark + ea + ip + gw + ref

			oid := O32(be.Uint32(val[:4]))
			mark := M32(be.Uint32(val[4:8]))
			ea := IP32(be.Uint32(val[V1_MARK_LEN+V1_AREC_EA : V1_MARK_LEN+V1_AREC_EA+4]))

			if oid == 0 || mark == 0 {
				log.err("db restore ea: %v invalid oid(mark): %v(%v), discarding", ea, owners.name(oid), mark)
			} else if oid == mgw.oid && mark < mgw.cur_mark[oid] {
				log.debug("db restore ea: %v expired, discarding", ea)
			} else {
				log.debug("db restore ea: %v restore", ea)

				mgw.insert_record(oid, mark, val[V1_MARK_LEN:])
				map_tun.insert_record(oid, mark, val[V1_MARK_LEN:])
				db_insert_record(val)
			}
			return nil
		})
		return nil
	})
}

// restore address records from the ref bucket
func (mtun *MapTun) db_restore() {

	if rdb == nil {
		return
	}

	rdb.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(refbkt))
		if bkt == nil {
			return nil
		}
		log.info("db restoring ref records")
		bkt.ForEach(func(key, val []byte) error {

			// db_arec is a slice containing: oid + mark + ea + ip + gw + ref

			oid := O32(be.Uint32(val[:4]))
			mark := M32(be.Uint32(val[4:8]))
			var ref rff.Ref
			ref.H = be.Uint64(val[V1_MARK_LEN+V1_AREC_REFH : V1_MARK_LEN+V1_AREC_REFH+8])
			ref.L = be.Uint64(val[V1_MARK_LEN+V1_AREC_REFL : V1_MARK_LEN+V1_AREC_REFL+8])

			if oid == 0 || mark == 0 {
				log.err("db restore ref: %v invalid oid(mark): %v(%v), discarding", ref, owners.name(oid), mark)
			} else if oid == mtun.oid && mark < mtun.cur_mark[oid] {
				log.debug("db restore ref: %v expired, discarding", ref)
			} else {
				log.debug("db restore ref: %v restore", ref)

				mtun.insert_record(oid, mark, val[V1_MARK_LEN:])
				map_gw.insert_record(oid, mark, val[V1_MARK_LEN:])
				db_insert_record(val)
			}
			return nil
		})
		return nil
	})
}

// restore allocated eas
func (gen *GenEA) db_restore() {

	if db == nil {
		return
	}

	db.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(eabkt))
		if bkt == nil {
			return nil
		}
		log.info("db restoring allocated eas")
		bkt.ForEach(func(key, val []byte) error {

			// db_arec is a slice containing: oid + mark + ea + ip + gw + ref

			oid := O32(be.Uint32(val[:4]))
			mark := M32(be.Uint32(val[4:8]))
			ea := IP32(be.Uint32(val[V1_MARK_LEN+V1_AREC_EA : V1_MARK_LEN+V1_AREC_EA+4]))

			if oid == 0 || mark == 0 {
				log.err("db restore allocated ea: %v invalid oid(mark): %v(%v), ignoring", ea, owners.name(oid), mark)
			} else if oid != mapper_oid {
				log.debug("db restore allocated ea: %v not allocated by mapper, ignoring", ea)
			} else {

				_, added := gen.allocated.Put(ea, func(old interface{}, exists bool) (interface{}, bool) {
					return M32(0), !exists
				})

				if added {
					log.debug("db restore allocated ea: %v", ea)
				} else {
					log.err("db restore allocated ea: %v already exists", ea)
				}

			}
			return nil
		})
		return nil
	})
}

// restore allocated refs
func (gen *GenREF) db_restore() {

	if db == nil {
		return
	}

	var refzero rff.Ref // constant rff.Ref{0,0}

	db.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(refbkt))
		if bkt == nil {
			return nil
		}
		log.info("db restoring allocated refs")
		bkt.ForEach(func(key, val []byte) error {

			// db_arec is a slice containing: oid + mark + ea + ip + gw + ref

			oid := O32(be.Uint32(val[:4]))
			mark := M32(be.Uint32(val[4:8]))
			var ref rff.Ref
			ref.H = be.Uint64(val[V1_MARK_LEN+V1_AREC_REFH : V1_MARK_LEN+V1_AREC_REFH+8])
			ref.L = be.Uint64(val[V1_MARK_LEN+V1_AREC_REFL : V1_MARK_LEN+V1_AREC_REFL+8])

			if oid == 0 || mark == 0 {
				log.err("db restore allocated ref: %v invalid oid(mark): %v(%v), ignoring", ref, owners.name(oid), mark)
			} else if oid != mapper_oid {
				log.debug("db restore allocated ref: %v not allocated by mapper, ignoring", ref)
			} else {

				_, added := gen.allocated.Put(ref, func(old interface{}, exists bool) (interface{}, bool) {
					return refzero, !exists
				})

				if added {
					log.debug("db restore allocated ref: %v", ref)
				} else {
					log.err("db restore allocated ref: %v already exists", ref)
				}

			}
			return nil
		})
		return nil
	})
}

func db_save_oid(pb *PktBuf) {

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

	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(oidbkt))
		return err
	})
	if err != nil {
		log.fatal("db save oid: cannot create bucket %v: %v", oidbkt, err)
	}

	err = db.Update(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(oidbkt))
		err := bkt.Put(oid, name)
		return err
	})
	if err != nil {
		log.err("db save oid: failed to save oid %v(%v): %v", string(name), be.Uint32(oid), err)
	}
}

func db_save_time_base(pb *PktBuf) {

	pkt := pb.pkt[pb.iphdr:pb.tail]

	if len(pkt) < V1_HDR_LEN+4+4 {
		log.err("db save time base: pktlen(%v) too short, dropping", len(pkt))
		return
	}

	off := V1_HDR_LEN

	tbase := pkt[off+2 : off+2+int(pkt[off+1])]

	log.debug("db save time base: %v", string(tbase))

	var err error

	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(basebkt))
		return err
	})
	if err != nil {
		log.fatal("db save time base: cannot create bucket %v: %v", basebkt, err)
	}

	err = db.Update(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(basebkt))
		err := bkt.Put([]byte("time_base"), tbase)
		return err
	})
	if err != nil {
		log.err("db failed to save time base %v: %v", string(tbase), err)
	}
}

func db_save_mark(pb *PktBuf) {

	pkt := pb.pkt[pb.iphdr:pb.tail]

	if len(pkt) < V1_HDR_LEN+V1_MARK_LEN {
		log.err("db save mark: pktlen(%v) too short, dropping", len(pkt))
		return
	}

	off := V1_HDR_LEN

	if zero(pkt[off+V1_OID:off+V1_OID+4]) || zero(pkt[off+V1_MARK:off+V1_MARK+4]) {
		log.err("db save mark: invalid oid or mark, ignoring")
		return
	}

	var err error

	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(markbkt))
		return err
	})
	if err != nil {
		log.fatal("db save mark: cannot create bucket %v: %v", markbkt, err)
	}

	err = db.Update(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(markbkt))
		err := bkt.Put(pkt[off+V1_OID:off+V1_OID+4], pkt[off+V1_MARK:off+V1_MARK+4])
		return err
	})
	if err != nil {
		log.err("db save mark: failed to save mark: %v", err)
	}
}

func db_insert_record(db_arec []byte) {

	if zero(db_arec[V1_MARK_LEN+V1_AREC_GW:V1_MARK_LEN+V1_AREC_GW+4]) || zero(db_arec[V1_MARK_LEN+V1_AREC_REFH:V1_MARK_LEN+V1_AREC_REFL+8]) {
		log.err("db insert arec: null gw + ref, ignoring")
		return
	}

	var err error

	ea_zero := zero(db_arec[V1_MARK_LEN+V1_AREC_EA : V1_MARK_LEN+V1_AREC_EA+4])
	ip_zero := zero(db_arec[V1_MARK_LEN+V1_AREC_IP : V1_MARK_LEN+V1_AREC_IP+4])

	if !ea_zero && ip_zero {

		log.debug("db insert arec: ea -> db_arec")

		err = db.Update(func(tx *bolt.Tx) error {
			_, err := tx.CreateBucketIfNotExists([]byte(eabkt))
			return err
		})
		if err != nil {
			log.fatal("db insert arec: cannot create bucket %v: %v", eabkt, err)
		}

		err = db.Update(func(tx *bolt.Tx) error {
			bkt := tx.Bucket([]byte(eabkt))
			err := bkt.Put(db_arec[V1_MARK_LEN+V1_AREC_EA:V1_MARK_LEN+V1_AREC_EA+4], db_arec)
			return err
		})
		if err != nil {
			log.err("db insert arec: failed to save arec: %v", err)
		}

	} else if ea_zero && !ip_zero {

		log.debug("db insert arec: ref -> db_arec")

		err = db.Update(func(tx *bolt.Tx) error {
			_, err := tx.CreateBucketIfNotExists([]byte(refbkt))
			return err
		})
		if err != nil {
			log.fatal("db insert arec: cannot create bucket %v: %v", refbkt, err)
		}

		err = db.Update(func(tx *bolt.Tx) error {
			bkt := tx.Bucket([]byte(refbkt))
			err := bkt.Put(db_arec[V1_MARK_LEN+V1_AREC_REFH:V1_MARK_LEN+V1_AREC_REFL+8], db_arec)
			return err
		})
		if err != nil {
			log.err("db insert arec: failed to save arec: %v", err)
		}

	} else {
		log.err("db insert arec: invalid address record, ignoring")
	}
}

func db_save_arec(pb *PktBuf) {

	pkt := pb.pkt[pb.iphdr:pb.tail]
	pktlen := len(pkt)
	if pktlen < V1_HDR_LEN+V1_MARK_LEN+V1_AREC_LEN {
		log.err("db save arec: packet too short, ignoring")
		return
	}

	off := V1_HDR_LEN

	if zero(pkt[off+V1_OID : off+V1_OID+4]) {
		log.err("db save arec: null oid, ignoring packet")
		return
	}

	if zero(pkt[off+V1_MARK : off+V1_MARK+4]) {
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
		db_insert_record(db_arec)
	}
}

func db_listen() {

	for pb := range dbchan {

		pkt := pb.pkt[pb.iphdr:pb.tail]

		if err := pb.validate_v1_header(len(pkt)); err != nil {

			log.err("db: invalid v1 packet from %v:  %v", pb.peer, err)
			retbuf <- pb
			continue
		}

		cmd := pkt[V1_CMD]

		if cli.trace {
			pb.pp_raw("db in:  ")
		}

		switch cmd {

		case V1_DATA | V1_NOOP:
		case V1_DATA | V1_SET_AREC:
			db_save_arec(pb)
		case V1_DATA | V1_SET_MARK:
			db_save_mark(pb)
		case V1_DATA | V1_SAVE_OID:
			db_save_oid(pb)
		case V1_DATA | V1_SAVE_TIME_BASE:
			db_save_time_base(pb)
		default: // invalid
			log.err("db: unrecognized v1 cmd: %v", cmd)
		}

		retbuf <- pb
	}
}

func stop_db_restore() {

	if rdb != nil {
		log.info("closing restore DB: %v", dbname+"~")
		rdb.Close()
		rdb = nil
	}
	rdbpath := path.Join(cli.datadir, dbname+"~")
	os.Remove(rdbpath)
}

func stop_db() {

	if db != nil {
		log.info("closing DB: %v", dbname)
		db.Close()
		db = nil
	}
	stop_db_restore()
}

func start_db() {

	var err error

	rdbname := dbname + "~"
	dbpath := path.Join(cli.datadir, dbname)
	rdbpath := path.Join(cli.datadir, rdbname)

	// if restore DB exists then we restore from it regardless of whether DB exists
	// or not presuming this is a result of a previous failed or aborted startup

	rdb, err = bolt.Open(rdbpath, 0440, &bolt.Options{Timeout: 1 * time.Second})
	if err == nil {
		log.info("opening existing restore DB %v", rdbname)
		os.Remove(dbpath)
	} else if os.IsNotExist(err) {
		if err := os.Rename(dbpath, rdbpath); err != nil {
			if os.IsNotExist(err) {
				rdb = nil
			} else {
				log.fatal("cannot rename DB %v to %v: %v", dbname, rdbname, err)
			}
		} else {
			log.info("opening existing DB %v as restore DB renamed to %v", dbname, rdbname)
			rdb, err = bolt.Open(rdbpath, 0440, &bolt.Options{Timeout: 1 * time.Second})
			if err != nil {
				log.fatal("cannot open restore DB %v: %v", rdbname, err)
			}
		}
	} else {
		log.fatal("cannot open existing restore DB %v: %v", rdbname, err)
	}

	log.info("creating DB %v", dbname)

	os.MkdirAll(cli.datadir, 0770)
	db, err = bolt.Open(dbpath, 0660, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		log.fatal("cannot create %v: %v", dbname, err)
	}

	go db_listen()
}
