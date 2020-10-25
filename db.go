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

func (o *Owners) db_restore() {

	if rdb == nil {
		return
	}

	// key: oid		-- O32
	// val: name    -- string
	rdb.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(oidbkt))
		if bkt == nil {
			return nil
		}
		log.info("db: restoring oids")
		bkt.ForEach(func(key, val []byte) error {

			oid := O32(be.Uint32(key))
			name := string(val)

			if int(oid) >= len(o.oids) {
				o.oids = append(o.oids, make([]string, int(oid)-len(o.oids)+1)...)
			}

			if oid == 0 || len(name) == 0 {
				log.err("db restore oids: detected unassigned owner id: %v(%v), discarding", name, oid)
			} else if o.oids[oid] == name {
				log.err("db restore oids: detected duplicate owner name: %v(%v), discarding", name, oid)
			} else if o.oids[oid] != "" {
				log.err("db restore oids: detected duplicate owner id: %v(%v), discarding", name, oid)
			} else {
				log.debug("db: restore oid: %v(%v)", name, oid)
				o.oids[oid] = name
			}
			return nil
		})
		return nil
	})

	// copy to new DB

	var err error

	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(oidbkt))
		return err
	})
	if err != nil {
		log.fatal("db restore oids: cannot create bucket %v: %v", oidbkt, err)
	}

	err = db.Update(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(oidbkt))
		key := []byte{0, 0, 0, 0}
		for oid, name := range o.oids {
			if oid != 0 && len(name) != 0 { // skip over unassigned oids
				be.PutUint32(key, uint32(oid))
				log.debug("db: re-save oid: %v(%v)", name, oid)
				err := bkt.Put(key, []byte(name))
				if err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		log.fatal("db restore oids: restore owner ids failed: %v", err)
	}
}

func (m *Mark) db_restore() {

	if rdb == nil {
		return
	}

	// read marks from db

	mm := make(map[O32]M32) // temporary map oid -> mark for copying to new db

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
				log.err("db: invalid mark: %v(%v), discarding", owners.name(oid), mark)
			} else {
				log.debug("db: restore mark: %v(%v)", owners.name(oid), mark)
				mm[oid] = mark
			}
			return nil
		})
		return nil
	})

	// adjust time base from db

	mark := mm[mapper_oid]
	if mark == 0 {
		log.err("db restore marks: missing mapper mark")
	} else {
		time.Now().Add(-time.Duration(mark)*time.Second - 1)
	}

	// copy valid marks to new db

	var err error

	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(oidbkt))
		return err
	})
	if err != nil {
		log.fatal("db restore marks: cannot create bucket %v: %v", markbkt, err)
	}

	err = db.Update(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(markbkt))
		key := []byte{0, 0, 0, 0}
		val := []byte{0, 0, 0, 0}
		for oid, mark := range mm {
			if owners.name(oid) != "unknown" && mark != 0 { // skip over invalid marks
				be.PutUint32(key, uint32(oid))
				be.PutUint32(val, uint32(mark))
				log.debug("db: re-save mark: %v(%v)", owners.name(oid), mark)
				err := bkt.Put(key, val)
				if err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		log.fatal("db restore marks: restore marks failed: %v", err)
	}
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
		log.err("db save oid: failed to save oid: %v", err)
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

	dbpath := path.Join(cli.datadir, dbname)
	rdbpath := dbpath + "~"

	log.info("opening DB: %v", dbname)

	if err := os.Rename(dbpath, rdbpath); err != nil {
		if os.IsNotExist(err) {
			rdb = nil
		} else {
			log.fatal("cannot rename %v: %v", dbname, err)
		}
	} else {
		rdb, err = bolt.Open(rdbpath, 0440, &bolt.Options{Timeout: 1 * time.Second})
		if err != nil {
			log.fatal("cannot open %v: %v", dbname+"~", err)
		}
	}

	os.MkdirAll(cli.datadir, 0770)
	db, err = bolt.Open(dbpath, 0660, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		log.fatal("cannot create %v: %v", dbname, err)
	}

	go db_listen()
}
