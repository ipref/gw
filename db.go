/* Copyright (c) 2018-2021 Waldemar Augustyn */

package main

import (
	. "github.com/ipref/common"
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
	dbbasename = "mapper"
	base_bkt   = "base" // various base data
	ea_bkt     = "ea"   // ea  -> db_arec
	ref_bkt    = "ref"  // ref -> db_arec
	mark_bkt   = "mark" // oid -> mark
	oid_bkt    = "oid"  // oid -> name
)

type DB struct {
	dbname  string
	rdbname string
	dbpath  string
	rdbpath string
	db      *bolt.DB // current DB
	rdb     *bolt.DB // restore DB
	recv    chan *PktBuf
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
		pkt := pb.pkt[pb.data:]

		off := V1_HDR_LEN
		pkt[off] = V1_TYPE_STRING
		pkt[off+1] = byte(len(tbase))
		copy(pkt[off+2:], tbase)

		off += (len(tbase) + 5) &^ 3
		pb.tail = pb.data + off
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
		log.info("mgw:  restoring ea records")
		bkt.ForEach(func(key, val []byte) error {

			// db_arec is a slice containing: oid + mark + ea + ip + gw + ref

			oid := O32(be.Uint32(val[:4]))
			mark := M32(be.Uint32(val[4:8]))
			arec := AddrRecDecode(ea_iplen, gw_iplen, val[V1_MARK_LEN:])

			if oid == 0 || mark == 0 {
				log.err("mgw:  restore ea: %v invalid oid mark: %v(%v): %v, discarding",
					arec.EA, owners.name(oid), oid, mark)
			} else if oid == mgw.oid && mark < mgw.cur_mark[oid] {
				log.debug("mgw:  restore ea: %v expired, discarding", arec.EA)
			} else {

				mgw.insert_record(oid, mark, val[V1_MARK_LEN:])
				map_tun.insert_record(oid, mark, val[V1_MARK_LEN:])
				db.insert_record(val)
				if oid == mapper_oid {
					gen_ea.allocated[arec.EA] = true
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
			arec := AddrRecDecode(ea_iplen, gw_iplen, val[V1_MARK_LEN:])

			if oid == 0 || mark == 0 {
				log.err("mtun: restore ref: %v invalid oid(mark): %v(%v), discarding",
					&arec.Ref, owners.name(oid), mark)
			} else if oid == mtun.oid && mark < mtun.cur_mark[oid] {
				log.debug("mtun: restore ref: %v expired, discarding", &arec.Ref)
			} else {

				mtun.insert_record(oid, mark, val[V1_MARK_LEN:])
				map_gw.insert_record(oid, mark, val[V1_MARK_LEN:])
				db.insert_record(val)
				if oid == mapper_oid {
					gen_ref.allocated[arec.Ref] = true
				}
			}
			return nil
		})
		return nil
	})
}

func (db *DB) save_oid(pb *PktBuf) {

	pkt := pb.pkt[pb.data:pb.tail]

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

	pkt := pb.pkt[pb.data:pb.tail]

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

	pkt := pb.pkt[pb.data:pb.tail]

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

	// db_arec is a slice containing: oid + mark + ea + ip + gw + ref

	arec := AddrRecDecode(ea_iplen, gw_iplen, db_arec[V1_MARK_LEN:])

	if arec.GW.IsZeroAddr() || arec.Ref.IsZero()  {
		log.err("db insert arec: null gw + ref, ignoring")
		return
	}

	var err error
	var mark M32

	if !arec.EA.IsZeroAddr() && arec.IP.IsZeroAddr() {

		if cli.debug["db"] {
			mark = M32(be.Uint32(db_arec[V1_MARK : V1_MARK+4]))
			log.debug("db save: mark(%v) %v -> %v + %v", mark, arec.EA, arec.GW, &arec.Ref)
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
			err := bkt.Put(arec.EA.AsSlice(), db_arec)
			return err
		})
		if err != nil {
			log.err("db insert arec: failed to save arec: %v", err)
		}

	} else if arec.EA.IsZeroAddr() && !arec.IP.IsZeroAddr() {

		if cli.debug["db"] {
			mark = M32(be.Uint32(db_arec[V1_MARK : V1_MARK+4]))
			log.debug("db save: mark(%v) %v -> %v", mark, &arec.Ref, arec.IP)
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
			err := bkt.Put(ref_asslice(arec.Ref), db_arec)
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

	pkt := pb.pkt[pb.data:pb.tail]
	pktlen := len(pkt)
	if pktlen < V1_HDR_LEN+V1_MARK_LEN+v1_arec_len {
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

	db_arec := make([]byte, V1_MARK_LEN+v1_arec_len, V1_MARK_LEN+v1_arec_len)
	copy(db_arec, pkt[off+V1_OID:off+V1_MARK+4])

	off += V1_MARK_LEN

	if (pktlen-off)%v1_arec_len != 0 {
		log.err("db save arec: corrupted packet, ignoring")
		return
	}

	for ; off < pktlen; off += v1_arec_len {
		copy(db_arec[V1_MARK_LEN:], pkt[off:off+v1_arec_len])
		db.insert_record(db_arec)
	}
}

func (db *DB) remove_expired_eas(pb *PktBuf) int {

	pkt := pb.pkt[pb.data:pb.tail]
	pktlen := len(pkt)
	if pktlen < V1_HDR_LEN+V1_MARK_LEN+v1_arec_len {
		log.err("db remove eas: packet too short, ignoring")
		return DROP
	}

	off := V1_HDR_LEN + V1_MARK_LEN

	if (pktlen-off)%v1_arec_len != 0 {
		log.err("db remove eas: corrupted packet, ignoring")
		return DROP
	}

	if db.db == nil {
		return DROP
	}

	var err error

	err = db.db.Update(func(tx *bolt.Tx) error {

		bkt := tx.Bucket([]byte(ea_bkt))

		if bkt == nil {
			return nil
		}

		for ; off < pktlen; off += v1_arec_len {

			arec := AddrRecDecode(ea_iplen, gw_iplen, pkt[off:])

			if arec.EA.IsZeroAddr() {
				continue
			}

			// db_arecb is a slice containing: oid + mark + ea + ip + gw + ref

			db_arecb := bkt.Get(arec.EA.AsSlice())
			db_arec := AddrRecDecode(ea_iplen, gw_iplen, db_arecb[V1_MARK_LEN:])

			if arec.EA != db_arec.EA {
				log.err("db remove ea(%v): ea mismatch, cannot remove ea", db_arec.EA)
				continue
			}
			if arec.GW != db_arec.GW {
				log.err("db remove ea(%v): gw mismatch, cannot remove ea", db_arec.EA)
				continue
			}
			if arec.Ref != db_arec.Ref {
				log.err("db remove ea(%v): ref mismatch, cannot remove ea", db_arec.EA)
				continue
			}

			if cli.debug["db"] {
				log.debug("db remove ea(%v): %v + %v", db_arec.EA, db_arec.GW, &db_arec.Ref)
			}

			err = bkt.Delete(arec.EA.AsSlice())

			if err != nil {
				break
			}
		}

		return err
	})

	if err != nil {
		log.err("db remove eas failed: %v", err)
		return DROP
	}

	pb.peer = "db"
	gen_ea.recv <- pb
	return ACCEPT
}

func (db *DB) find_expired_eas(pb *PktBuf) int {

	pkt := pb.pkt[pb.data:pb.tail]
	pktlen := len(pkt)
	if pktlen < V1_HDR_LEN+V1_MARK_LEN+v1_arec_len {
		log.err("db find eas: packet too short, ignoring")
		return DROP
	}

	off := V1_HDR_LEN

	if is_zero(pkt[off+V1_OID : off+V1_OID+4]) {
		log.err("db find eas: null oid, ignoring packet")
		return DROP
	}

	seek_oid := O32(be.Uint32(pkt[off+V1_OID : off+V1_OID+4]))

	off += V1_MARK_LEN

	if (pktlen - off) != v1_arec_len {
		log.err("db find eas: corrupted packet, ignoring")
		return DROP
	}

	seek_ea := AddrRecDecode(ea_iplen, gw_iplen, pkt[off:]).EA.AsSlice()

	// assume NACK

	pkt[V1_CMD] = V1_NACK | V1_RECOVER_EA
	pb.tail = pb.data + off
	be.PutUint16(pkt[V1_PKTLEN:V1_PKTLEN+2], uint16(off/4))
	pb.peer = "db"

	// search for eas
	//
	// these operations are atomic because all access to db is from inside this go routine

	var seek_mark M32

	if db.db == nil {
		log.err("db find eas: db unavailable")
		goto reply
	}

	db.db.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(mark_bkt))
		if bkt == nil {
			return nil
		}
		val := bkt.Get(pkt[V1_HDR_LEN+V1_OID : V1_HDR_LEN+V1_OID+4])
		if val != nil {
			seek_mark = M32(be.Uint32(val))
		}
		return nil
	})

	if seek_mark == 0 {
		log.err("db find eas: cannot find current mark for %v(%v) in db",
			owners.name(seek_oid), seek_oid)
		goto reply
	}

	db.db.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(ea_bkt))
		if bkt == nil {
			return nil
		}

		cur := bkt.Cursor()

		for ea, db_arec := cur.Seek(seek_ea); ea != nil; ea, db_arec = cur.Next() {

			// db_arec is a slice containing: oid + mark + ea + ip + gw + ref

			if O32(be.Uint32(db_arec[V1_OID:V1_OID+4])) != seek_oid {
				continue
			}
			if !(M32(be.Uint32(db_arec[V1_MARK:V1_MARK+4]))+RCVY_EXPIRE < seek_mark) {
				continue
			}

			copy(pkt[off:off+v1_arec_len], db_arec[V1_MARK_LEN:V1_MARK_LEN+v1_arec_len])

			off += v1_arec_len
			if off >= RCVY_MAX*v1_arec_len+V1_HDR_LEN+V1_MARK_LEN {
				break
			}
		}
		return nil
	})

	// change to ACK if any eas found

	if off > V1_HDR_LEN+V1_MARK_LEN {
		pkt[V1_CMD] = V1_ACK | V1_RECOVER_EA
		pb.tail = pb.data + off
		be.PutUint16(pkt[V1_PKTLEN:V1_PKTLEN+2], uint16(off/4))
	}

reply:
	pb.schan <- pb
	return ACCEPT
}

func (db *DB) remove_expired_refs(pb *PktBuf) int {

	pkt := pb.pkt[pb.data:pb.tail]
	pktlen := len(pkt)
	if pktlen < V1_HDR_LEN+V1_MARK_LEN+v1_arec_len {
		log.err("db remove refs: packet too short, ignoring")
		return DROP
	}

	off := V1_HDR_LEN + V1_MARK_LEN

	if (pktlen-off)%v1_arec_len != 0 {
		log.err("db remove refs: corrupted packet, ignoring")
		return DROP
	}

	if db.db == nil {
		return DROP
	}

	var err error

	err = db.db.Update(func(tx *bolt.Tx) error {

		bkt := tx.Bucket([]byte(ref_bkt))

		if bkt == nil {
			return nil
		}

		for ; off < pktlen; off += v1_arec_len {

			arec := AddrRecDecode(ea_iplen, gw_iplen, pkt[off:])

			if arec.Ref.IsZero() {
				continue
			}

			// db_arecb is a slice containing: oid + mark + ea + ip + gw + ref

			db_arecb := bkt.Get(ref_asslice(arec.Ref))
			db_arec := AddrRecDecode(ea_iplen, gw_iplen, db_arecb[V1_MARK_LEN:])

			if arec.GW != db_arec.GW {
				log.err("db remove gw+ref(%v + %v): gw mismatch, cannot remove ref", arec.GW, &arec.Ref)
				continue
			}
			if arec.Ref != db_arec.Ref {
				log.err("db remove gw+ref(%v + %v): ref mismatch, cannot remove ref", arec.GW, &arec.Ref)
				continue
			}
			if arec.IP != db_arec.IP {
				log.err("db remove gw+ref(%v + %v): ip mismatch, cannot remove ref", arec.GW, &arec.Ref)
				continue
			}

			if cli.debug["db"] {
				log.debug("db remove gw+ref(%v + %v -> %v)", arec.GW, &arec.Ref, arec.IP)
			}

			err = bkt.Delete(ref_asslice(arec.Ref))

			if err != nil {
				break
			}
		}

		return err
	})

	if err != nil {
		log.err("db remove refs failed: %v", err)
		return DROP
	}

	pb.peer = "db"
	gen_ref.recv <- pb
	return ACCEPT
}

func (db *DB) find_expired_refs(pb *PktBuf) int {

	pkt := pb.pkt[pb.data:pb.tail]
	pktlen := len(pkt)
	if pktlen < V1_HDR_LEN+V1_MARK_LEN+v1_arec_len {
		log.err("db find refs: packet too short, ignoring")
		return DROP
	}

	off := V1_HDR_LEN

	if is_zero(pkt[off+V1_OID : off+V1_OID+4]) {
		log.err("db find refs: null oid, ignoring packet")
		return DROP
	}

	seek_oid := O32(be.Uint32(pkt[off+V1_OID : off+V1_OID+4]))

	off += V1_MARK_LEN

	if (pktlen - off) != v1_arec_len {
		log.err("db find refs: corrupted packet, ignoring")
		return DROP
	}

	seek_ref := ref_asslice(AddrRecDecode(ea_iplen, gw_iplen, pkt[off:]).Ref)

	// assume NACK

	pkt[V1_CMD] = V1_NACK | V1_RECOVER_REF
	pb.tail = pb.data + off
	be.PutUint16(pkt[V1_PKTLEN:V1_PKTLEN+2], uint16(off/4))
	pb.peer = "db"

	// search for refs
	//
	// these operations are atomic because all access to db is from inside this go routine

	var seek_mark M32

	if db.db == nil {
		log.err("db find eas: db unavailable")
		goto reply
	}

	db.db.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(mark_bkt))
		if bkt == nil {
			return nil
		}
		val := bkt.Get(pkt[V1_HDR_LEN+V1_OID : V1_HDR_LEN+V1_OID+4])
		if val != nil {
			seek_mark = M32(be.Uint32(val))
		}
		return nil
	})

	if seek_mark == 0 {
		log.err("db find refs: cannot find current mark for %v(%v) in db",
			owners.name(seek_oid), seek_oid)
		goto reply
	}

	db.db.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(ref_bkt))
		if bkt == nil {
			return nil
		}

		cur := bkt.Cursor()

		for ref, db_arec := cur.Seek(seek_ref); ref != nil; ref, db_arec = cur.Next() {

			// db_arec is a slice containing: oid + mark + ea + ip + gw + ref

			if O32(be.Uint32(db_arec[V1_OID:V1_OID+4])) != seek_oid {
				continue
			}
			if !(M32(be.Uint32(db_arec[V1_MARK:V1_MARK+4]))+RCVY_EXPIRE < seek_mark) {
				continue
			}

			copy(pkt[off:off+v1_arec_len], db_arec[V1_MARK_LEN:V1_MARK_LEN+v1_arec_len])

			off += v1_arec_len
			if off >= RCVY_MAX*v1_arec_len+V1_HDR_LEN+V1_MARK_LEN {
				break
			}
		}
		return nil
	})

	// change to ACK if any refs found

	if off > V1_HDR_LEN+V1_MARK_LEN {
		pkt[V1_CMD] = V1_ACK | V1_RECOVER_REF
		pb.tail = pb.data + off
		be.PutUint16(pkt[V1_PKTLEN:V1_PKTLEN+2], uint16(off/4))
	}

reply:
	pb.schan <- pb
	return ACCEPT
}

func (db *DB) receive(pb *PktBuf) {

	pkt := pb.pkt[pb.data:pb.tail]

	if err := pb.validate_v1_header(len(pkt)); err != nil {

		log.err("db: invalid v1 packet from %v:  %v", pb.peer, err)
		retbuf <- pb
		return
	}

	cmd := pkt[V1_CMD]

	if cli.trace {
		pb.pp_raw("db in:  ")
	}

	verdict := DROP

	switch cmd {

	case V1_DATA | V1_NOOP:
	case V1_DATA | V1_SET_AREC:
		db.save_arec(pb)
	case V1_DATA | V1_SET_MARK:
		db.save_mark(pb)
	case V1_REQ | V1_RECOVER_EA:
		verdict = db.find_expired_eas(pb)
	case V1_DATA | V1_RECOVER_EA:
		verdict = db.remove_expired_eas(pb)
	case V1_REQ | V1_RECOVER_REF:
		verdict = db.find_expired_refs(pb)
	case V1_DATA | V1_RECOVER_REF:
		verdict = db.remove_expired_refs(pb)
	case V1_DATA | V1_SAVE_OID:
		db.save_oid(pb)
	case V1_DATA | V1_SAVE_TIME_BASE:
		db.save_time_base(pb)
	default: // invalid
		log.err("db: unrecognized v1 cmd: 0x%x from %v", cmd, pb.peer)
	}

	if verdict == DROP {
		retbuf <- pb
	}
}

func (db *DB) open_db() {

	// if restore DB exists then we restore from it regardless of whether DB exists
	// or not presuming this is a result of a previously failed or aborted startup

	if fd, err := os.Open(db.rdbpath); os.IsNotExist(err) {

		if err := os.Rename(db.dbpath, db.rdbpath); err != nil {
			if os.IsNotExist(err) {
				db.rdb = nil
			} else {
				log.fatal("cannot rename DB %v to %v: %v", db.dbname, db.rdbname, err)
			}
		} else {
			log.info("opening existing DB %v as restore DB renamed to %v", db.dbname, db.rdbname)
			frdb, err := bolt.Open(db.rdbpath, 0440, &bolt.Options{Timeout: 1 * time.Second, ReadOnly: true})
			if err != nil {
				log.fatal("cannot open restore DB %v: %v", db.rdbname, err)
			}
			db.rdb = frdb
		}

	} else {

		fd.Close()

		os.Remove(db.dbpath)
		log.info("opening existing restore DB %v", db.rdbname)

		frdb, err := bolt.Open(db.rdbpath, 0440, &bolt.Options{Timeout: 1 * time.Second, ReadOnly: true})
		if err != nil {
			log.fatal("cannot open existing restore DB %v: %v", db.rdbname, err)
		}
		db.rdb = frdb
	}

	log.info("creating DB %v", db.dbname)

	os.MkdirAll(cli.datadir, 0770)
	fdb, err := bolt.Open(db.dbpath, 0660, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		log.fatal("cannot create %v: %v", db.dbname, err)
	}
	db.db = fdb
}

func (db *DB) stop_restore() {

	if db.rdb != nil {
		log.info("closing restore DB: %v", db.rdbname)
		db.rdb.Close()
		db.rdb = nil
	}
	rdbpath := path.Join(cli.datadir, db.rdbname)
	os.Remove(rdbpath)
}

func (db *DB) stop() {

	if db.db != nil {
		log.info("closing DB: %v", db.dbname)
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
	db.dbname = dbbasename
	if ea_iplen == 4 {
		db.dbname += "_ea4"
	} else {
		db.dbname += "_ea6"
	}
	if gw_iplen == 4 {
		db.dbname += "_gw4"
	} else {
		db.dbname += "_gw6"
	}
	db.dbname += ".db"
	db.rdbname = db.dbname + "~"
	db.dbpath = path.Join(cli.datadir, db.dbname)
	db.rdbpath = path.Join(cli.datadir, db.rdbname)
	db.recv = make(chan *PktBuf, PKTQLEN*4)
}
