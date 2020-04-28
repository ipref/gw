/* Copyright (c) 2018-2020 Waldemar Augustyn */

package main

import (
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
	dbname = "mapper.db"
	oidbkt = "oid"
)

var db *bolt.DB  // current DB
var rdb *bolt.DB // restore DB
var dbchan chan *PktBuf

func db_restore_owners(o *Owners) {

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
		log.info("db: restoring owner ids")
		bkt.ForEach(func(key, val []byte) error {

			oid := O32(be.Uint32(key))
			name := string(val)

			if int(oid) >= len(o.oids) {
				o.oids = append(o.oids, make([]string, int(oid)-len(o.oids)+1)...)
			}

			if oid == 0 || len(name) == 0 {
				log.err("db: detected unassigned owner id: %v(%v), discarding", name, oid)
			} else if o.oids[oid] == name {
				log.err("db: detected duplicate owner name: %v(%v), discarding", name, oid)
			} else if o.oids[oid] != "" {
				log.err("db: detected duplicate owner id: %v(%v), discarding", name, oid)
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
		log.fatal("db: restore owner ids: %v", err)
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
		log.fatal("db: restore owner id: %v", err)
	}
}

func db_save_oid(pb *PktBuf) {

	pkt := pb.pkt[pb.iphdr:pb.tail]

	if len(pkt) < V1_HDR_LEN+4+4 {
		log.err("db: save oid: pktlen(%v) too short, dropping", len(pkt))
		return
	}
	if pkt[V1_CMD] != V1_SAVE_OID {
		log.err("db: save oid: non DATA mode [%02x], dropping", pkt[V1_CMD])
		return
	}

	off := V1_HDR_LEN

	oid := pkt[off : off+4]
	name := pkt[off+4+2 : off+4+2+int(pkt[off+4+1])]

	log.debug("db: save oid: %v(%v)", string(name), be.Uint32(oid))

	var err error

	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(oidbkt))
		return err
	})
	if err != nil {
		log.fatal("db: cannot create bucket %v: %v", oidbkt, err)
	}

	err = db.Update(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(oidbkt))
		err := bkt.Put(oid, name)
		return err
	})
	if err != nil {
		log.err("db: save oid: failed to save oid: %v", err)
	}
}

func db_restore_eas(gea *GenEA) {
}

func db_listen() {

	for pb := range dbchan {

		pkt := pb.pkt[pb.iphdr:pb.tail]

		if err := pb.validate_v1_header(len(pkt)); err != nil {

			log.err("db: invalid v1 packet from %v:  %v", pb.peer, err)
			retbuf <- pb
			continue
		}

		cmd := pkt[V1_CMD] & 0x3f

		if cli.trace {
			pb.pp_raw("db in:  ")
		}

		switch cmd {

		case V1_NOOP:
		case V1_SAVE_OID:
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
		rdb, err = bolt.Open(rdbpath, 0666, &bolt.Options{Timeout: 1 * time.Second})
		if err != nil {
			log.fatal("cannot open %v: %v", dbname+"~", err)
		}
	}

	os.MkdirAll(cli.datadir, 0775)
	db, err = bolt.Open(dbpath, 0664, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		log.fatal("cannot create %v: %v", dbname, err)
	}

	go db_listen()
}
