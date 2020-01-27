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

func db_listen() {

	for pb := range dbchan {

		retbuf <- pb
	}
}

func stop_db_restore() {

	if rdb != nil {
		log.info("closing restore DB: %v", rdbname)
		rdb.Close()
		rdb = nil
	}
	rdbpath := path.Join(cli.datadir, dbname + "~")
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
			log.fatal("cannot open %v: %v", rdbname, err)
		}
	}

	db, err = bolt.Open(dbpath, 0666, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		log.fatal("cannot create %v: %v", dbname, err)
	}

	go db_listen()
}
