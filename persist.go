/* Copyright (c) 2018-2020 Waldemar Augustyn */

package main

import (
	bolt "go.etcd.io/bbolt"
	"time"
)

const (
	dbpath   = "mapper.db"
	eabucket = "ea-map"
)

var db *bolt.DB

func open_db() {

	var err error

	log.info("opening DB: %v", dbpath)
	db, err = bolt.Open(dbpath, 0666, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		db = nil
		goexit <- "cannot open DB"
	}
}
