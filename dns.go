/* Copyright (c) 2018 Waldemar Augustyn */

package main

import (
	"github.com/fsnotify/fsnotify"
	"path/filepath"
)

// watch files for DNS information
func dns_watcher() {

	if len(cli.hosts_path) == 0 && len(cli.dns_path) == 0 {
		log.info("dns watcher: nothing to watch, exiting")
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.fatal("dns watcher: cannot setup file watcher: %v", err)
	}

	// instll file watchers

	for _, path := range []string{cli.hosts_path, cli.dns_path} {
		if len(path) > 0 {
			fname := filepath.Base(path)
			err := watcher.Add(path)
			if err != nil {
				log.fatal("dns watcher: cannot watch file %v: %v", fname, err)
			}
			log.info("dns watcher: watching %v", fname)
		}
	}

	// watch file changes

	for {
		select {
		case event := <-watcher.Events:
			log.info("dns watcher: %v", event)
		case err := <-watcher.Errors:
			log.err("dns watcher: file watch:", err)
		}
	}

	watcher.Close()
}
