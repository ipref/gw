/* Copyright (c) 2018 Waldemar Augustyn */

package main

import (
	"github.com/fsnotify/fsnotify"
	"path/filepath"
	"time"
)

const (
	DEBOUNCE = time.Duration(4765 * time.Millisecond) // [s] file event debounce time
)

/* Parsing DNS files

We watch files for changes, then debounce file events before parsing. Each DNS
file type has its own parsing go routine. The routne waits for its debounce
timer to fire.  The timer is restarted on every file event. That way a series of
rapid file events is reduced to a single timer event.
*/

type DnsFunc struct {
	gofunc func(string, *time.Timer)
	timer  *time.Timer
}

func parse_hosts(path string, timer *time.Timer) {

	for _ = range timer.C {
		log.info("dns watcher: parsing: %v", filepath.Base(path))
	}
}

func parse_dns(path string, timer *time.Timer) {

	for _ = range timer.C {
		log.info("dns watcher: parsing: %v", filepath.Base(path))
	}
}

// watch files for DNS information
func dns_watcher() {

	if len(cli.hosts_path) == 0 && len(cli.dns_path) == 0 {
		log.info("dns watcher: nothing to watch, exiting")
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.fatal("dns watcher: cannot setup file watcher: %v", err)
	}

	// install file watchers

	dns_funcs := make(map[string]DnsFunc)

	if len(cli.hosts_path) != 0 {
		dns_funcs[cli.hosts_path] = DnsFunc{
			parse_hosts,
			time.NewTimer(1), // parse immediately
		}
	}

	if len(cli.dns_path) != 0 {
		dns_funcs[cli.dns_path] = DnsFunc{
			parse_dns,
			time.NewTimer(1), // parse immediately
		}
	}

	for path, dnsfunc := range dns_funcs {
		fname := filepath.Base(path)
		err := watcher.Add(path)
		if err != nil {
			log.fatal("dns watcher: cannot watch file %v: %v", fname, err)
		}
		go dnsfunc.gofunc(path, dnsfunc.timer)
		log.info("dns watcher: watching file: %v", fname)
	}

	// watch file changes

	for {
		select {
		case event := <-watcher.Events:
			fname := filepath.Base(event.Name)
			log.debug("dns watcher: file changed: %v %v", fname, event.Op)
			dnsfunc, ok := dns_funcs[event.Name]
			if ok {
				dnsfunc.timer.Stop()
				if (event.Op & fsnotify.Remove) != 0 {
					// re-install watcher (no need to remove first)
					err = watcher.Add(event.Name)
					if err != nil {
						log.fatal("dns watcher: cannot re-watch file: %v", fname)
					}
				}
				dnsfunc.timer.Reset(DEBOUNCE)
			} else {
				log.err("dns watcher: unexpected event from file: %v", fname)
			}
		case err := <-watcher.Errors:
			log.err("dns watcher: file watch:", err)
		}
	}

	watcher.Close()
}
