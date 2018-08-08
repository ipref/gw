/* Copyright (c) 2018 Waldemar Augustyn */

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/fsnotify/fsnotify"
	"io"
	"io/ioutil"
	"net"
	"path/filepath"
	"regexp"
	//"sort"
	"strconv"
	"strings"
	"time"
)

const (
	DEBOUNCE = time.Duration(4765 * time.Millisecond) // [s] file event debounce time
)

var re_hexref *regexp.Regexp
var re_decref *regexp.Regexp
var re_dotref *regexp.Regexp

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

func compile_regex() {
	re_hexref = regexp.MustCompile(`^[0-9a-fA-F]+([-][0-9a-fA-F]+)*$`)
	re_decref = regexp.MustCompile(`^[0-9]+([,][0-9]+)+$`)
	re_dotref = regexp.MustCompile(`^([1-9]?[0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])([.]([1-9]?[0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5]))+$`)
}

// parse reference
func parse_ref(sss string) (Ref, error) {

	var ref Ref
	var err error
	var val uint64 // go does not allow ref.l, err := something(), need intermediate variable

	// hex

	if re_hexref.MatchString(sss) {
		hex := strings.Replace(sss, "-", "", -1)
		hexlen := len(hex)
		if hexlen < 17 {
			ref.h = 0
			val, err = strconv.ParseUint(hex, 16, 64)
			if err != nil {
				return ref, err
			}
			ref.l = val
			return ref, nil
		} else {
			val, err = strconv.ParseUint(hex[:hexlen-16], 16, 64)
			if err != nil {
				return ref, err
			}
			ref.h = val
			val, err = strconv.ParseUint(hex[hexlen-16:hexlen], 16, 64)
			if err != nil {
				return ref, err
			}
			ref.l = val
			return ref, nil
		}
	}

	// decimal

	if re_decref.MatchString(sss) {
		decstr := strings.Replace(sss, ",", "", -1)
		ref.h = 0
		val, err = strconv.ParseUint(decstr, 10, 64)
		if err != nil {
			return ref, err
		}
		ref.l = val
		return ref, nil
	}

	// dotted decimal

	if re_dotref.MatchString(sss) {
		dot := strings.Split(sss, ".")
		dotlen := len(dot)
		for ii := 0; ii < dotlen; ii++ {
			dec, err := strconv.ParseUint(dot[ii], 10, 8)
			if err != nil {
				return ref, err
			}
			if ii < (dotlen - 8) {
				ref.h <<= 8
				ref.h += uint64(dec)
			} else {
				ref.l <<= 8
				ref.l += uint64(dec)
			}
		}
		return ref, nil
	}

	return ref, fmt.Errorf("invalid format")
}

// parse file formatted as /etc/hosts
func parse_hosts_file(fname string, input io.Reader) map[uint32]AddrRec {

	arecs := make(map[uint32]AddrRec) // use map to detect duplicate entries
	line_scanner := bufio.NewScanner(input)
	lno := 0

	for line_scanner.Scan() {

		lno += 1

		wholeline := line_scanner.Text()
		toks := strings.Split(wholeline, "#")

		if (len(toks) < 2) || (toks[1][0] != '=') {
			continue // empty line or no IPREF extension
		}

		left := toks[0]
		right := toks[1][1:]
		arec := AddrRec{}

		// every valid entry has an IP address as the first item

		ltoks := strings.Fields(left)
		if len(ltoks) == 0 {
			continue // comment line
		}
		addr := net.ParseIP(ltoks[0])
		if addr == nil {
			log.err("parse hosts: %v(%v): invalid IP address: %v", fname, lno, ltoks[0])
			continue
		}

		addr = addr.To4()

		if addr == nil {
			continue // not an IPv4 address
		}

		// ref is always preceeded by a "+"

		rtoks := strings.Split(right, "+")

		// every IPREF entry has a record type as first item

		if len(rtoks) == 0 {
			continue // empty, treat as comment
		}

		gwtoks := strings.Fields(rtoks[0])
		if len(gwtoks) == 0 {
			log.err("parse hosts: %v(%v): missing IPREF record type", fname, lno)
			continue
		}

		var rectype string

		if gwtoks[0] == "pub" || gwtoks[0] == "public" {
			rectype = "pub"
		} else if gwtoks[0] == "ext" || gwtoks[0] == "external" {
			rectype = "ext"
		} else if gwtoks[0] == "loc" || gwtoks[0] == "local" {
			continue // local host
		} else {
			log.err("parse hosts: %v(%v): invalid IPREF record type: %v", fname, lno, gwtoks[0])
			continue
		}

		// parse gw

		if len(gwtoks) > 2 {
			log.err("parse hosts: %v(%v): invalid gw address: %v", fname, lno, strings.Join(gwtoks[1:], " "))
			continue
		}

		if len(gwtoks) == 2 {
			gw := net.ParseIP(gwtoks[1])
			if gw == nil {
				log.err("parse hosts: %v(%v): invalid gw address: %v", fname, lno, gwtoks[1])
				continue
			}
			gw = gw.To4()
			if gw == nil {
				log.err("parse hosts: %v(%v): invalid IPv4 gw address: %v", fname, lno, gwtoks[1])
				continue
			}
			if !gw.IsGlobalUnicast() {
				log.err("parse hosts: %v(%v): non-unicast gw: %v", fname, lno, gwtoks[1])
				continue
			}
			arec.gw = be.Uint32(gw)
		}

		// parse ref

		if len(rtoks) > 2 {
			log.err("parse hosts: %v(%v): invalid reference: %v", fname, lno, strings.Join(rtoks[1:], " + "))
			continue
		}

		if len(rtoks) == 2 {
			reftoks := strings.Fields(rtoks[1])
			if len(reftoks) == 0 {
				log.err("parse hosts: %v(%v): missing reference", fname, lno)
				continue
			}
			if len(reftoks) > 1 {
				log.err("parse hosts: %v(%v): invalid reference: %v", fname, lno, rtoks[1])
				continue
			}

			ref, err := parse_ref(reftoks[0])
			if err != nil {
				log.err("parse hosts: %v(%v): invalid reference: %v: %v", fname, lno, reftoks[0], err)
				continue
			}

			arec.ref = ref
		}

		// build string showing gw + ref

		var sb strings.Builder

		sb.WriteString(addr.String())
		for ii := sb.Len(); ii < 15; ii++ {
			sb.WriteString(" ")
		}

		sb.WriteString("  =  ")

		if arec.gw != 0 {
			gw := []byte{0, 0, 0, 0}
			len := sb.Len()
			be.PutUint32(gw, arec.gw)
			sb.WriteString(net.IP(gw).String())
			for ii := sb.Len(); ii < len+16; ii++ {
				sb.WriteString(" ")
			}
		}
		if !arec.ref.isZero() {
			sb.WriteString("+ ")
			sb.WriteString(arec.ref.String())
		}

		// add records to arec

		if rectype == "pub" {

			// for pub entries, both gw and the reference are optional

			arec.ip = be.Uint32(addr)
			arecs[arec.ip] = arec

			log.debug("parse hosts: %3d  pub  %v", lno, sb.String())

		} else if rectype == "ext" {

			// for ext entries, both gw and the reference are mandatory

			if arec.gw == 0 {
				log.err("parse hosts: %v(%v): missing gw address", fname, lno)
				continue
			}

			if arec.ref.isZero() {
				log.err("parse hosts: %v(%v): missing reference", fname, lno)
				continue
			}

			arec.ea = be.Uint32(addr)
			arecs[arec.ea] = arec
			log.debug("parse hosts: %3d  ext  %v", lno, sb.String())
		}
	}

	return arecs
}

func parse_hosts(path string, timer *time.Timer) {

	fname := filepath.Base(path)

	for _ = range timer.C {

		wholefile, err := ioutil.ReadFile(path)
		if err != nil {
			log.err("parse hosts: cannot read %v: %v", fname, err)
			return
		}
		log.info("parse hosts: parsing: %v", fname)
		input := bytes.NewReader(wholefile)
		arecs := parse_hosts_file(fname, input)
		log.debug("parse hosts: num address records: %v", len(arecs))
		/*
			if log.level <= DEBUG {
				keys := make([]uint32, 0, len(arecs))
				for key, _ := range arecs {
					keys = append(keys, key)
				}
				sort.Slice(keys, func (i,j int) bool {return keys[i] < keys[j]})
				for _, key := range keys {
					arec := arecs[key]
					ip := []byte{0, 0, 0, 0}
					var sb strings.Builder

					if arec.ea == 0 {
						sb.WriteString("pub  ")
						be.PutUint32(ip, arec.ip)
					} else {
						sb.WriteString("ext  ")
						be.PutUint32(ip, arec.ea)
					}
					sb.WriteString(net.IP(ip).String())
					for ii := sb.Len(); ii < 21; ii++ {
						sb.WriteString(" ")
					}
					sb.WriteString("=  ")
					if arec.gw != 0 {
						len := sb.Len()
						be.PutUint32(ip, arec.gw)
						sb.WriteString(net.IP(ip).String())
						for ii := sb.Len(); ii < len + 15; ii++ {
							sb.WriteString(" ")
						}
					}
					if !arec.ref.isZero() {
						sb.WriteString("+ ")
						sb.WriteString(arec.ref.String())
					}
					log.debug("    %v", sb.String())
				}
			}
		*/
	}
}

// parse file with dns records
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

	compile_regex()

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