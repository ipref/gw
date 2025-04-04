/* Copyright (c) 2018-2021 Waldemar Augustyn */

package main

import (
	"bufio"
	"bytes"
	"github.com/fsnotify/fsnotify"
	rff "github.com/ipref/ref"
	"io"
	"io/ioutil"
	"net/netip"
	"path/filepath"
	"strings"
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

// parse file formatted as /etc/hosts
func parse_hosts_file(fname string, input io.Reader) map[IP]AddrRec {

	arecs := make(map[IP]AddrRec) // use map to detect duplicate entries
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
		addr, err := ParseIP(ltoks[0])
		if err != nil {
			log.err("dns watcher: %v(%v): invalid IP address: %v", fname, lno, ltoks[0])
			continue
		}

		// ref is always preceeded by a "+"

		rtoks := strings.Split(right, "+")

		// every IPREF entry has a record type as first item

		if len(rtoks) == 0 {
			continue // empty, treat as comment
		}

		gwtoks := strings.Fields(rtoks[0])
		if len(gwtoks) == 0 {
			log.err("dns watcher: %v(%v): missing IPREF record type", fname, lno)
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
			log.err("dns watcher: %v(%v): invalid IPREF record type: %v", fname, lno, gwtoks[0])
			continue
		}

		// parse gw

		if len(gwtoks) > 2 {
			log.err("dns watcher: %v(%v): invalid gw address: %v", fname, lno, strings.Join(gwtoks[1:], " "))
			continue
		}

		if len(gwtoks) == 2 {
			gw, err := ParseIP(gwtoks[1])
			if err != nil {
				log.err("dns watcher: %v(%v): invalid gw address: %v", fname, lno, gwtoks[1])
				continue
			}
			if !netip.Addr(gw).IsGlobalUnicast() {
				log.err("dns watcher: %v(%v): non-unicast gw: %v", fname, lno, gwtoks[1])
				continue
			}
			arec.gw = gw
		}

		// parse ref

		if len(rtoks) > 2 {
			log.err("dns watcher: %v(%v): invalid reference: %v", fname, lno, strings.Join(rtoks[1:], " + "))
			continue
		}

		if len(rtoks) == 2 {
			reftoks := strings.Fields(rtoks[1])
			if len(reftoks) == 0 {
				log.err("dns watcher: %v(%v): missing reference", fname, lno)
				continue
			}
			if len(reftoks) > 1 {
				log.err("dns watcher: %v(%v): invalid reference: %v", fname, lno, rtoks[1])
				continue
			}

			ref, err := rff.Parse(reftoks[0])
			if err != nil {
				log.err("dns watcher: %v(%v): invalid reference: %v: %v", fname, lno, reftoks[0], err)
				continue
			}

			arec.ref.H = ref.H
			arec.ref.L = ref.L
		}

		// build string showing gw + ref

		var sb strings.Builder

		sb.WriteString(addr.String())
		for ii := sb.Len(); ii < 15; ii++ {
			sb.WriteString(" ")
		}

		sb.WriteString("  =  ")

		if !arec.gw.IsZero() {
			len := sb.Len()
			sb.WriteString(arec.gw.String())
			for ii := sb.Len(); ii < len+16; ii++ {
				sb.WriteString(" ")
			}
		}
		if !arec.ref.IsZero() {
			sb.WriteString("+ ")
			sb.WriteString(arec.ref.String())
		}

		// add records to arec

		if rectype == "pub" {

			// for pub entries, both gw and the reference are optional

			arec.ip = addr
			arecs[arec.ip] = arec

			log.debug("dns watcher: %v %3d  pub  %v", fname, lno, sb.String())

		} else if rectype == "ext" {

			// for ext entries, both gw and the reference are mandatory

			if arec.gw.IsZero() {
				log.err("dns watcher: %v(%v): missing gw address", fname, lno)
				continue
			}

			if arec.ref.IsZero() {
				log.err("dns watcher: %v(%v): missing reference", fname, lno)
				continue
			}

			arec.ea = addr
			arecs[arec.ea] = arec
			log.debug("dns watcher: %v %3d  ext  %v", fname, lno, sb.String())
		}
	}

	return arecs
}

func install_hosts_records(oid O32, arecs map[IP]AddrRec) {

	// get mark for new keys

	mark := marker.now()

	// send new address records (if any, could be 0)

	keys := make([]IP, 0, len(arecs))
	for key, _ := range arecs {
		keys = append(keys, key)
	}
	numkeys := len(keys)

	log.info("dns watcher: sending hosts records to mapper: %v(%v) mark(%v), num(%v)",
		owners.name(oid), oid, mark, numkeys)

	for ix := 0; ix < numkeys; {

		pb := <-getbuf
		pbb := <-getbuf

		// v1 header

		pb.write_v1_header(V1_SET_AREC, 0)
		pkt := pb.pkt[pb.data:]

		// mark

		off := V1_HDR_LEN

		be.PutUint32(pkt[off+V1_OID:off+V1_OID+4], uint32(oid))
		be.PutUint32(pkt[off+V1_MARK:off+V1_MARK+4], uint32(mark))

		// arec records

		off += V1_MARK_LEN

		for off <= len(pkt)-v1_arec_len {

			rec, ok := arecs[keys[ix]]
			if !ok {
				log.fatal("dns watcher: unexpected invalid key") // paranoia
			}

			// validate

			if !rec.ea.IsZero() && rec.ip.IsZero() {

				if rec.gw.IsZero() || rec.ref.IsZero() {
					log.err("dns watcher: invalid ea address record: %v %v %v %v, ignoring",
						rec.ea, rec.ip, rec.gw, &rec.ref)
					goto skip_record
				}

			} else if rec.ea.IsZero() && !rec.ip.IsZero() {

				if rec.gw.IsZero() {
					rec.gw = cli.gw_ip
				}

				//if rec.ref.IsZero() {
				//
				//	// TODO: this is no good, it should check if a record already exists, as
				//	//       it stands, it will keep re-allocating on any change to the file
				//	//
				//	// The best approach would be to publish the allocations to a dynamic DNS
				//	// server, then convey records from the server to the mapper.
				//
				//	ref := <-random_dns_ref
				//	if ref.IsZero() {
				//		log.err("dns watcher: cannot get generated reference: %v %v %v %v, ignoring",
				//			rec.ea, rec.ip, rec.gw, &rec.ref)
				//		goto skip_record
				//	}
				//	rec.ref = ref
				//	log.info("dns watcher: allocated dns ref: %v %v %v %v",
				//		rec.ea, rec.ip, rec.gw, &rec.ref)
				//}

				if rec.gw.IsZero() || rec.ref.IsZero() {
					log.err("dns watcher: invalid ip address record: %v %v %v %v, ignoring",
						rec.ea, rec.ip, rec.gw, &rec.ref)
					goto skip_record
				}

			} else {
				log.err("dns watcher: invalid address record: %v %v %v %v, ignoring",
					rec.ea, rec.ip, rec.gw, &rec.ref)
				goto skip_record
			}

			// make sure second byte rule is met

			if !rec.ea.IsZero() && rec.ea.ByteFromEnd(1) >= SECOND_BYTE {
				log.err("dns watcher: address record second byte violation(ea): %v %v %v %v, ignoring",
					rec.ea, rec.ip, rec.gw, &rec.ref)
				goto skip_record
			}

			if !rec.ip.IsZero() && ((rec.ref.L>>8)&0xFF) >= SECOND_BYTE {
				log.err("dns watcher: address record second byte violation(ref): %v %v %v %v, ignoring",
					rec.ea, rec.ip, rec.gw, &rec.ref)
				goto skip_record
			}

			// pack it up

			if rec.ea.IsZero() {
				rec.ea = IPNum(ea_iplen, 0)
			}
			if rec.ip.IsZero() {
				rec.ip = IPNum(ea_iplen, 0)
			}
			v1_arec_encode(pkt[off:], rec)

			off += v1_arec_len

		skip_record:

			ix++
			if ix >= numkeys {
				break
			}
		}

		// send items

		if off > V1_HDR_LEN+V1_MARK_LEN {

			pb.tail = off
			be.PutUint16(pkt[V1_PKTLEN:V1_PKTLEN+2], uint16(off/4))

			pb.peer = "hosts"
			pbb.copy_from(pb)

			log.debug("dns watcher: sending packet with hosts records: %v(%v) mark(%v), num(%v)",
				owners.name(oid), oid, mark, (off-V1_HDR_LEN-V1_MARK_LEN)/v1_arec_len)

			recv_tun <- pb
			recv_gw <- pbb

		} else {

			log.info("dns watcher: no valid hosts records to send to mapper: %v(%v)",
				owners.name(oid), oid)

			retbuf <- pb
			retbuf <- pbb
		}
	}

	// set new mark whether we sent any records or not

	send_marker(mark, oid, "etc_hosts_parser")
}

func parse_hosts(path string, timer *time.Timer) {

	fname := filepath.Base(path)
	oid := owners.get_oid(path)

	for _ = range timer.C {

		wholefile, err := ioutil.ReadFile(path)
		if err != nil {
			log.err("dns watcher: cannot read file %v: %v", fname, err)
			return
		}
		log.debug("dns watcher: oid(%v) parsing file: %v", oid, fname)
		input := bytes.NewReader(wholefile)
		arecs := parse_hosts_file(fname, input)
		log.info("dns watcher: parsing file: %v: total number of address records: %v", fname, len(arecs))

		install_hosts_records(oid, arecs)
	}
}

// watch files for DNS information
func dns_watcher() {

	if len(cli.hosts_path) == 0 {
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
