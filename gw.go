/* Copyright (c) 2018-2021 Waldemar Augustyn */

package main

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"syscall"
	"golang.org/x/sys/unix"
)

var recv_gw chan *PktBuf
var send_gw chan *PktBuf

type RemoteGw struct {
	addr IP32
	port uint16
}

type RemoteGwConn struct {
	lock sync.RWMutex
	key RemoteGw
	con *net.UDPConn
	mtu int
	removed bool
	prev *RemoteGwConn // the previous most recently used connection (less recent)
	next *RemoteGwConn // the next most recently used connection (more recent)
}

type RemoteGwTable struct {
	lock sync.Mutex
	rcons map[RemoteGw]*RemoteGwConn
	nrcons int
	least_recent *RemoteGwConn
	most_recent *RemoteGwConn
}

func new_rgw_table() (rgws RemoteGwTable) {
	rgws.rcons = make(map[RemoteGw]*RemoteGwConn)
	return
}

func (rgws *RemoteGwTable) gc() {

	if cli.maxrgws < 1 {
		return
	}
	rgws.lock.Lock()
	defer rgws.lock.Unlock()
	for rgws.nrcons > cli.maxrgws {
		rcon := rgws.least_recent
		rcon.lock.Lock()
		rcon.next.prev = nil
		rgws.least_recent = rcon.next
		if rcon.prev != nil {
			panic("unexpected")
		}
		rcon.next = nil
		if !rcon.removed {
			rcon.con.Close() // ignore error
			rcon.removed = true
			rgws.nrcons--
		}
		rcon.lock.Unlock()
		delete(rgws.rcons, rcon.key)
	}
}

func (rgws *RemoteGwTable) active_rcon(rcon *RemoteGwConn) {

	rcon.lock.Lock()
	defer rcon.lock.Unlock()
	if rcon.removed || rcon.next == nil {
		return
	}
	rgws.lock.Lock()
	defer rgws.lock.Unlock()

	// remove from list
	if rcon.prev == nil {
		rgws.least_recent = rcon.next
	} else {
		rcon.prev.next = rcon.next
	}
	rcon.next.prev = rcon.prev

	// add to end of list
	rcon.prev = rgws.most_recent
	rcon.next = nil
	rgws.most_recent = rcon
	rcon.prev.next = rcon
}

func (rgws *RemoteGwTable) remove_rcon(rcon *RemoteGwConn) {

	rcon.lock.Lock()
	defer rcon.lock.Unlock()
	if rcon.removed {
		return
	}
	rcon.removed = true
	rcon.con.Close() // ignore error
	rgws.lock.Lock()
	defer rgws.lock.Unlock()
	rgws.nrcons--
	if rcon.prev == nil {
		rgws.least_recent = rcon.next
	} else {
		rcon.prev.next = rcon.next
	}
	if rcon.next == nil {
		rgws.most_recent = rcon.prev
	} else {
		rcon.next.prev = rcon.prev
	}
	rcon.prev = nil
	rcon.next = nil
	delete(rgws.rcons, rcon.key)
}

func (rgws *RemoteGwTable) get_rcon(saddr IP32, sport uint16,
	daddr IP32, dport uint16) (*RemoteGwConn, error) {

	// look for existing rcon
	key := RemoteGw{daddr, dport}
	rgws.lock.Lock()
	defer rgws.lock.Unlock()
	rcon, exists := rgws.rcons[key]
	if exists {
		rcon.lock.RLock()
		if rcon.removed {
			panic("unexpected")
		}
		rcon.lock.RUnlock()
		return rcon, nil
	}

	// open connection
	saddrb := []byte{0, 0, 0, 0}
	be.PutUint32(saddrb, uint32(saddr))
	daddrb := []byte{0, 0, 0, 0}
	be.PutUint32(daddrb, uint32(daddr))
	var dialer net.Dialer
	dialer.LocalAddr = &net.UDPAddr{saddrb, int(sport), ""}
	dialer.Control = func(network, address string, c syscall.RawConn) error {
		return rawconn_control(c, socket_configure)
	}
	c, err := dialer.Dial("udp4", (&net.UDPAddr{daddrb, int(dport), ""}).String())
	if err != nil {
		return nil, err
	}

	// create rcon
	rcon = &RemoteGwConn{}
	rcon.key = key
	var ok bool
	rcon.con, ok = c.(*net.UDPConn)
	if !ok {
		return nil, errors.New("expected net.UDPConn")
	}
	rcon.mtu, err = udpconn_getmtu(rcon.con)
	if err != nil {
		rcon.mtu = cli.ifc.MTU
	}
	rcon.removed = false
	rcon.prev = rgws.most_recent
	rcon.next = nil
	rgws.most_recent = rcon
	if rcon.prev == nil {
		rgws.least_recent = rcon
	} else {
		rcon.prev.next = rcon
	}
	rgws.rcons[key] = rcon
	rgws.nrcons++

	on_recv := func() {
		rgws.active_rcon(rcon)
	}
	on_emsgsize := func() {
		rcon.update_mtu()
	}
	on_close := func() {
		rgws.remove_rcon(rcon)
	}
	go gw_receiver(rcon.con, on_recv, on_emsgsize, on_close)
	go rgws.gc()
	return rcon, nil
}

func (rcon *RemoteGwConn) update_mtu() {

	mtu, err := udpconn_getmtu(rcon.con)
	if err != nil {
		log.trace("gw: get mtu failed: %v", err)
		return // silently ignore
	}
	rcon.lock.Lock()
	log.trace("gw: update remote connection mtu %v -> %v", rcon.mtu, mtu)
	rcon.mtu = mtu
	rcon.lock.Unlock()
}

func (rcon *RemoteGwConn) get_mtu() int {

	rcon.lock.RLock()
	defer rcon.lock.RUnlock()
	return rcon.mtu
}

func gw_sender(rgws *RemoteGwTable) {

	for pb := range send_gw {

		switch pb.typ {

		case PKT_V1:

			pkt := pb.pkt[pb.data:pb.tail]

			if pkt[V1_CMD] == V1_SET_MARK {

				// update time mark

				off := V1_HDR_LEN
				oid := O32(be.Uint32(pkt[off+V1_OID : off+V1_OID+4]))
				if oid == arp_oid {
					// arp_marker = M32(be.Uint32(pkt[off+V1_MARK : off+V1_MARK+4]))
				} else {
					log.err("gw out:  arp timer update oid(%v) does not match arp_oid(%v), ignoring", oid, arp_oid)
				}
				retbuf <- pb
				continue

			} else {
				log.err("gw out:  unknown v1 packet data/end(%v/%v), dropping", pb.data, len(pb.pkt))
				retbuf <- pb
				continue
			}

		case PKT_IPREF:

		next_fragment:
			if cli.debug["gw"] {
				log.debug("gw out:  %v", pb.pp_pkt())
			}

			if cli.trace {
				pb.pp_net("gw out:  ")
				pb.pp_tran("gw out:  ")
				pb.pp_raw("gw out:  ")
			}

		again:
			if pb.src != cli.gw_ip {
				log.err("gw out:  src(%v) is not gateway, packet dropped", pb.src)
				retbuf <- pb
				continue
			}
			rcon, err := rgws.get_rcon(pb.src, pb.sport, pb.dst, pb.dport)
			if err != nil {
				log.err("gw out:  error creating remote connection, packet dropped: %v", err)
				retbuf <- pb
				continue
			}
			mtu := rcon.get_mtu()
			mtu -= IP_HDR_MIN_LEN + UDP_HDR_LEN
			if mtu <= 0 {
				log.err("gw out:  bad mtu, dropping packet")
				retbuf <- pb
				continue
			}
			sent, trimmed, orig_mf, status := ipref_frag_in_place(pb, mtu)
			switch status {
			case IPREF_FRAG_IN_PLACE_NOT_NEEDED:
			case IPREF_FRAG_IN_PLACE_SUCCESS:
				log.trace("gw out:  fragmenting (%v + %v)", sent, trimmed)
			case IPREF_FRAG_IN_PLACE_DF:
				log.trace("gw out:  needs fragmentation but DF set, dropping") // TODO ICMP
				retbuf <- pb
				continue
			case IPREF_FRAG_IN_PLACE_SPACE:
				log.err("gw out:  not enough space in buffer to fragment, dropping")
				retbuf <- pb
				continue
			default:
				panic("unexpected")
			}
			wlen, err := rcon.con.Write(pb.pkt[pb.data:pb.tail])
			if err != nil {
				if errno, ok := error_errno(err); ok && errno == syscall.EMSGSIZE {
					log.trace("gw out:  write failed (EMSGSIZE), trying again")
					rcon.update_mtu()
					ipref_undo_frag_in_place(pb, trimmed, orig_mf)
					goto again
				}
				log.err("gw out:  write failed: %v", err)
				go rgws.remove_rcon(rcon)
				retbuf <- pb
				continue
			}
			if wlen != pb.len() {
				log.err("gw out:  write failed")
				go rgws.remove_rcon(rcon)
				retbuf <- pb
				continue
			}
			if trimmed != 0 {
				frag_off := ipref_next_frag_in_place(pb, trimmed, orig_mf)
				log.trace("gw out:  moving on to next fragment (%v)", frag_off)
				goto next_fragment
			}
			retbuf <- pb

		default:
			log.fatal("gw out:  unknown packet type: %v", pb.typ)
		}
	}
}

func gw_receiver(con *net.UDPConn, on_recv func(), on_emsgsize func(), on_close func()) {

	if cli.devmode {
		return
	}

	for {

		pb := <-getbuf
		pb.typ = PKT_IPREF
		pb.data = TUN_HDR_LEN + IPREF_HDR_MAX_LEN - IP_HDR_MIN_LEN

		rlen, addr, err := con.ReadFromUDP(pb.pkt[pb.data:])
		if cli.debug["gw"] {
			log.debug("gw in:   src IP: %v  rcvlen(%v)", addr, rlen)
		}
		if err != nil {
			if errno, ok := error_errno(err); ok && errno == syscall.EMSGSIZE {
				log.trace("gw in:   read failed (EMSGSIZE)")
				if on_emsgsize != nil {
					on_emsgsize()
				}
				retbuf <- pb
				continue
			} else {
				log.err("gw in:   read failed, closing connection: %v", err)
				retbuf <- pb
				break
			}
		}
		if rlen == 0 {
			log.err("gw in:   read failed (no data), closing connection")
			retbuf <- pb
			break
		}
		if rlen == len(pb.pkt) - pb.data {
			log.err("gw in:   read failed (not enough space), dropping packet")
			retbuf <- pb
			continue
		}
		if on_recv != nil {
			on_recv()
		}
		pb.tail = pb.data + rlen
		pb.src = IP32(be.Uint32(addr.IP))
		pb.sport = uint16(addr.Port)
		pb.dst = cli.gw_ip
		pb.dport = IPREF_PORT

		if cli.debug["gw"] {
			log.debug("gw in:   %v", pb.pp_pkt())
		}

		if cli.trace {
			pb.pp_net("gw in:   ")
			pb.pp_tran("gw in:   ")
			pb.pp_raw("gw in:   ")
		}

		recv_gw <- pb
	}

	if on_close != nil {
		on_close()
	}
}

func start_gw() {

	var con *net.UDPConn

	if !cli.devmode {

		gw_ip := []byte{0, 0, 0, 0}
		be.PutUint32(gw_ip, uint32(cli.gw_ip))
		var config net.ListenConfig
		config.Control = func(network, address string, c syscall.RawConn) error {
			return rawconn_control(c, socket_configure)
		}
		packet_con, err := config.ListenPacket(context.Background(), "udp4",
			(&net.UDPAddr{gw_ip, IPREF_PORT, ""}).String())
		if err != nil {
			log.fatal("gw: cannot listen on UDP: %v", err)
		}
		var ok bool
		con, ok = packet_con.(*net.UDPConn)
		if !ok {
			log.fatal("gw: listen UDP: expected net.UDPConn")
		}

		log.info("gw: gateway %v %v mtu(%v) %v pkt buffers",
			cli.gw_ip, cli.ifc.Name, cli.ifc.MTU, cli.maxbuf)
	}

	rgws := new_rgw_table()
	go gw_sender(&rgws)
	on_emsgsize := func() {
		// we should only get EMSGSIZE on the client sockets
		log.fatal("gw in:   EMSGSIZE on server socket")
	}
	on_close := func() {
		log.fatal("gw in:   server socket closed")
	}
	go gw_receiver(con, nil, on_emsgsize, on_close)
}

func udpconn_getmtu(con *net.UDPConn) (mtu int, err error) {

	err = udpconn_control(con, func(fd uintptr) (ctrl_err error) {
		mtu, ctrl_err = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU)
		return
	})
	return
}

func udpconn_control(con *net.UDPConn, ctrl func(fd uintptr) error) error {

	rawcon, err := con.SyscallConn()
	if err != nil {
		return err
	}
	return rawconn_control(rawcon, ctrl)
}

func rawconn_control(con syscall.RawConn, ctrl func(fd uintptr) error) (ctrl_err error) {

	err := con.Control(func(fd uintptr) {
		ctrl_err = ctrl(fd)
	})
	if err != nil {
		return err
	}
	return
}

func socket_configure(fd uintptr) (err error) {

	err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	if err != nil {
		return
	}
	err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	if err != nil {
		return
	}
	err = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_PROBE)
	if err != nil {
		return
	}
	return
}

func error_errno(err error) (errno syscall.Errno, ok bool) {

	switch err2 := err.(type) {
	case *net.OpError:
		return error_errno(err2.Err)
	case *os.SyscallError:
		return error_errno(err2.Err)
	case syscall.Errno:
		return err2, true
	}
	log.trace("error_errno: unrecognized: (%T) %v", err, err)
	return
}
