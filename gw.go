/* Copyright (c) 2018-2021 Waldemar Augustyn */

package main

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"syscall"
	. "github.com/ipref/common"
	"golang.org/x/sys/unix"
)

var recv_gw chan *PktBuf
var send_gw chan *PktBuf

const (
	GW_RECV_OFF = TUN_HDR_LEN +
		(IPv6_HDR_MIN_LEN + IPv6_FRAG_HDR_LEN) +
		(IPREF_HDR_MAX_LEN - IPREF_HDR_MIN_LEN) -
		IPREF_HDR_MIN_LEN
)

type RemoteGw struct {
	addr IP
}

type RemoteGwConn struct {
	lock sync.Mutex
	key RemoteGw // can't change
	con *net.UDPConn
	sport uint16 // can't change
	dport uint16 // can't change
	mtu int // can change
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

// Will still lock the individual rcons regardless.
func (rgws *RemoteGwTable) gc(lock bool) {

	if cli.maxrgws < 1 {
		return
	}
	if lock {
		rgws.lock.Lock()
		defer rgws.lock.Unlock()
	}
	for rgws.nrcons > cli.maxrgws {
		rcon := rgws.least_recent
		rcon.lock.Lock()
		rcon.next.lock.Lock()
		rcon.next.prev = nil
		rcon.next.lock.Unlock()
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

func (rgws *RemoteGwTable) active_rcon(rcon *RemoteGwConn, lock bool) {

	if lock {
		rcon.lock.Lock()
		defer rcon.lock.Unlock()
	}
	if rcon.removed || rcon.next == nil {
		return
	}
	if lock {
		rgws.lock.Lock()
		defer rgws.lock.Unlock()
	}

	// remove from list
	if rcon.prev == nil {
		rgws.least_recent = rcon.next
	} else {
		rcon.prev.lock.Lock()
		rcon.prev.next = rcon.next
		rcon.prev.lock.Unlock()
	}
	rcon.next.lock.Lock()
	rcon.next.prev = rcon.prev
	rcon.next.lock.Unlock()

	// add to end of list
	rcon.prev = rgws.most_recent
	rcon.next = nil
	rgws.most_recent = rcon
	rcon.prev.lock.Lock()
	rcon.prev.next = rcon
	rcon.prev.lock.Unlock()
}

func (rgws *RemoteGwTable) remove_rcon(rcon *RemoteGwConn, lock bool) {

	if lock {
		rcon.lock.Lock()
		defer rcon.lock.Unlock()
	}
	if rcon.removed {
		return
	}
	rcon.removed = true
	rcon.con.Close() // ignore error
	if lock {
		rgws.lock.Lock()
		defer rgws.lock.Unlock()
	}
	rgws.nrcons--
	if rcon.prev == nil {
		rgws.least_recent = rcon.next
	} else {
		rcon.prev.lock.Lock()
		rcon.prev.next = rcon.next
		rcon.prev.lock.Unlock()
	}
	if rcon.next == nil {
		rgws.most_recent = rcon.prev
	} else {
		rcon.next.lock.Lock()
		rcon.next.prev = rcon.prev
		rcon.next.lock.Unlock()
	}
	rcon.prev = nil
	rcon.next = nil
	delete(rgws.rcons, rcon.key)
}

// Use dport = 0 to get the connection regardless of port, or use the default
// port when creating a new connection.
func (rgws *RemoteGwTable) get_rcon(daddr IP, dport uint16,
	lock bool) (*RemoteGwConn, error) {

	// look for existing rcon
	key := RemoteGw{daddr}
	if lock {
		rgws.lock.Lock()
		defer rgws.lock.Unlock()
	}
	rcon, exists := rgws.rcons[key]
	if exists {
		rcon.lock.Lock()
		if rcon.removed {
			panic("unexpected")
		}
		if dport == 0 || rcon.dport == dport {
			rgws.active_rcon(rcon, false)
			rcon.lock.Unlock()
			return rcon, nil
		} else {
			log.trace("gw:      updating remote gateway port %v -> %v", rcon.dport, dport)
			rgws.remove_rcon(rcon, false)
			rcon.lock.Unlock()
		}
	}

	// open connection
	saddr := cli.gw_ip
	sport := uint16(cli.gw_port)
	if dport == 0 {
		dport = uint16(cli.rgw_port)
	}
	var dialer net.Dialer
	dialer.LocalAddr = &net.UDPAddr{saddr.AsSlice(), int(sport), ""}
	dialer.Control = func(network, address string, c syscall.RawConn) error {
		return rawconn_control(c, socket_configure)
	}
	c, err := dialer.Dial(gw_proto(), (&net.UDPAddr{daddr.AsSlice(), int(dport), ""}).String())
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
	rcon.sport = sport
	rcon.dport = dport
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
		rcon.prev.lock.Lock()
		rcon.prev.next = rcon
		rcon.prev.lock.Unlock()
	}
	rgws.rcons[key] = rcon
	rgws.nrcons++

	on_recv := func(IP, uint16) {
		rgws.active_rcon(rcon, true)
	}
	on_emsgsize := func() {
		rcon.update_mtu()
	}
	on_close := func() {
		rgws.remove_rcon(rcon, true)
	}
	go gw_receiver(rcon.con, on_recv, on_emsgsize, on_close)
	rgws.gc(false)
	return rcon, nil
}

func (rgws *RemoteGwTable) set_dport(daddr IP, dport uint16, lock bool) {

	_, err := rgws.get_rcon(daddr, dport, lock)
	if err != nil {
		log.err("gw:      error connecting to remote gateway: %v", err)
	}
}

func (rcon *RemoteGwConn) update_mtu() {

	mtu, err := udpconn_getmtu(rcon.con)
	if err != nil {
		log.trace("gw:      get mtu failed: %v", err)
		return // silently ignore
	}
	rcon.lock.Lock()
	log.trace("gw:      update remote connection mtu %v -> %v", rcon.mtu, mtu)
	rcon.mtu = mtu
	rcon.lock.Unlock()
}

func (rcon *RemoteGwConn) get_mtu() int {

	rcon.lock.Lock()
	defer rcon.lock.Unlock()
	return rcon.mtu
}

func gw_sender(rgws *RemoteGwTable) {

	for pb := range send_gw {

		switch pb.typ {

		case PKT_V1:

			log.err("gw out:  unknown v1 packet data/end(%v/%v), dropping", pb.data, len(pb.pkt))
			retbuf <- pb
			continue

		case PKT_IPREF:

		next_fragment:
			if cli.debug["gw"] {
				log.debug("gw out:  %v", pb.pp_pkt())
			}

			if cli.trace {
				pb.pp_net("gw out:  ")
				pb.pp_tran("gw out:  ")
				// pb.pp_raw("gw out:  ")
			}

		again:
			if !pb.ipref_ok() {
				log.err("gw out:  invalid ipref packet, dropping")
				retbuf <- pb
				continue
			}
			src_ip := IPFromSlice(pb.ipref_sref_ip())
			dst_ip := IPFromSlice(pb.ipref_dref_ip())
			if src_ip != cli.gw_ip {
				log.err("gw out:  src(%v) is not gateway, packet dropped", src_ip)
				retbuf <- pb
				continue
			}
			rcon, err := rgws.get_rcon(dst_ip, 0, true)
			if err != nil {
				log.err("gw out:  error creating remote connection, packet dropped: %v", err)
				retbuf <- pb
				continue
			}
			mtu := rcon.get_mtu()
			l5_mtu := mtu - UDP_HDR_LEN
			if dst_ip.Is4() {
				l5_mtu -= IPv4_HDR_MIN_LEN
			} else {
				l5_mtu -= IPv6_HDR_MIN_LEN
			}
			if l5_mtu <= 0 || l5_mtu >> 16 != 0 {
				log.err("gw out:  bad mtu, dropping packet")
				retbuf <- pb
				continue
			}
			sent, trimmed, orig_mf, status := ipref_frag_in_place(pb, l5_mtu)
			switch status {
			case IPREF_FRAG_IN_PLACE_NOT_NEEDED:
			case IPREF_FRAG_IN_PLACE_SUCCESS:
				log.trace("gw out:  fragmenting (%v + %v)", sent, trimmed)
			case IPREF_FRAG_IN_PLACE_DF:
				log.trace("gw out:  needs fragmentation but DF set, sending icmp")
				pb.icmp.typ = IPREF_ICMP_DEST_UNREACH
				pb.icmp.code = IPREF_ICMP_FRAG_NEEDED
				pb.icmp.mtu = uint16(l5_mtu)
				pb.icmp.ours = true
				icmpreq <- pb
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
				rgws.remove_rcon(rcon, true)
				retbuf <- pb
				continue
			}
			if wlen != pb.len() {
				log.err("gw out:  write failed")
				rgws.remove_rcon(rcon, true)
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

func gw_receiver(con *net.UDPConn,
	on_recv func(IP, uint16), on_emsgsize func(), on_close func()) {

	if cli.devmode {
		return
	}

	for {

		pb := <-getbuf
		pb.typ = PKT_IPREF
		pb.data = GW_RECV_OFF

		rlen, addr, err := con.ReadFromUDP(pb.pkt[pb.data:])
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
		if cli.debug["gw"] {
			log.debug("gw in:   src IP: %v  rcvlen(%v)", addr, rlen)
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
		src_ip := IPFromSlice(addr.IP)
		src_port := uint16(addr.Port)
		pb.tail = pb.data + rlen
		if !pb.ipref_ok() {
			log.err("gw in:   invalid ipref packet, dropping")
			retbuf <- pb
			continue
		}
		sref_ip := IPFromSlice(pb.ipref_sref_ip())
		dref_ip := IPFromSlice(pb.ipref_dref_ip())
		if sref_ip.IsZeroAddr() && sref_ip.Ver() == src_ip.Ver() {
			copy(pb.ipref_sref_ip(), src_ip.AsSlice())
		}
		if sref_ip != src_ip {
			log.err("gw in:   ipref header src(%v) does not match ip header src(%v), dropping",
				sref_ip, src_ip)
			retbuf <- pb
			continue
		}
		if dref_ip != cli.gw_ip {
			log.err("gw in:   ipref header dst(%v) does not match gateway ip, dropping", dref_ip)
			retbuf <- pb
			continue
		}
		if on_recv != nil {
			on_recv(src_ip, src_port)
		}

		if cli.debug["gw"] {
			log.debug("gw in:   %v", pb.pp_pkt())
		}

		if cli.trace {
			pb.pp_net("gw in:   ")
			pb.pp_tran("gw in:   ")
			// pb.pp_raw("gw in:   ")
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

		var config net.ListenConfig
		config.Control = func(network, address string, c syscall.RawConn) error {
			return rawconn_control(c, socket_configure)
		}
		packet_con, err := config.ListenPacket(context.Background(), gw_proto(),
			(&net.UDPAddr{cli.gw_ip.AsSlice(), cli.gw_port, ""}).String())
		if err != nil {
			log.fatal("gw:      cannot listen on UDP: %v", err)
		}
		var ok bool
		con, ok = packet_con.(*net.UDPConn)
		if !ok {
			log.fatal("gw:      listen UDP: expected net.UDPConn")
		}

		log.info("gw:      gateway %v %v mtu(%v) %v pkt buffers",
			cli.gw_ip, cli.ifc.Name, cli.ifc.MTU, cli.maxbuf)
	}

	rgws := new_rgw_table()
	go gw_sender(&rgws)
	on_recv := func(saddr IP, sport uint16) {
		rgws.set_dport(saddr, sport, true)
	}
	on_emsgsize := func() {
		// we should only get EMSGSIZE on the client sockets
		log.fatal("gw in:   EMSGSIZE on server socket")
	}
	on_close := func() {
		log.fatal("gw in:   server socket closed")
	}
	go gw_receiver(con, on_recv, on_emsgsize, on_close)
}

func gw_proto() string {
	if cli.gw_ip.Is4() {
		return "udp4"
	} else {
		return "udp6"
	}
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
