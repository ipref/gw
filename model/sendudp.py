#!/usr/bin/env python3

import os
import socket
import sys
import threading

IP_MTU_DISCOVER = 10
IP_PMTUDISC_DONT  = 0 # Never send DF frames.
IP_PMTUDISC_WANT  = 1 # Use per route hints.
IP_PMTUDISC_DO    = 2 # Always DF.
IP_PMTUDISC_PROBE = 3 # Ignore dst pmtu.

PMTUD_BY_NAME = {
    'dont':  IP_PMTUDISC_DONT,
    'want':  IP_PMTUDISC_WANT,
    'do':    IP_PMTUDISC_DO,
    'probe': IP_PMTUDISC_PROBE,
}

PKTBUFLEN = 1 << 17

def main():
    dst = sys.argv[1]
    ipver = sys.argv[2]
    if ipver != '4' and ipver != '6':
        raise ValueError(f'IP version: {ipver!r}')
    if len(sys.argv) > 3:
        port = int(sys.argv[3])
    else:
        port = 5204
    if len(sys.argv) > 4:
        pmtud = sys.argv[4]
    else:
        pmtud = 'want'
    if pmtud not in PMTUD_BY_NAME:
        raise ValueError(f'pmtud: {df!r}')
    pmtud = PMTUD_BY_NAME[pmtud]

    sock = socket.socket(socket.AF_INET if ipver == '4' else socket.AF_INET6,
        socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IP, IP_MTU_DISCOVER, pmtud)
    sock.bind(('0.0.0.0' if ipver == '4' else '::', port))
    sock.connect((dst, port))

    def sendloop():
        while True:
            n = input()
            if n == '':
                n = 8
            else:
                n = int(n)
            try:
                sock.sendall(b'\0' * n)
            except OSError as exc:
                print(f'send error: {exc}')

    def recvloop():
        while True:
            try:
                data, addr = sock.recvfrom(PKTBUFLEN)
            except OSError as exc:
                print(f'recv error: {exc}')
                continue
            extra = ''
            if len(data) == PKTBUFLEN:
                extra = ', truncated'
            print(f'received {len(data)} bytes from {addr}{extra}')

    threading.Thread(target=sendloop).start()
    threading.Thread(target=recvloop).start()

if __name__ == '__main__':
    main()
