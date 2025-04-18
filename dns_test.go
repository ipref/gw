/* Copyright (c) 2018-2020 Waldemar Augustyn */

package main

import (
	"strings"
	"testing"
)

func TestParseHosts(t *testing.T) {

	hosts := `
127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4
::1         localhost localhost.localdomain localhost6 localhost6.localdomain6

ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

# IPREF mappings for taro

192.168.84.97   taro        #= pub + 7000
192.168.73.127  taro-7      #= pub + 7107
10.254.8.88     tikopia     #= ext 192.168.84.98 + 8000
10.254.22.202   tikopia-8   #= ext 192.168.84.98 + 8028

# test records

  19.37.2 example.com another.example.com #= pub
179.187.127.252 hoeta oset3 #= ext 198.247.163.149 + abc-123-7DFE-007

179.40.12.22 hosta oset4 #= ext 198.27.43.199 + abc-127
179.41.7.23 hoata oset5 #=ext 198.29.10.15 + abc-145
    howta oset7 #= ext 198.2.3.9 + abc-158
179.43.12.25 hoewa oset8 #= pub
179.44.12.24  #= pub 192.168.163.14
179.45.12.23  #= pub + 1234,341,900
179.46.12.22  #= + 1234,341,97
179.47.12.21  #= public 192.168.163.15+255.184.7.17.28.118.18.53.28.11.235.108
179.48.12.20 hoewa oset8#=pub 192.168.163.16
179.49.1.42 hoetg oset9 #= extern 198.247.163.149 + abc-123-7DFE-007
179.50.27.52 hoetq oset1#= ext 198.27.16.19 + abc-12323 8294
179.51.7.82     asfhos#= ext 198.47.63.14 + abc-123-7DFEG-690
179.52.67.62     asfhos#= ext + abc-123-7D-a444
179.53.37.52     asfhos#= ext 198.47.63.17
179.54.37.53     asfhos#= ext 198.47.63.19 +
179.55.37.54     asfhos#= ext 0.0.0.0 + ae45-221
179.56.37.55     asfhos#= ext 255.255.255.255 + ae45-221
179.57.38.56    #= pub 32.28.1.5 28.1.33.5
179.58.39.57    #=
179.59.40.58    #= ext 32.29.2.6 + afe07 + 127e
`
	res := map[IP32]AddrRec{
		0xc0a85461: {0, 0xc0a85461, 0, Ref{0, 0x7000}},          // 192.168.84.97  = + 7000
		0xc0a8497f: {0, 0xc0a8497f, 0, Ref{0, 0x7107}},          // 192.168.73.127 = + 7107
		0x0afe0858: {0x0afe0858, 0, 0xc0a85462, Ref{0, 0x8000}}, // 10.254.8.88    = 192.168.84.98 + 8000
		0x0afe16ca: {0x0afe16ca, 0, 0xc0a85462, Ref{0, 0x8028}}, // 10.254.22.202  = 192.168.84.98 + 8028

		0xb3bb7ffc: {0xb3bb7ffc, 0, 0xc6f7a395, Ref{0, 0xabc1237dfe007}}, // 179.187.127.252 = 198.247.163.149 + abc1237dfe007
		0xb3280c16: {0xb3280c16, 0, 0xc61b2bc7, Ref{0, 0xabc127}},        // 179.40.12.22    = 198.27.43.199   + abc127
		0xb3290717: {0xb3290717, 0, 0xc61d0a0f, Ref{0, 0xabc145}},        // 179.41.7.23      = 198.29.10.15    + abc145

		0xb32b0c19: {0, 0xb32b0c19, 0, Ref{0, 0}},          // 179.43.12.25 =
		0xb32c0c18: {0, 0xb32c0c18, 0xc0a8a30e, Ref{0, 0}}, // 179.44.12.24 = 192.168.163.14
		0xb32d0c17: {0, 0xb32d0c17, 0, Ref{0, 0x4992900c}}, // 179.45.12.23 =  + 1234,341,900

		0xb32f0c15: {0, 0xb32f0c15, 0xc0a8a30f, Ref{0xffb80711, 0x1c7612351c0beb6c}}, // 179.47.12.21 = 192.168.163.15 + 255.184.7.17.28.118.18.53.28.11.235.108
		0xb3300c14: {0, 0xb3300c14, 0xc0a8a310, Ref{0, 0}},                           // 179.48.12.20 = 192.168.163.16
	}
	log.set(INFO, false)
	arecs := parse_hosts_file("/etc/hosts", strings.NewReader(hosts))
	for key, val := range arecs {
		rec, ok := res[key]
		if !ok {
			t.Errorf("unexpected key: %08x", key)
			continue
		}
		if rec != val {
			t.Errorf("mismatched values: key: %08x   val: {%x %x %x {%x, %x}}",
				key, val.EA, val.IP, val.GW, val.Ref.h, val.Ref.l)
		}
	}
	if len(res) != len(arecs) {
		t.Errorf("mismatched num of results: %v != %v", len(arecs), len(res))
	}

	/* Also the following errors should print to stderr during successful test run

	   ERR  parse hosts: /etc/hosts(17): invalid IP address: 19.37.2
	   ERR  parse hosts: /etc/hosts(22): invalid IP address: howta
	   ERR  parse hosts: /etc/hosts(26): missing IPREF record type
	   ERR  parse hosts: /etc/hosts(29): invalid IPREF record type: extern
	   ERR  parse hosts: /etc/hosts(30): invalid reference:  abc-12323 8294
	   ERR  parse hosts: /etc/hosts(31): invalid reference: abc-123-7DFEG-690: invalid format
	   ERR  parse hosts: /etc/hosts(32): missing gw address
	   ERR  parse hosts: /etc/hosts(33): missing reference
	   ERR  parse hosts: /etc/hosts(34): missing reference
	   ERR  parse hosts: /etc/hosts(35): non-unicast gw: 0.0.0.0
	   ERR  parse hosts: /etc/hosts(36): non-unicast gw: 255.255.255.255
	   ERR  parse hosts: /etc/hosts(37): invalid gw address: 32.28.1.5 28.1.33.5
	   ERR  parse hosts: /etc/hosts(38): missing IPREF record type
	   ERR  parse hosts: /etc/hosts(39): invalid reference:  afe07  +  127e
	*/
}
