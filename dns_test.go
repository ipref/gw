/* Copyright (c) 2018-2020 Waldemar Augustyn */

package main

import (
	. "github.com/ipref/common"
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

192.168.84.97   taro        #= pub + 0-7000
192.168.73.127  taro-7      #= pub + 0-7107
10.254.8.88     tikopia     #= ext 192.168.84.98 + 0-8000
10.254.22.202   tikopia-8   #= ext 192.168.84.98 + 0-8028

# test records

  19.37.2 example.com another.example.com #= pub
179.187.127.252 hoeta oset3 #= ext 198.247.163.149 + abc-123-7DFE-007

179.40.12.22 hosta oset4 #= ext 198.27.43.199 + abc-127
179.41.7.23 hoata oset5 #=ext 198.29.10.15 + abc-145
    howta oset7 #= ext 198.2.3.9 + abc-158
179.43.12.25 hoewa oset8 #= pub
179.44.12.24  #= pub 192.168.163.14
179.48.12.20 hoewa oset8#=pub 192.168.163.16
179.49.1.42 hoetg oset9 #= extern 198.247.163.149 + abc-123-7DFE-007
179.50.27.52 hoetq oset1#= ext 198.27.16.19 + abc-12323 8294
179.51.7.82     asfhos#= ext 198.47.63.14 + abc-123-7DFEG-690
179.52.67.62     asfhos#= ext + abc-123-7D-a444
179.53.37.52     asfhos#= ext 198.47.63.17
179.54.37.53     asfhos#= ext 198.47.63.19 +
179.56.37.55     asfhos#= ext 255.255.255.255 + ae45-221
179.57.38.56    #= pub 32.28.1.5 28.1.33.5
179.58.39.57    #=
179.59.40.58    #= ext 32.29.2.6 + afe07 + 0-127e
`

	res := map[IP]AddrRec{
		MustParseIP("192.168.84.97"): {IP{}, MustParseIP("192.168.84.97"), IP{}, Ref{L: 0x7000}},
		MustParseIP("192.168.73.127"): {IP{}, MustParseIP("192.168.73.127"), IP{}, Ref{L: 0x7107}},
		MustParseIP("10.254.8.88"): {MustParseIP("10.254.8.88"), IP{}, MustParseIP("192.168.84.98"), Ref{L: 0x8000}},
		MustParseIP("10.254.22.202"): {MustParseIP("10.254.22.202"), IP{}, MustParseIP("192.168.84.98"), Ref{L: 0x8028}},

		MustParseIP("179.187.127.252"): {MustParseIP("179.187.127.252"), IP{}, MustParseIP("198.247.163.149"), Ref{L: 0xabc01237dfe0007}},
		MustParseIP("179.40.12.22"): {MustParseIP("179.40.12.22"), IP{}, MustParseIP("198.27.43.199"), Ref{L: 0xabc0127}},
		MustParseIP("179.41.7.23"): {MustParseIP("179.41.7.23"), IP{}, MustParseIP("198.29.10.15"), Ref{L: 0xabc0145}},

		MustParseIP("179.43.12.25"): {IP{}, MustParseIP("179.43.12.25"), IP{}, Ref{}},
		MustParseIP("179.44.12.24"): {IP{}, MustParseIP("179.44.12.24"), MustParseIP("192.168.163.14"), Ref{}},

		MustParseIP("179.48.12.20"): {IP{}, MustParseIP("179.48.12.20"), MustParseIP("192.168.163.16"), Ref{}},
	}
	log.set(INFO, false)
	arecs := parse_hosts_file("/etc/hosts", strings.NewReader(hosts))
	for key, val := range arecs {
		rec, ok := res[key]
		if !ok {
			t.Errorf("unexpected key: %v", key)
			continue
		}
		if rec != val {
			t.Errorf("mismatched values: key: %v   val: {%v %v %v %v}",
				key, val.EA, val.IP, val.GW, val.Ref)
		}
	}
	if len(res) != len(arecs) {
		t.Errorf("mismatched num of results: %v != %v", len(arecs), len(res))
	}

	/* Also the following errors should print to stderr during successful test run

		E dns watcher: /etc/hosts(17): invalid IP address: 19.37.2
		E dns watcher: /etc/hosts(22): invalid IP address: howta
		E dns watcher: /etc/hosts(26): invalid IPREF record type: extern
		E dns watcher: /etc/hosts(27): invalid reference:  abc-12323 8294
		E dns watcher: /etc/hosts(28): invalid reference: abc-123-7DFEG-690: invalid format
		E dns watcher: /etc/hosts(29): missing gw address
		E dns watcher: /etc/hosts(30): missing reference
		E dns watcher: /etc/hosts(31): missing reference
		E dns watcher: /etc/hosts(32): non-unicast gw: 255.255.255.255
		E dns watcher: /etc/hosts(33): invalid gw address: 32.28.1.5 28.1.33.5
		E dns watcher: /etc/hosts(34): missing IPREF record type
		E dns watcher: /etc/hosts(35): invalid reference:  afe07  +  0-127e
	*/
}
