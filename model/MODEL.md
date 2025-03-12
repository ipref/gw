## A working IPREF gateway model

originally written on 1/14/2025

The primary function of IPREF gateways is to perform necessary transformations that will allow IP packets to traverse different address spaces. The transformations work the same way whether traversing address spaces within the same protocol, such as NAT traversal, or cross protocol, such as IPv4/IPv6. In the latter case, there is an additional step of repackaging packets between IPv4 and IPv6 formats which does not affect the transformations themselves.

This model shows how the transformations work in the case of IPv4 NAT traversal.

### Minimum network setup

The minimum setup requires four nodes: two IPREF gateways and two hosts. It represents two sites connected over the Internet. The Internet is simulated by a direct connection between the gateways.

The entire model network is implemented using VirtualBox VMs. In this way, the exercise can be performed on a single machine. It can be any machine that supports VirtualBox. VirtualBox has a feature allowing to create virtual networks contained entirely within the VirtualBox. This feature will NOT be used. There is a reason for that. Instead, the host's network will be used with bridge adapters for all four VMs.

### Network diagram

                       host network 192.168.10.0/24

                      ┌───────┐.97     .98┌───────┐
      Site 7          │  gw7  ┝━━━━━━━━━━━┥  gw8  │          Site 8
                      └───┬───┘           └───┬───┘
                          │.1                 │.2
      192.168.97.0/24     │                   │     192.168.98.0/24
        ━━━━━━━━━━━┯━━━━━━┷━                 ━┷━━━━━━━┯━━━━━━━━━━━
                   │.11                               │.22
              ┌────┴────┐                        ┌────┴────┐
              │ host711 │                        │ host822 │
              └─────────┘                        └─────────┘


### Conventions

It is very confusing for humans to follow the transformations performed by the gateways. To make it a little easier, certain conventions are used:

- There are two sites: site 7 and site 8
- Odd numbers generally refer to site 7
- Even numbers generally refer to site 8
- The host network is assumed to be 192.168.10.0/24

### Start the model network

Start VMs

    [on the host]

    vboxmanage startvm --type headless gw7
    vboxmanage startvm --type headless gw8
    vboxmanage startvm --type headless host711
    vboxmanage startvm --type headless host822

Setup four terminals dedicated for the four VMs, then ssh to each:

    ssh tom@192.168.10.97
    ssh tom@192.168.10.98
    ssh -J tom@192.168.10.97 tom@192.168.97.11
    ssh -J tom@192.168.10.98 tom@192.168.98.22

Start IPREF gateways

    [on gw7 and gw8]

    sudo su -
    systemctl start ipref-gw.service

The model is now operational. The hosts attached to IPREF gateways are unaware of any transformations performed by the IPREF gateways.

### Simple tests

The objective of the model was to verify that the IPREF gateways make it possible to traverse different address spaces. Mere ability to ssh to hosts in different spaces verifies that. There is much more work needed to make IPREF gateways commercially viable but this exercise validated the approach.

    [on host711]

    ping host822
    traceroute host822
    ssh host822
    scp some.file tom@host822:.
    iperf3 -s
    iperf3 -c host822
    iperf3 -u -c host822

    [on host822]

    ping host711
    traceroute host711
    ssh host711
    scp some.file tom@host711:.
    iperf3 -s
    iperf3 -c host711
    iperf3 -u -c host711

Use tcpdump to see how addresses are transformed at each stage.

## VM setup

The model was written for the RHEL 9 Linux distribution. Other RHEL-like distros, such as alma or rocky, should work without adjustments.

This model uses a statically linked IPREF gateway binary downloadable from assets of release 0.0.2:

	gw-20241219-022526-adeef19

### VM setup for IPREF gateways gw7 and gw8

#### Machine configuration

* disk:	16G
* memory: 2.5G
* cpus:	4
* eth: 2 interfaces, both configured as bridge adapters

#### Installation

* os: RHEL 9 or alma/rocky 9
* base: minimal install
* selinux: permissive
* enp0s3: 192.168.10.97/24	`-- on gw7`
* enp0s3: 192.168.10.98/24	`-- on gw8`
* enp0s8: leave unconfigured
* user account: tom (wheel)

#### Gateway configuration

Setup forwarding through the gateway. Adjust mac addresses and DNS server addresses as needed.

    [as root]

    nmcli c                     -- list configurations
    nmcli c delete enp0s8       -- remove existing configuration

    nmcli c add type ethernet con-name enp0s8 ifname enp0s8 mac 08:00:27:ec:94:fd \
			ip4 192.168.97.1/24 \	-- on gw7
			ip4 192.168.98.2/24 \	-- on gw8
			ipv4.dns 192.168.10.8 ipv4.dns-search example.com \
			ipv6.method disable

    vi /etc/sysctl.d/10-enable-forwarding.conf
        net.ipv4.ip_forward=1

    sysctl -p /etc/sysctl.d/10-enable-forwarding.conf

Disable firewalld to allow ssh through the gateway to attached hosts.

Opening port 22 is insufficient since the firewall blocks forwarding between the interfaces. Newer versions of firewalld might allow it in which case the below might not be necessary.

    systemctl stop firewalld.service
    systemctl disable firewalld.service
    systemctl mask firewalld.service

Filter out ipref packets.

The IPREF gateway binary uses an older version of bpf filter which leaks packets into the host. These packets must be filtered out.

    vi /etc/nftables/ipref.nft

        flush ruleset

        table ip ipref {
            chain PREROUTING {
                type filter hook prerouting priority mangle; policy accept;

                iifname "enp0s3" udp sport 1045 drop
                iifname "enp0s3" udp dport 1045 drop
            }
        }

    vi /etc/sysconfig/nftables.conf
        include "/etc/nftables/ipref.nft"

    systemctl start nftables.service
    systemctl enable nftables.service

#### Ipref configuration

  We use a single, statically linked binary to run ipref gateway. The configuration keeps the binary in a standard user's subdirectory. This helps testing different binaries during development. This setup uses the binary ipref-gw-20241219-022526-adeef19 included in the 0.0.2 release.

	[as tom]

	mkdir -p ~/ipref-gw
	cd ~/ipref-gw
	curl -sLO https://github.com/ipref/gw/releases/download/0.0.2/ipref-gw-20241219-022526-adeef19

Set up working directory for the gateway binary.

	[as root]
	
	mkdir -p /var/lib/ipref-gw

Set up special hosts file for the gateway binary. Notice that what appears as a comment is not a comment. It is done for compatibility with standard /etc/hosts file. The gateway interprets the entire line.

	vi /usr/lib/ipref-gw/hosts	-- on gw7
	
	    192.168.97.11   host711    #= pub 192.168.10.97 + 10711
	    10.248.22.222   host822    #= ext 192.168.10.98 + 20822
	
	vi /var/lib/ipref-gw/hosts	-- on gw8

	    192.168.98.22   host822    #= pub 192.168.10.98 + 20822
	    10.255.11.111   host711    #= ext 192.168.10.97 + 10711

Set up systemd service for the gateway binary

	vi /etc/systemd/system/ipref-gw.service
	
	    [Unit]
	    Description=ipref ipref-gw
	    After=network-online.target
	    Wants=network-online.target
	
	    [Service]
	    Environment=SERVICE=ipref-gw
	
	    ExecStartPre=/bin/bash -eu -c ' \
	        mkdir -p /var/lib/$SERVICE; \
	        ln -snf $(ls ~tom/ipref-gw/ipref-gw-* | tail -1) /var/lib/$SERVICE/$SERVICE; \
            '
	
	    ExecStart=/usr/bin/bash -eux -c ' \
	        exec $(realpath /var/lib/$SERVICE/$SERVICE) \
	            -gateway 192.168.10.97 \		-- on gw7
	            -gateway 192.168.10.98 \		-- on gw8
	            -hosts /var/lib/$SERVICE/hosts \
	            -data /var/lib/$SERVICE \
	            '
	
	    [Install]
	    WantedBy=multi-user.target

#### Selinux

The gateway should work with selinux enforcing but frequent changes to selinux policies sometimes require small tweaks. For first time testing, it's best to set selinux to permissive mode to avoid a possibility of interference.

	setenforce 0

### VM setup for hosts host711 and host822

#### Machine configuration

* disk:	16G
* memory: 1.5G
* cpus:	2
* eth: 1 interface configured as a bridge adapter

#### Installation

* os: RHEL 9 or alma/rocky 9
* base: minimal install
* selinux: enforcing
* enp0s3: 192.168.97.11/24	`-- on host711`
* enp0s3: 192.168.98.22/24	`-- on host822`
* user account: tom (wheel)

#### Host configuration

Regular hosts are unaware of IPREF transformation. Remote destinations appear as hosts on a local private network.

Set up /etc/hosts

	[as root]
	
	vi /etc/hosts		-- on host711
	
    127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4
    ::1         localhost localhost.localdomain localhost6 localhost6.localdomain6
    10.248.22.222   host822
    
    vi /etc/hosts		-- on host822
    
    127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4
    ::1         localhost localhost.localdomain localhost6 localhost6.localdomain6
    10.255.11.111   host711

Allow iperf3 through the firewall

    firewall-cmd --add-port 5201/tcp
    firewall-cmd --add-port 5201/udp
    firewall-cmd --runtime-to-permanent

// vim: expandtab
