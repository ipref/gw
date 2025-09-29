# IPREF Gateway Setup Guide

This guide covers production deployment of an IPREF gateway, including proper network architecture, security considerations, and service publishing.

## Table of Contents
1. [Architecture Overview](#architecture-overview)
2. [Security Model](#security-model)
3. [Client Mode Setup](#client-mode-setup)
4. [Server Mode Setup](#server-mode-setup)
5. [DNS Configuration](#dns-configuration)
6. [Production Deployment](#production-deployment)

## Architecture Overview

### Two-Interface Design

**In production, an IPREF gateway should have two network interfaces:**

1. **Internet-facing interface**: Connects to the Internet, possibly behind NAT
2. **Internal-facing interface**: Drop point for local network traffic

```
Internet
    │
    │ (may be behind NAT)
    │
┌───▼────────────────────┐
│  Internet Interface    │
│  (eth0 / ens0)         │
│                        │
│   IPREF Gateway        │
│   - UDP tunnel (1045)  │
│   - Address mapper     │
│   - Forwarder          │
│                        │
│  Internal Interface    │
│  (eth1 / ens1)         │
└───┬────────────────────┘
    │
    │ **FIREWALL HERE**
    │
┌───▼────────────────────┐
│  Firewall/Router       │
│  - Packet filtering    │
│  - Stateful inspection │
│  - IDS/IPS (optional)  │
└───┬────────────────────┘
    │
    │
┌───▼────────────────────┐
│  Internal Network      │
│  - Workstations        │
│  - Servers             │
│  - IoT devices         │
└────────────────────────┘
```

### Component Roles

- **IPREF Gateway**: Handles address translation and IPREF tunnel encapsulation
- **DNS Agent**: Synchronizes DNS records to inform the mapper of published services
- **CoreDNS + IPREF Plugin**: Provides IPREF-aware DNS resolution for local clients
- **Firewall**: Guards all traffic between gateway and internal network

## Security Model

### ⚠️ Critical: IPREF Gateway is NOT a Firewall

**The IPREF gateway performs address translation and access control through reference allocation, but it is not a security firewall.** You must deploy an independent firewall between the gateway and your internal network.

### Defense in Depth

IPREF provides a defense-in-depth approach:

1. **First layer**: IPREF reference-based access control
   - Only services with allocated references (>1024 recommended) are accessible
   - Large reference space makes port scanning impractical
   - Gateway controls which local addresses can be reached via IPREF

2. **Second layer**: Independent firewall (REQUIRED)
   - Filters all traffic exiting the gateway toward internal network
   - Stateful packet inspection
   - Protection against malformed packets, DoS attacks, etc.
   - Logs and monitors suspicious activity

### Why Two Layers?

This may seem redundant--enabling access in IPREF, then filtering it again at the firewall--but this is a good security practice:

- **Gateway compromise**: If the gateway is compromised, the firewall still protects the internal network
- **Configuration errors**: Mistakes in IPREF configuration are caught by the firewall
- **Attack surface**: Reduces the attack surface of the internal network
- **Audit trail**: Firewall provides logging independent of the gateway

### Recommended Firewall Rules

```bash
# Default policy: deny all from gateway to internal network
iptables -P FORWARD DROP

# Allow established/related connections
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow specific services from gateway to internal network
iptables -A FORWARD -i eth1 -o eth2 -p tcp --dport 80 -j ACCEPT   # HTTP
iptables -A FORWARD -i eth1 -o eth2 -p tcp --dport 443 -j ACCEPT  # HTTPS
iptables -A FORWARD -i eth1 -o eth2 -p tcp --dport 22 -j ACCEPT   # SSH

# Log dropped packets
iptables -A FORWARD -j LOG --log-prefix "IPREF-FW-DROP: "
```

## Client Mode Setup

Client mode allows you to access IPREF network resources without publishing your own services.

### Prerequisites

- Linux 64-bit system (tested on Rocky Linux, RHEL, Debian, Ubuntu)
- 1 vCPU, 2GB RAM minimum
- UDP port 1045 accessible for gateway
- Root or sudo access

### Step 1: Install Binaries

```bash
# Download pre-built binaries
wget https://github.com/ipref/gw/releases/latest/download/ipref-gw
wget https://github.com/ipref/gw/releases/latest/download/ipref-dns-agent
wget https://github.com/ipref/gw/releases/latest/download/ipref-coredns

chmod +x ipref-*
sudo mv ipref-* /usr/local/bin/
```

### Step 2: Create Required Directories

```bash
sudo mkdir -p /var/lib/ipref /run/ipref /etc/coredns
```

### Step 3: Configure CoreDNS

Create `/etc/coredns/Corefile`:

```
. {
    ipref {
        upstream 8.8.8.8
        ea-ipver 4
        gw-ipver 4
        mapper /run/ipref/mapper.sock
    }
    forward . 8.8.8.8 8.8.4.4
    log
}
```

**Configuration options:**
- `upstream`: DNS server to query for AA records (IPREF addresses)
- `ea-ipver`: IP version for encoded addresses (local network) - 4 or 6
- `gw-ipver`: IP version for gateway-to-gateway tunnel - 4 or 6
- `mapper`: Unix socket path for communication with the gateway
- `forward`: Fallback DNS for non-IPREF queries

### Step 4: Start Services

#### Terminal 1: Start Gateway

```bash
sudo ipref-gw \
    -data /var/lib/ipref \
    -gateway-bind 0.0.0.0 \
    -gateway-pub 0.0.0.0 \
    -encode-net 10.240.0.0/12 \
    -mapper-socket /run/ipref/mapper.sock
```

**Configuration options:**
- `-data`: Directory for mapper database (will be created if doesn't exist)
- `-gateway-bind`: Interface to listen on for UDP tunnel (0.0.0.0 = all interfaces)
- `-gateway-pub`: Public IP address (use 0.0.0.0 for client-only mode)
- `-encode-net`: Local address range for encoding remote IPREF addresses
- `-mapper-socket`: Unix socket path for IPC with DNS components

#### Terminal 2: Start DNS Agent

```bash
sudo ipref-dns-agent \
    -ea-ipver 4 \
    -gw-ipver 4 \
    -m unix:///run/ipref/mapper.sock \
    -t 60
```

**Configuration options:**
- `-ea-ipver`: IP version for encoded addresses
- `-gw-ipver`: IP version for gateway tunnel
- `-m`: Mapper socket path
- `-t`: Update interval in minutes

#### Terminal 3: Start CoreDNS

```bash
sudo ipref-coredns -conf /etc/coredns/Corefile
```

### Step 5: Configure DNS Resolution

```bash
# Temporarily set DNS resolver (will reset on reboot)
echo "nameserver 127.0.0.1" | sudo tee /etc/resolv.conf

# For systemd-resolved systems:
sudo mkdir -p /etc/systemd/resolved.conf.d
echo -e "[Resolve]\nDNS=127.0.0.1\nDomains=~." | sudo tee /etc/systemd/resolved.conf.d/ipref.conf
sudo systemctl restart systemd-resolved
```

### Step 6: Test Connectivity

```bash
# Test DNS resolution
dig k41.nexsand.us
# Should return an address in 10.240.0.0/12 range

# Test connectivity
ping k41.nexsand.us

# Test web access
curl http://k41.nexsand.us
```

### Demo Hosts

| Host | Location | Purpose |
|------|----------|---------|
| k41.nexsand.us | United States | General testing |
| m41.nexsand.ca | Canada | Latency comparison |
| o61.nexsand.uk | United Kingdom | International routing |

## Server Mode Setup

Server mode allows you to publish services from your private network to the IPREF network without port forwarding.

### Network Architecture

```
Internet                           Private Network (10.0.0.0/24)
    │                                      │
    ├── UDP/1045 (IPREF tunnel)            │
    │   │                                  │
    │   ▼                                  │
┌───┴────────────────────┐                 │
│  eth0: 203.0.113.5     │                 │
│  (Internet Interface)  │                 │
│                        │                 │
│   IPREF Gateway        │                 │
│   ipref-gw             │                 │
│   dns-agent            │                 │
│   coredns              │                 │
│                        │                 │
│  eth1: 10.0.0.1        │                 │
│  (Internal Interface)  │                 │
└───┬────────────────────┘                 │
    │                                      │
    │ **PLACE FIREWALL HERE**              │
    │                                      │
┌───▼──────────────────────────────────────┤
│  Firewall: 10.0.0.254                    │
│  - iptables / nftables                   │
│  - Packet filtering                      │
│  - IDS (optional)                        │
└───┬──────────────────────────────────────┘
    │
┌───▼──────────────────────────────────────┐
│  Internal Network                        │
│  - Web server: 10.0.0.10 (host11)        │
│  - SSH server: 10.0.0.22 (host22)        │
└──────────────────────────────────────────┘
```

### Prerequisites

In addition to client mode requirements:
- A public domain name (e.g., `example.com`)
- Access to configure DNS records
- Services running on internal network

### Step 1: Configure Gateway with Public IP

Replace `0.0.0.0` in the `-gateway-pub` parameter with your public IP address:

```bash
sudo ipref-gw \
    -data /var/lib/ipref \
    -gateway-bind 0.0.0.0 \
    -gateway-pub 203.0.113.5 \
    -encode-net 10.240.0.0/12 \
    -mapper-socket /run/ipref/mapper.sock
```

**Important**: Use your actual public IP address, not `0.0.0.0`. If behind NAT, use the external NAT IP address.

### Step 2: Configure Internal DNS Zone

Create `/etc/coredns/db.internal` with your local network addresses:

```dns
$ORIGIN internal.
$TTL 120

internal.  IN  SOA  localhost. admin.internal. ( 1 120 120 120 120 )
internal.  IN  NS   localhost.

gw.internal.       IN  A  10.0.0.1     ; Gateway internal interface
host11.internal.   IN  A  10.0.0.10    ; Web server
host22.internal.   IN  A  10.0.0.22    ; SSH server
```

### Step 3: Update CoreDNS Configuration

Update `/etc/coredns/Corefile` to serve the internal zone:

```
internal {
    file /etc/coredns/db.internal
    transfer {
        to *
    }
    log
}

. {
    ipref {
        upstream 8.8.8.8
        ea-ipver 4
        gw-ipver 4
        mapper /run/ipref/mapper.sock
    }
    forward . 8.8.8.8 8.8.4.4
    log
}
```

### Step 4: Configure DNS Agent

Update the DNS agent to sync between internal and external DNS:

```bash
sudo ipref-dns-agent \
    -ea-ipver 4 \
    -gw-ipver 4 \
    -m unix:///run/ipref/mapper.sock \
    -t 60 \
    internal:example.com:ns1.example.com,ns2.example.com
```

**Configuration format**: `internal_tld:external_domain:nameserver1,nameserver2`

This tells the agent to:
- Query `*.internal` records from local CoreDNS
- Query `*.example.com` records from `ns1.example.com` and `ns2.example.com`
- Match hostnames and create mappings

### Step 5: Configure External DNS (Public Zone)

Add AA records to your public DNS zone for `example.com`:

```dns
$ORIGIN example.com.
$TTL 3600

example.com.  IN  SOA  ns1.example.com. admin.example.com. ( 2024123101 7200 3600 1209600 3600 )
example.com.  IN  NS   ns1
example.com.  IN  NS   ns2

; Gateway A record (required)
gw.example.com.      IN  A    203.0.113.5

; AA records for IPREF addresses
gw.example.com.      IN  TXT  "AA gw.example.com + 1"
host11.example.com.  IN  TXT  "AA gw.example.com + 1025"
host22.example.com.  IN  TXT  "AA gw.example.com + 1026"
```

**AA Record Format**: `"AA <gateway_fqdn> + <reference>"`
- Reference 1 is reserved for the gateway itself
- Use references ≥1025 for services (>1024 recommended for security)
- References can use hyphens to separate 16-bit groups: `"AA gw.example.com + 1-22"`

### Step 6: Configure Firewall

**CRITICAL**: Place a firewall between the gateway and internal network:

```bash
# Example using iptables

# Allow forwarding from eth1 (gateway) to eth2 (internal)
# But only for specific services

# HTTP to web server
iptables -A FORWARD -i eth1 -d 10.0.0.10 -p tcp --dport 80 -j ACCEPT

# HTTPS to web server
iptables -A FORWARD -i eth1 -d 10.0.0.10 -p tcp --dport 443 -j ACCEPT

# SSH to SSH server
iptables -A FORWARD -i eth1 -d 10.0.0.22 -p tcp --dport 22 -j ACCEPT

# Allow return traffic
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# Drop everything else
iptables -A FORWARD -i eth1 -j DROP

# Log dropped packets
iptables -A FORWARD -j LOG --log-prefix "IPREF-DROP: "
```

### Step 7: Verify Configuration

```bash
# Check that mapper database was created
ls -lh /var/lib/ipref/mapper_ea4_gw4.db

# Check gateway logs for mapping activity
sudo journalctl -u ipref-gateway | grep "save\|restore"

# Test from external client
dig host11.example.com
ping host11.example.com
curl http://host11.example.com
```

## DNS Configuration

### Hostname Matching

The DNS agent creates mappings by matching hostnames between internal and external DNS:

```
Internal DNS (*.internal)    External DNS (*.example.com)
-------------------------    ----------------------------
host11.internal  10.0.0.10   host11.example.com  AA gw.example.com + 1025
host22.internal  10.0.0.22   host22.example.com  AA gw.example.com + 1026
```

The agent matches by comparing the first segment of the hostname. If `host11.internal` and `host11.example.com` match, it creates a mapping:
- Local IP: `10.0.0.10`
- IPREF: `gw.example.com` with reference `1025`

### DNS Provider Notes

#### NSOne
Zone transfers require using the special endpoint:
```bash
ipref-dns-agent ... internal:domain.com:xfr01.nsone.net
```

#### Cloudflare
Enable zone transfers in the DNS dashboard: DNS → Settings → Zone Transfers

#### Route53
Configure transfer policy in AWS Console: Route 53 → Hosted zones → Transfer settings

### CoreDNS Advanced Configuration

#### Multiple Zones

```
internal {
    file /etc/coredns/db.internal
    log
}

dmz {
    file /etc/coredns/db.dmz
    log
}

. {
    ipref {
        upstream 8.8.8.8
        ea-ipver 4
        gw-ipver 4
        mapper /run/ipref/mapper.sock
    }
    forward . 8.8.8.8 8.8.4.4
    log
}
```

#### IPv6 Support

Example using IPv6 for both encoding network and gateway tunnels:

```bash
# Start gateway with IPv6 (use your actual public IPv6 address)
sudo ipref-gw \
    -data /var/lib/ipref \
    -gateway-bind :: \
    -gateway-pub YOUR_PUBLIC_IPV6 \
    -encode-net fd00:240::/64 \
    -mapper-socket /run/ipref/mapper.sock

# Configure CoreDNS for IPv6
```

CoreDNS configuration:

```
. {
    ipref {
        upstream 2001:4860:4860::8888
        ea-ipver 6
        gw-ipver 6
        mapper /run/ipref/mapper.sock
    }
    forward . 2001:4860:4860::8888 2001:4860:4860::8844
    log
}
```

#### Bind to Specific Interface

```
. {
    bind 127.0.0.2  # Use alternative address alongside systemd-resolved
    ipref {
        upstream 8.8.8.8
        ea-ipver 4
        gw-ipver 4
        mapper /run/ipref/mapper.sock
    }
    log
}
```

## Production Deployment

### Using SystemD Services

See the `systemd/` directory for production service files:

```bash
# Install service files
sudo cp systemd/*.service /etc/systemd/system/
sudo cp systemd/ipref.env /etc/sysconfig/ipref

# Edit configuration
sudo vi /etc/sysconfig/ipref

# Reload systemd
sudo systemctl daemon-reload

# Enable services
sudo systemctl enable ipref-gateway ipref-dns-agent ipref-coredns

# Start services
sudo systemctl start ipref-gateway ipref-dns-agent ipref-coredns

# Check status
sudo systemctl status ipref-gateway
```

### Service Management

```bash
# View logs
sudo journalctl -u ipref-gateway -f
sudo journalctl -u ipref-dns-agent -f
sudo journalctl -u ipref-coredns -f

# Restart services
sudo systemctl restart ipref-gateway

# Stop services
sudo systemctl stop ipref-gateway ipref-dns-agent ipref-coredns
```

### Firewall Configuration

```bash
# Open UDP port 1045 for IPREF tunnel
sudo firewall-cmd --add-port=1045/udp --permanent

# If running public CoreDNS
sudo firewall-cmd --add-port=53/udp --permanent
sudo firewall-cmd --add-port=53/tcp --permanent

sudo firewall-cmd --reload
```

### Monitoring

```bash
# Check gateway process
ps aux | grep ipref-gw

# Check port binding
ss -ulnp | grep 1045

# Check mapper database exists and size
ls -lh /var/lib/ipref/mapper_ea4_gw4.db

# Monitor traffic
sudo tcpdump -i eth0 udp port 1045
```

### Resource Requirements

| Deployment | vCPUs | RAM | Network |
|-----------|-------|-----|---------|
| Client only | 1 | 2GB | 10Mbps+ |
| Small server (<10 services) | 2 | 4GB | 100Mbps+ |
| Medium server (<100 services) | 4 | 8GB | 1Gbps+ |
| Large server (100+ services) | 8 | 16GB | 10Gbps+ |

### Security Checklist

- [ ] Gateway has two separate network interfaces
- [ ] Independent firewall deployed between gateway and internal network
- [ ] Firewall rules configured with default-deny policy
- [ ] Service references use values ≥1025
- [ ] UDP port 1045 open on Internet-facing interface only
- [ ] Gateway processes running as root or with CAP_NET_ADMIN
- [ ] Regular security updates applied
- [ ] Firewall logs monitored for suspicious activity
- [ ] Mapper database backed up regularly
- [ ] DNS zone transfers secured (TSIG keys if possible)

### Backup and Recovery

```bash
# Backup mapper database
sudo cp /var/lib/ipref/mapper_ea4_gw4.db /backup/mapper_ea4_gw4.db.$(date +%Y%m%d)

# Backup configuration
sudo tar czf /backup/ipref-config.tar.gz /etc/coredns /etc/sysconfig/ipref

# Restore mapper database
sudo systemctl stop ipref-gateway
sudo cp /backup/mapper_ea4_gw4.db.20241001 /var/lib/ipref/mapper_ea4_gw4.db
sudo systemctl start ipref-gateway
```

## Troubleshooting

For common issues and solutions, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md).
