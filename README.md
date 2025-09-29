# IPREF Gateway

Access services behind NAT without port forwarding.

## What is IPREF?

IPREF (**IP** addressing with **References**) is a networking protocol that provides direct connectivity between hosts across different address spaces--including private networks behind NAT, overlapping networks, and even across IPv4/IPv6 boundaries. It eliminates the need for traditional NAT port forwarding by using reference-based addressing.

Unlike VPNs or mesh networks, IPREF works at the protocol level and is inherently peer-to-peer. Services become accessible automatically once DNS is configured with no manual port forwarding, no complex NAT rules, no firewall exceptions.

**Learn more:** [IETF Draft Specification](https://www.ietf.org/archive/id/draft-augustyn-intarea-ipref-06.html) | [Architecture Details](docs/ARCHITECTURE.md)

## Quick Start

### Prerequisites

- Linux 64-bit (tested on Rocky Linux, RHEL, Debian, Ubuntu)
- 1 vCPU, 2GB RAM minimum
- UDP port 1045 accessible
- Basic networking tools (`dig`, `ping`, `traceroute`)

### Download Binaries

Download pre-built binaries from GitHub releases:

```bash
# Download pre-built binaries (Linux amd64)
wget https://github.com/ipref/gw/releases/latest/download/ipref-gw
wget https://github.com/ipref/gw/releases/latest/download/ipref-dns-agent
wget https://github.com/ipref/gw/releases/latest/download/ipref-coredns

chmod +x ipref-*
sudo mv ipref-* /usr/local/bin/
```

### Client Mode Setup

Client mode allows you to access IPREF network resources without publishing services.

#### 1. Start the Gateway

```bash
# Create directories
sudo mkdir -p /var/lib/ipref /run/ipref /etc/coredns

# Start gateway
sudo ipref-gw \
    -data /var/lib/ipref \
    -gateway-bind 0.0.0.0 \
    -gateway-pub 0.0.0.0 \
    -encode-net 10.240.0.0/12 \
    -mapper-socket /run/ipref/mapper.sock
```

#### 2. Start DNS Agent (in another terminal)

```bash
sudo ipref-dns-agent \
    -ea-ipver 4 \
    -gw-ipver 4 \
    -m unix:///run/ipref/mapper.sock \
    -t 60
```

#### 3. Start CoreDNS (in another terminal)

First, create `/etc/coredns/Corefile`:

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

Then start CoreDNS:

```bash
sudo ipref-coredns -conf /etc/coredns/Corefile
```

#### 4. Configure DNS Resolution

Point your system's DNS resolver to the local CoreDNS instance:

```bash
# Temporarily set DNS resolver (will reset on reboot)
echo "nameserver 127.0.0.1" | sudo tee /etc/resolv.conf

# For systemd-resolved systems, alternatively:
sudo mkdir -p /etc/systemd/resolved.conf.d
echo -e "[Resolve]\nDNS=127.0.0.1\nDomains=~." | sudo tee /etc/systemd/resolved.conf.d/ipref.conf
sudo systemctl restart systemd-resolved
```

## Testing Your Installation

### Demo Hosts

Test your IPREF installation with these live demo hosts:

| Host | Location | Access |
|------|----------|--------|
| k41.nexsand.us | United States | https://k41.nexsand.us |
| m41.nexsand.ca | Canada | https://m41.nexsand.ca |
| o61.nexsand.uk | United Kingdom | https://o61.nexsand.uk |

### Verification Commands

```bash
# Test DNS resolution (should show 10.240.x.x address)
dig k41.nexsand.us

# Test connectivity
ping k41.nexsand.us

# Access web service
curl http://k41.nexsand.us
```

**Success indicators:**
- `dig` returns an address in the `10.240.0.0/12` range
- `ping` receives responses from that encoded address
- `curl` successfully fetches the webpage

**Troubleshooting:** See [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)

## Publishing Your Own Services

Once you have the gateway running, you can publish services from your local network without port forwarding. IPREF allows you to publish thousands of services from within a private address space.

### Overview

1. **Set up internal DNS** - Map local services to `.internal` TLD
2. **Set up external DNS** - Add AA records to your public DNS zone
3. **Configure gateway** - Gateway automatically matches domain segments to map IPREF addresses to local IPs

### Example

To publish `webserver.internal` at `10.0.0.10` as `web.example.com`:

**Internal DNS** (`/etc/coredns/db.internal`):
```
webserver.internal.  IN  A  10.0.0.10
```

**External DNS** (in your public zone):
```
web.example.com.  IN  TXT  "AA gw.example.com + 1025"
gw.example.com.   IN  A    YOUR_PUBLIC_IP
gw.example.com.   IN  TXT  "AA gw.example.com + 1"
```

The DNS agent synchronizes these records, and the gateway automatically maps incoming connections for `web.example.com` to `10.0.0.10`.

**Complete guide:** [docs/SETUP.md](docs/SETUP.md)

## Building from Source

### Quick Build (Recommended)

The provided Makefile builds all three required components automatically:

```bash
# Clone all repositories in the same directory
git clone https://github.com/ipref/gw
git clone https://github.com/ipref/dns-agent
git clone https://github.com/coredns/coredns
git clone https://github.com/ipref/coredns-plugin-ipref

# Checkout specific CoreDNS version
cd coredns
git checkout v1.12.1
cd ..

# Build all components
cd gw
make

# Find binaries in bin/ directory
ls bin/
```

This automatically builds:
- Gateway binary (`gw`)
- DNS agent (`dns-agent`)
- CoreDNS with IPREF plugin (`coredns`)

**Detailed build instructions:** [docs/BUILD.md](docs/BUILD.md)

## IPv6 Support

IPREF fully supports IPv6. The gateway can:
- Use IPv6 for the encoding network (e.g., `fd00:240::/64`)
- Use IPv6 for UDP tunnels between gateways
- Bridge IPv4 and IPv6 networks seamlessly
- Traverse NAT, NAT6, and mixed protocol scenarios

Configure IP versions with the `-ea-ipver` (encoding) and `-gw-ipver` (gateway tunnel) options.

## Documentation

- **[Setup Guide](docs/SETUP.md)** - Detailed configuration for publishing services
- **[Architecture](docs/ARCHITECTURE.md)** - Protocol details and technical internals
- **[Build Guide](docs/BUILD.md)** - Detailed build instructions and development setup
- **[Troubleshooting](docs/TROUBLESHOOTING.md)** - Common issues and solutions
- **[Examples](examples/)** - Configuration examples for various scenarios
- **[Systemd Services](systemd/)** - Production deployment with systemd

## Related Repositories

- [dns-agent](https://github.com/ipref/dns-agent) - DNS synchronization agent
- [coredns-plugin-ipref](https://github.com/ipref/coredns-plugin-ipref) - CoreDNS IPREF plugin
- [common](https://github.com/ipref/common) - Shared IPREF libraries

## License

[GPL-2.0](https://choosealicense.com/licenses/gpl-2.0/)
