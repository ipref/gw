# IPREF Architecture

## Protocol Overview

IPREF (**IP** addressing with **References**) is a networking protocol ([draft-augustyn-intarea-ipref](https://www.ietf.org/archive/id/draft-augustyn-intarea-ipref-06.html)) that provides means of communication across different address spaces, such as private networks behind NAT, overlapping networks, or even across different protocols.

IPREF can traverse NAT, NAT6, and cross protocol IPv4/IPv6 connections. It is inherently peer-to-peer and eliminates the need for traditional NAT port forwarding.

## Gateway Architecture

This gateway is a reference implementation of the IPREF protocol that integrates an IPREF forwarder with an address mapper.

### Core Components

#### IPREF Forwarder
The forwarder handles bidirectional packet translation between local IP addresses and IPREF addresses, transmitting encapsulated packets through UDP tunnels to peer gateways on port 1045.

**Key responsibilities:**
- Packet encapsulation/decapsulation
- UDP tunnel management
- Peer gateway discovery and connection maintenance
- Traffic routing between local network and IPREF network

#### Address Mapper
The mapper manages the allocation of references and encoded addresses, maintaining mappings between local addresses and their IPREF equivalents.

**Key responsibilities:**
- Reference allocation and management
- Address encoding/decoding
- Mapping database persistence
- Unix socket API for DNS agent and CoreDNS plugin

### Supporting Components

For complete functionality, the gateway requires two supporting components:

#### DNS Agent (`dns-agent`)
Synchronizes DNS records to inform the mapper of locally-hosted services by periodically querying authoritative DNS servers for AA records.

**Responsibilities:**
- Query authoritative DNS for AA records
- Extract IPREF address mappings from DNS
- Update mapper with discovered services
- Support for zone transfers (AXFR)

#### CoreDNS with IPREF Plugin
Provides IPREF-aware DNS resolution for local clients, translating AA records into A/AAAA records by requesting address allocations from the mapper.

**Responsibilities:**
- Receive DNS queries from local clients
- Query upstream DNS for AA records
- Request address allocations from mapper via Unix socket
- Return encoded addresses (10.240.0.0/12 range) to clients
- Forward non-IPREF queries to upstream resolvers

## Network Flow

### Outbound Connection (Local → Remote IPREF Host)

1. Local client queries DNS for `service.example.com`
2. CoreDNS queries upstream DNS, receives AA record
3. CoreDNS requests address allocation from mapper via Unix socket
4. Mapper allocates address from encoding network (e.g., `10.240.5.100`)
5. CoreDNS returns `10.240.5.100` to local client
6. Local client sends packet to `10.240.5.100`
7. Gateway intercepts packet, looks up IPREF mapping
8. Gateway encapsulates packet and sends via UDP tunnel to remote gateway
9. Remote gateway decapsulates and delivers to actual service

### Inbound Connection (Remote → Local IPREF Host)

1. Remote client queries DNS for `service.mydomain.com`
2. Remote DNS returns AA record pointing to local gateway
3. Remote gateway establishes UDP tunnel to local gateway
4. DNS agent periodically discovers service mapping via zone transfer
5. DNS agent informs local mapper of the service
6. Mapper creates mapping between IPREF address and local IP
7. Gateway receives encapsulated packet via UDP tunnel
8. Gateway decapsulates and forwards to local service IP

## Address Encoding

IPREF uses a configurable encoding network (default: `10.240.0.0/12`) to represent remote IPREF addresses as local IP addresses.

### Reference Space
- References are 64-bit integers
- Reference 1 is conventionally reserved for the gateway itself
- References ≥1024 recommended for services (security through obscurity)
- References can be allocated sequentially or with gaps

### Encoding Format
The encoding network address represents the IPREF reference in a way that can be uniquely mapped back to the original IPREF address.

Example mapping:
- IPREF reference: `1025`
- Gateway: `gw.example.com`
- Encoded as: `10.240.x.x` (specific encoding algorithm in mapper)

## Communication Patterns

### Unix Domain Socket Protocol
The mapper exposes a Unix domain socket (default: `/run/ipref/mapper.sock`) that both the DNS agent and CoreDNS plugin use to:

- Query existing mappings
- Request new address allocations
- Register discovered services
- Update mapping TTLs

### DNS Integration Patterns

#### Pattern 1: Internal + External DNS
- Internal DNS (`.internal` TLD) maps local IPs
- External DNS (public domain) maps IPREF addresses
- DNS agent synchronizes external → mapper
- Suitable for hosting services

#### Pattern 2: Client-Only Mode
- No internal DNS required
- DNS agent runs without zone specification
- Only outbound connections to remote IPREF hosts
- Suitable for clients accessing services

## IPv6 Support

IPREF supports both IPv4 and IPv6 at two levels:

### Encoded Address IP Version (`ea-ipver`)
The IP version used for the encoding network:
- `4`: Use IPv4 encoding network (e.g., `10.240.0.0/12`)
- `6`: Use IPv6 encoding network (e.g., `fd00:240::/64`)

### Gateway IP Version (`gw-ipver`)
The IP version used for UDP tunnels between gateways:
- `4`: Use IPv4 for gateway-to-gateway communication
- `6`: Use IPv6 for gateway-to-gateway communication

These can be mixed (e.g., IPv4 encoding with IPv6 tunnels) to support various network configurations.

## Security Considerations

### Reference Obscurity
Using references ≥1024 makes port scanning impractical:
- 2^64 possible references
- No way to enumerate services without DNS
- Services not discoverable by network scanning

### Tunnel Security
- UDP tunnels use port 1045
- Packet authentication via IPREF protocol
- Gateway validates source addresses
- Stale mappings can be cleared by deleting database

### Firewall Configuration
Only UDP port 1045 needs to be accessible:
- No per-service port forwarding
- No complex NAT rules
- Services remain behind gateway
- Internal network topology hidden

## Database Schema

The mapper maintains a BoltDB database with mappings:

```
mapper_ea4_gw4.db  (for IPv4 encoding + IPv4 gateway)
mapper_ea4_gw6.db  (for IPv4 encoding + IPv6 gateway)
mapper_ea6_gw4.db  (for IPv6 encoding + IPv4 gateway)
mapper_ea6_gw6.db  (for IPv6 encoding + IPv6 gateway)
```

Each database stores:
- IPREF reference numbers
- Encoded addresses
- Gateway addresses
- Local IP addresses (for published services)
- TTL and timestamp information

## Performance Characteristics

### Latency
- Additional latency from encapsulation: <1ms
- UDP tunnel overhead: ~50 bytes per packet
- No connection setup delay (UDP-based)

### Throughput
- Limited by UDP tunnel capacity
- Typical deployment: 1Gbps+
- No significant overhead from protocol

### Resource Requirements
- **Minimum**: 1 vCPU, 2GB RAM
- **Recommended**: 2 vCPUs, 4GB RAM
- Database size: ~1MB per 1000 mappings
- Network: 1Gbps+ for production

## Failure Modes

### Gateway Failure
- Local clients lose access to IPREF network
- Existing connections drop
- Recovery: restart gateway (mappings persist in database)

### DNS Agent Failure
- New services not discovered
- Existing mappings continue to work
- Recovery: automatic reconnection

### CoreDNS Failure
- Local clients cannot resolve IPREF addresses
- Existing connections using cached DNS continue
- Recovery: restart CoreDNS

### Stale Mappings
If mapper database contains outdated entries:
```bash
sudo systemctl stop ipref-gateway
sudo rm /var/lib/ipref/mapper_*.db
sudo systemctl start ipref-gateway
```

## Related Specifications

- [IPREF Internet Draft](https://www.ietf.org/archive/id/draft-augustyn-intarea-ipref-06.html) - Protocol specification
- [CoreDNS Plugin Development](https://coredns.io/manual/toc/#writing-plugins) - Plugin architecture
- [DNS Zone Transfers (AXFR)](https://datatracker.ietf.org/doc/html/rfc5936) - Used by DNS agent
