# IPREF Gateway Troubleshooting Guide

Quick solutions for the most common issues when deploying and operating IPREF gateways.

## Table of Contents

1. [Gateway Issues](#gateway-issues)
2. [DNS Issues](#dns-issues)
3. [Connectivity Issues](#connectivity-issues)
4. [Getting Help](#getting-help)

---

## Gateway Issues

### "src(x.x.x.x) is not gateway, packet dropped"

**Symptoms**: Gateway logs show messages about source addresses not matching the gateway.

**Cause**: The mapper database contains stale entries from a previous configuration.

**Solution**:
```bash
# Stop services and remove database
sudo systemctl stop ipref-gateway ipref-dns-agent ipref-coredns
sudo rm /var/lib/ipref/mapper_*.db
sudo systemctl start ipref-gateway ipref-dns-agent ipref-coredns
```

### Gateway Won't Start

**Symptoms**: `ipref-gw` exits immediately after starting.

**Common causes:**

1. **Permission denied on /run/ipref/mapper.sock**
   ```bash
   sudo mkdir -p /run/ipref
   sudo chmod 755 /run/ipref
   ```

2. **UDP port 1045 already in use**
   ```bash
   sudo ss -ulnp | grep 1045
   # Kill the conflicting process if found
   ```

3. **Invalid network configuration**
   ```bash
   # Check logs for specific error
   sudo journalctl -u ipref-gateway -n 50
   ```

---

## DNS Issues

### DNS Zone Transfer Failures (NSOne)

**Symptoms**: `ipref-dns-agent` logs show failed zone transfers.

**Cause**: NSOne requires a special zone transfer endpoint.

**Solution**:
```bash
# Use xfr01.nsone.net instead of primary nameservers
sudo ipref-dns-agent \
    -ea-ipver 4 \
    -gw-ipver 4 \
    -m unix:///run/ipref/mapper.sock \
    -t 60 \
    internal:example.com:xfr01.nsone.net
```

**Other providers**:
- **Cloudflare**: Enable zone transfers in DNS → Settings
- **Route53**: Configure transfer policy in hosted zone settings

### DNS Resolution Not Working

**Symptoms**: `dig` queries return SERVFAIL or no results.

**Quick diagnosis**:
```bash
# Check if CoreDNS is running and listening
sudo systemctl status ipref-coredns
sudo ss -ulnp | grep 53

# Test CoreDNS directly
dig @127.0.0.1 k41.nexsand.us

# Check resolv.conf points to localhost
cat /etc/resolv.conf
```

**Solutions**:

1. **CoreDNS not running**
   ```bash
   sudo systemctl restart ipref-coredns
   sudo journalctl -u ipref-coredns -n 20
   ```

2. **resolv.conf not pointing to CoreDNS**
   ```bash
   echo "nameserver 127.0.0.1" | sudo tee /etc/resolv.conf
   ```

3. **Mapper socket not accessible**
   ```bash
   ls -la /run/ipref/mapper.sock
   # Socket should exist and have proper permissions
   ```

### AA Records Not Found

**Symptoms**: DNS queries work but return regular A records instead of encoded IPREF addresses.

**Diagnosis**:
```bash
# Query external DNS for AA records
dig TXT host11.example.com @ns1.example.com
# Should return: "AA gw.example.com + 1025"

# Check dns-agent logs
sudo journalctl -u ipref-dns-agent -f
```

**Solution**:
```bash
# Verify AA record format in DNS zone: "AA <gateway_fqdn> + <reference>"
# Then restart dns-agent to force sync
sudo systemctl restart ipref-dns-agent
```

---

## Connectivity Issues

### Cannot Reach IPREF Hosts

**Symptoms**: DNS resolution works (returns 10.240.x.x address) but ping/curl fail.

**Quick diagnosis**:
```bash
# Verify DNS returns encoded address
dig k41.nexsand.us
# Should return address in 10.240.0.0/12 range

# Check routing
ip route get 10.240.1.1

# Check if gateway is running
sudo systemctl status ipref-gateway
```

**Solutions**:

1. **Missing route to encoded network** (if on separate client machine)
   ```bash
   sudo ip route add 10.240.0.0/12 via <gateway-internal-ip>
   ```

2. **Gateway not forwarding**
   ```bash
   sudo systemctl restart ipref-gateway
   sudo journalctl -u ipref-gateway -f
   ```

3. **Peer gateway unreachable**
   ```bash
   # Test UDP connectivity to peer gateway
   dig gw.example.com
   ping <peer-gateway-public-ip>
   ```

### Local Services Not Accessible from IPREF

**Symptoms**: External clients cannot reach services you've published.

**Diagnosis**:
```bash
# Verify AA records published externally
dig TXT host11.example.com @8.8.8.8

# Verify internal DNS has the local IP
dig host11.internal @127.0.0.1

# Check if service is reachable locally
curl http://10.0.0.10  # Use actual internal IP
```

**Solutions**:

1. **Hostname mismatch**
   ```bash
   # Internal and external hostnames must match
   # Internal: host11.internal -> 10.0.0.10
   # External: host11.example.com -> AA gw.example.com + 1025
   # The first segment (host11) must match exactly
   ```

2. **dns-agent not syncing**
   ```bash
   ps aux | grep dns-agent
   # Should show: internal:example.com:ns1.example.com

   sudo systemctl restart ipref-dns-agent
   sudo journalctl -u ipref-dns-agent -f
   ```

3. **Firewall blocking internal service**
   ```bash
   # Check firewall rules
   sudo iptables -L -n -v | grep 10.0.0.10

   # Allow traffic to service (example)
   sudo iptables -A FORWARD -i eth1 -d 10.0.0.10 -p tcp --dport 80 -j ACCEPT
   ```

---

## Getting Help

### Quick Diagnostic Commands

```bash
# Check all services
systemctl status ipref-gateway ipref-dns-agent ipref-coredns

# Check port bindings
sudo ss -ulnp | grep -E "1045|53"

# View recent logs
sudo journalctl -u ipref-gateway --since "10 minutes ago"
sudo journalctl -u ipref-dns-agent --since "10 minutes ago"
sudo journalctl -u ipref-coredns --since "10 minutes ago"

# Test connectivity
dig @127.0.0.1 k41.nexsand.us
ping k41.nexsand.us
curl http://k41.nexsand.us
```

### Create Diagnostic Bundle

If you need to report an issue:

```bash
mkdir ipref-diagnostics

sudo journalctl -u ipref-gateway --since "1 hour ago" > ipref-diagnostics/gateway.log
sudo journalctl -u ipref-dns-agent --since "1 hour ago" > ipref-diagnostics/dns-agent.log
sudo journalctl -u ipref-coredns --since "1 hour ago" > ipref-diagnostics/coredns.log

systemctl status ipref-gateway > ipref-diagnostics/status.txt
ip addr > ipref-diagnostics/ip-addr.txt
ip route > ipref-diagnostics/ip-route.txt

tar czf ipref-diagnostics.tar.gz ipref-diagnostics/
```

### Report Issues

**GitHub Issues**: https://github.com/ipref/gw/issues

Include:
- Operating system and version
- IPREF component versions
- Configuration files (redact sensitive info)
- Diagnostic logs
- Steps to reproduce the issue
