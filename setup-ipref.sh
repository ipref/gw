#!/bin/bash

set -exo pipefail  # Exit on error

# -- Variables --
GATEWAY_PUBLIC_IP="1.2.3.4"
GATEWAY_ENCODE_NET="10.240.0.0/12"
DNS_AGENT_OPTS="internal:example.com:ns1.example.com,ns2.example.com"

# -- Checks and pre-requisites --
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root"
    exit 1
fi
command -v go >/dev/null 2>&1 || { echo "Go is required but not installed. Aborting." >&2; exit 1; }
command -v git >/dev/null 2>&1 || { echo "Git is required but not installed. Aborting." >&2; exit 1; }

mkdir -p /var/lib/ipref /etc/coredns /run/ipref
echo "Setting up build environment..."
WORK_DIR=$(mktemp -d)
cd "$WORK_DIR"

# -- Build
check_binary() {
    local binary=$1
    local version_arg=${2:---version}
    if [ -f "/usr/local/bin/$binary" ]; then
        echo "Found existing $binary binary, checking if it works..."
        if "/usr/local/bin/$binary" $version_arg >/dev/null 2>&1; then
            echo "$binary is already installed and working, skipping build"
            return 0
        fi
    fi
    return 1
}

# - gw
if ! check_binary "gw" "-h"; then
    echo "Building gateway..."
    git clone https://github.com/ipref/gw.git
    cd gw
    go mod download
    go build -o gw
    cp gw /usr/local/bin/
    cd ..
fi

# - dns-agent
if ! check_binary "dns-agent" "-h"; then
    echo "Building DNS agent..."
    git clone https://github.com/ipref/dns-agent.git
    cd dns-agent
    go build
    cp dns-agent /usr/local/bin/
    cd ..
fi

# - coredns
if ! check_binary "coredns"; then
    echo "Building CoreDNS with IPREF plugin..."
    git clone https://github.com/coredns/coredns.git
    cd coredns
    git checkout v1.12.1
    echo "require github.com/ipref/common v1.3.1" >> go.mod
    cd plugin
    git clone https://github.com/ipref/coredns-plugin-ipref.git
    mv coredns-plugin-ipref ipref
    cd ..
    sed -i '/auto:auto/a ipref:ipref' plugin.cfg
    make
    cp coredns /usr/local/bin/
    cd ..
fi

# -- Configs
cat > /etc/coredns/Corefile <<EOF
internal {
    file /etc/coredns/db.internal
    transfer {
        to *
    }
    log
    debug
}
. {
    ipref {
        upstream 8.8.8.8
        ea-ipver 4
        gw-ipver 4
        mapper /run/ipref/mapper.sock
    }
    log
    debug
}
EOF

cat > /etc/coredns/db.internal <<EOF
\$ORIGIN internal.
\$TTL 120

internal.  IN  SOA  localhost. admin.internal. ( 1 120 120 120 120 )
internal.  IN  NS   localhost.

gw.internal.      IN  A  10.0.0.1
host11.internal.  IN  A  10.0.0.11
host22.internal.  IN  A  10.0.0.22
EOF


# -- Systemd services
cat > /etc/systemd/system/ipref-gateway.service <<EOF
[Unit]
Description=IPREF Gateway
After=network.target

[Service]
ExecStart=/usr/local/bin/gw \
 -data /var/lib/ipref \
 -gateway-bind 0.0.0.0 \
 -gateway-pub $GATEWAY_PUBLIC_IP \
 -encode-net 10.240.0.0/12 \
 -mapper-socket /run/ipref/mapper.sock
Restart=always

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/ipref-dns-agent.service <<EOF
[Unit]
Description=IPREF DNS Agent
After=ipref-gateway.service

[Service]
ExecStart=/usr/local/bin/dns-agent \
 -ea-ipver 4 \
 -gw-ipver 4 \
 -m unix:///run/ipref/mapper.sock \
 -t 60 \
 $DNS_AGENT_OPTS
Restart=always

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/ipref-coredns.service <<EOF
[Unit]
Description=CoreDNS with IPREF plugin
After=ipref-gateway.service

[Service]
ExecStart=/usr/local/bin/coredns -conf /etc/coredns/Corefile
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl stop systemd-resolved
systemctl disable systemd-resolved

systemctl daemon-reload
systemctl enable ipref-gateway ipref-dns-agent ipref-coredns
systemctl start ipref-gateway ipref-dns-agent ipref-coredns

# -- Cleanup
rm -rf "$WORK_DIR"

echo "IPREF gateway installation complete!"
echo "Please configure your network settings and DNS records as described in the documentation."
echo "Don't forget to:"
echo "1. Update your public DNS records for domains specified in DNS_AGENT_OPTS"
echo "2. Adjust the gateway public IP address in GATEWAY_PUBLIC_IP"
echo "3. Configure your nameserver settings to use the local CoreDNS server"
echo "Please refer to https://github.com/ipref/gw/blob/master/README.md for more details."
