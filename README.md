# IPREF gateway
IPREF provides means of communication across different address spaces, such as private networks behind NAT, or across different protocols. It provides compatibility between IPv4 and IPv6. It can traverse NAT, NAT6, and cross protocol IPv4/IPv6. It is inherently peer-to-peer.

An IPREF gateway must be installed within each address space that wants to communicate. Here is an example of how such a gateway may be installed at a home network.

## Building

For a complete IPREF gateway, you'll need three binaries: `gw`, `dns-agent`, and `coredns`. Below are instructions for manually building them. Alternatively, you can use the Makefile in this repository to perform the process automatically. Before using it, you'll need to clone these repositories alongside the `gw` repository:

- https://github.com/ipref/dns-agent
- https://github.com/coredns/coredns (it's recommended to checkout tag `v1.12.1`)
- https://github.com/ipref/coredns-plugin-ipref

So the same directory should contain `gw`, `dns-agent`, `coredns`, and `coredns-plugin-ipref`.

Then just run `make` inside this repository, and you'll find the binaries in `bin/`.

## Build the gateway
### Prerequisites

- Go 1.22 or later
- Git

### Steps

1. Clone the repository:
```bash
git clone https://github.com/ipref/gw.git
cd gw
```

2. Install dependencies:
```bash
go mod download
```

3. Build the project:
```bash
go build -o gw
```

The build will generate an executable named `gw` in your current directory.

### Dependencies

The project uses the following main dependencies (as specified in go.mod):

- github.com/fsnotify/fsnotify v1.8.0
- github.com/hashicorp/golang-lru/v2 v2.0.7
- github.com/ipref/common v1.3.1
- go.etcd.io/bbolt v1.3.11
- golang.org/x/sys v0.28.0

### Verify installation

To verify the build was successful:

```bash
./gw -h
```

## Build the DNS agent

The DNS agent informs the gateway about the mappings between public IPREF addresses and private IP addresses by periodically querying DNS servers.

Clone the repository and build it:

```sh
git clone https://github.com/ipref/dns-agent.git
cd dns-agent/
go build
```

The binary will be named `dns-agent`. Verify that it was built successfully:

```sh
./dns-agent -h
```

## Build CoreDNS with the `ipref` plugin

CoreDNS can be used to host the special resolver (using the `ipref` plugin) and also optionally your `*.internal` and/or your public nameservers.

The special resolver receives requests from the local network and translates AA records into A/AAAA records by asking `gw` to dynamically allocate addresses in the encoding network that are mapped to the IPREF address that appears in the AA record.

To build CoreDNS, you'll need to clone the CoreDNS repo and also the ipref plugin repo inside CoreDNS's tree. You'll also need to add the dependencies for the ipref plugin to CoreDNS's `go.mod`.

```sh
git clone https://github.com/coredns/coredns.git
cd coredns/
git checkout v1.12.1
echo "require github.com/ipref/common v1.3.1" >> go.mod
cd plugin/
git clone https://github.com/ipref/coredns-plugin-ipref.git
mv coredns-plugin-ipref/ ipref/ # Rename
```

Additionally, to ensure that CoreDNS's build system can find the plugin, this line needs to be added to the `plugin.cfg` file at the top level of the CoreDNS repo:

```
ipref:ipref
```

The order in `plugin.cfg` determines the order that plugins apply. It is recommended to place the above line after the line `auto:auto`.

Once these steps are complete, you can run `make` to build CoreDNS. Verify that it was build successfully:

```sh
./coredns -plugins
```

Make sure `ipref` is in the list of plugins. If not, then the build system might not have recognized the plugin. Also make sure that the `require` line mentioned above is still in `go.mod` - Go's build system might have removed it if it couldn't find the plugin. Make sure the plugin repo is in the correct place and has the correct name before running `make`.

> You have to disable `systemd-resolved` in order for CoreDNS to occupy port 53

## Configuration

For the sake of demonstration, we'll assume that you've decided to use:

- `*.internal` as your internal, private TLD for hosting local IP addresses
- `*.example.com` as your public domain for hosting IPREF addresses
- `ns1.example.com` and `ns2.example.com` are your public nameservers for `example.com`
- `10.240.0.0/12` as your encoding network (the virtual, local address space that the gateway uses to emulate remote IPREF hosts)
- `1.2.3.4` is your gateway's public IP address

Run the gateway using these arguments:

```sh
gw \
    -data /var/lib/ipref \
    -gateway-bind 0.0.0.0 \
    -gateway-pub 1.2.3.4 \
    -encode-net 10.240.0.0/12 \
    -mapper-socket /run/ipref/mapper.sock
```

The directory `/var/lib/ipref` is where the mapping database will be stored. `/run/ipref/mapper.sock` is the path to the Unix domain socket used for communication between `gw`, `dns-agent`, and the CoreDNS ipref plugin (it will be created by `gw` on startup).

`-gateway-bind` can be used to tell the gateway to only listen for UDP tunnel packets on a specific interface. Specifying `0.0.0.0` will tell it to listen on all interfaces.

Run the DNS agent like so:

```sh
dns-agent \
    -ea-ipver 4 \
    -gw-ipver 4 \
    -m unix:///run/ipref/mapper.sock \
    -t 60 \
    internal:example.com:ns1.example.com,ns2.example.com
```

The options `-ea-ipver` and `-gw-ipver` specify the IP version for the local network and UDP tunnel respectively. The `-t` option specifies the approximate interval in minutes at which the DNS agent will query the nameservers for updates.

CoreDNS requires a Corefile (configuration file). Depending on your use case, there are a variety of ways to configure it. This example demonstrates a basic setup where CoreDNS acts as the special resolver (using the ipref plugin) and hosts the `*.internal` domain from a zone file.

`/etc/coredns/Corefile`:

```Corefile
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
```

The `ea-ipver` and `gw-ipver` options are the same as for `dns-agent`. The `upstream` specifies the nameserver to query for AA records.

Your `/etc/coredns/db.internal` is a zone file containing your local IP addresses. For example:

```
$ORIGIN internal.
$TTL 120

internal.  IN  SOA  localhost. admin.internal. ( 1 120 120 120 120 )
internal.  IN  NS   localhost.

gw.internal.      IN  A  10.0.0.1 ; The gateway itself
host11.internal.  IN  A  10.0.0.11
host22.internal.  IN  A  10.0.0.22
```

You can then start CoreDNS with:

```sh
coredns -conf /etc/coredns/Corefile
```

Finally, you will need to add AA records to your nameservers for your public domain (`example.com` in this example). Your zone file for this domain might look like:

```
$ORIGIN example.com.
$TTL 3600

example.com.  IN  SOA  ns1.example.com. admin.example.com. ( 2024123101 7200 3600 1209600 3600 )
example.com.  IN  NS   ns1
example.com.  IN  NS   ns2

gw.example.com.      IN  A    1.2.3.4

gw.example.com.      IN  TXT  "AA gw.example.com + 1" ; By convention, ref 1 is reserved for the gw itself
host11.example.com.  IN  TXT  "AA gw.example.com + 11"
host22.example.com.  IN  TXT  "AA gw.example.com + 22"
```

## Install and configure the gateway at a home network.
Blah, blah

## Test the gateway's ability to connect to hosts in other address spaces.
Blah, blah...

Nexsand, Inc, has set up a demo network in the cloud. It publishes test websites in three locations:

	https://k41.nexsand.us
	https://m41.nexsand.ca
	https://o61.nexsand.uk

These websites can be viewed with a successful installation of the gateway. It is a quick test to check if it operates correctly.

Blah, blah...

## Publish local services to the Internet

There is no need to mess with NAT, no need to manipulate ports, no need to assign global IP addresses. IPREF allows to publish arbitrary number of services, thousands of them, from within a private address space (behind NAT)

### Setup some local service

Blah, blah...

It could be a machine with an ssh access, or a web server.

Blah, blah...

### Set up internal DNS server

First publish the server in an internal DNS server. This server publishes local addresses of services hosted on the local network (local address space). These DNS names are only visible internally. Typically TLD '.internal' is used for the purpose

Blah, blah...

### Set up external DNS server

Publish IPREF addresses of the local services in a publicly accessible DNS server.

Blah, blah...

### Configure the gateway to publish local services to the Internet

Publishing a service via IPREF amounts to setting proper DNS entries in the internal and external DNS servers. The gateway makes a match between top domain segments. That way it knows which IPREF address corresponds to which local native address.

Blah, blah, ...

### Testing the services

Blah, blah...

## Dealing with IPv6 Internet

If your Internet Service provider offers IPv6 addresses, and you router supports IPv6, you can connect to both IPv4 and IPv6 Internets and reach external hosts over either IPv4 or IPv6 Internet.

Connect the IPv6 Internet to the IPREF gateway. There is no need to change anything in your local network.

Blah, blah...
