# IPREF gateway
IPREF provides means of communication across different address spaces, such as private networks behind NAT, or across different protocols. It provides compatibility between IPv4 and IPv6. It can traverse NAT, NAT6, and cross protocol IPv4/IPv6. It is inherently peer-to-peer.

An IPREF gateway must be installed within each address space that wants to communicate. Here is an example of how such a gateway may be installed at a home network.

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
