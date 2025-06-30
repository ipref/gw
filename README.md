# IPREF gateway
IPREF provides means of communication across different address spaces, such as private networks behind NAT, or across different protocols. It provides compatibility between IPv4 and IPv6. It can traverse NAT, NAT6, and cross protocol IPv4/IPv6. It is inherently peer-to-peer.

An IPREF gateway must be installed within each address space that wants to communicate. Here is an example of how such a gateway may be installed at a home network.

## Build the gateway
Blah, blah...

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
