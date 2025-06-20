# IPREF gateway

IPREF™ is an IP addressing system where hosts are referred to by a combination of an IP address and a reference, hence ipref. It is used for communication between private networks. The IP portion of an IPREF address is usually an address of one of the gateways to local networks. The reference is an opaque unsigned integer assigned by local networks. References have no meaning beyond the local network they were assigned in. A local network's _address mapper_ makes use of them to produce valid local IP addresses.

IPREF is for local networks wishing to exchange information with other local networks. It is about local-to-local, there is no intention to provide IPREF support for communication between local networks and public Internet. However, one might notice that most all services appearing on the public Internet are actually hosted on local networks and then made public via Network Address Translation (NAT). IPREF allows to reach those same services on their private networks directly.

IPREF is compatible with IPv4 and IPv6, or a mix thereof. Local networks may be IPv4 or IPv6 and still be able to communicate with other local networks. IPREF is a better Internet.

Only gateways need to implement IPREF.  Hosts on the attached local networks are not aware of IPREF. There is no need to modify them in any way.

IPREF can be implemented in many different ways. This sample implementation uses random assignment of _references_ and _encoded local addresses_. It integrates _address mapper_ with IPREF _forwarder_. Such arrangement is suitable for local networks with single gateways.

The gateway is simple but quite capable. It can be used to test IPREF and to develop other services based on IPREF.

This code includes technology covered by patent US 10,749,840 B2.

# Block diagram

Major components of the gateway are shown in the diagram below. Blocks in the area between the dashed lines are part of the executable. For more realistic operations, DNS support is required. The gateway needs an IPREF aware resolver and a DNS agent. These two components communicate with the _address mapper_ to provide mapping between IPREF addresses and standard IP addresses used in local networks.

```
   ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━
                                                                IPREF gateway
                          ┏━━━━━━━━━━━━━━━━━━━━━━━━━┓
                          ┃                         ┃
                          ┃  ╭───────────────────╮  ┃
                          ┃  │ ifc   ─╴▷╶─   udp │  ┃
               ipref ifc  ┃  ╰───────────────────╯  ┃  udp tunnel
                       ───┨  ╭───────────────────╮  ┠───
                          ┃  │ ifc   ─╴◁╶─   udp │  ┃
                          ┃  ╰───────────────────╯  ┃
                          ┃                         ┃
                          ┃         ipref forwarder ┃
                          ┗━━━━━━━━━━━━┯━━━━━━━━━━━━┛
                                       │
                    ┏━━━━━━━━━━━━━━━━━━┷━━━━━━━━━━━━━━━━━━┓
                    ┃                                     ┃  ╭─────────╮
                    ┃   ┌───────────┐       ╔═════════╗   ┠──┤  timer  │
                    ┃   │   access  │ ─╴▷╶─ ║ address ║   ┃  ╰─────────╯
                    ┃   │ functions │ ─╴◁╶─ ║ records ║   ┃  ╭─────────╮
                    ┃   └───────────┘       ╚═════════╝   ┃  │ static  │
                    ┃                                     ┠──┤ address │
                    ┃                                     ┃  │ config  │
                    ┃                      address mapper ┃  ╰─────────╯
                    ┗━━━━━━━┯━━━━━━━━━━━━━━━━━━━━━━━┯━━━━━┛
                            │                       │
                      ╭─────┴─────╮            ╭────┴────╮
                      │ resolver  │            │ address │
                      │  broker   │            │ broker  │
                      ╰─────┬─────╯            ╰────┬────╯
                            │                       │          IPREF gateway
     ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━╺━┿━╸━ ━ ━ ━ ━ ━ ━ ━ ━ ━╺━┿━╸━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━
                            │                       │
                       ┏━━━━┷━━━━┓            ┏━━━━━┷━━━━━┓
   local resolvers     ┃ caching ┃            ┃           ┃
              ─────────┨   DNS   ┃            ┃ DNS agent ┃
                       ┃ server  ┃            ┃           ┃
                       ┗━━┯━━━┯━━┛            ┗━━━━┯━━┯━━━┛
       ╭────────╮         │   │                    │  │             ╭──────────╮
       │ local  │         │   │                    │  │           ╭──────────╮ │
       │  DNS   ├─────────┴───┼────────────────────╯  │           │ external │ │
       │ server │             ╰───────────────────────┴───────────┤   DNS    │ │
       ╰────────╯                                                 │ servers  │╶╯
                                                                  ╰──────────╯
```

### IPREF forwarder

IPREF forwarder consists of two threads. One thread receives packets from the IPREF interface, maps addresses to IPREF, then sends packets to peer gateways via udp tunnel. Another thread operates in the opposite direction. It receives packets from peer gateways via udp tunnel, maps addresses back from IPREF, then sends packets to the IPREF interface.

### Address mapper

Address mapper manages mappings between local addresses and their IPREF equivalents. It allocates references and _encoded addresses_ which are standard IP addresses that are presented to local hosts in lieu of external IPREF addresses.  Address mapper also allocates full IPREF addresses for local hosts originating communication over IPREF. It takes into account IPREF addresses advertised by local DNS servers and IPREF addresses resolved on behalf of local networks' hosts. That information is presented to the _forwarder_ for proper address encoding and decoding.

### Caching DNS server

IPREF, similarly to standard IP, does not require DNS for its operations but name mapping service is immensely useful making it a required component of any practical networking system. To work properly with DNS, IPREF requires a *caching DNS server* that is aware of the *address mapper*. The server must inform *address mapper* of all IPREF DNS queries issued by hosts on the local network. The server must also negotiate allocation of _references_ and _encoded addresses_ with the mapper. All resolvers on the local network must use an IPREF aware DNS caching server.

This implementation provides a suitable ipref _plugin_ for [coredns](https://coredns.io/) DNS server.

### DNS agent

The *address mapper* must be informed of all local hosts reachable externally via their equivalent IPREF addresses. That information is provided by a *DNS agent*. The agent examines both external and internal DNS servers to determine the mapping between standard local IP addresses and externally visible IPREF addresses. This implementation perform simple matching between the top segments of the DNS names listed in the local server and in the related external servers. The agent then passes local IP addresses and their corresponding IPREF addresses to the *address mapper* which constructs proper *address records* for use by the *forwarder*. The agent is only concerned with DNS records that relate to *its* local network. It does not query DNS records related to other local networks.

### Local DNS server

Local DNS server is optional. It is used only if local networks wish to advertise some of their hosts for external access via IPREF. Local DNS servers are standard, unmodified DNS servers.

### External DNS servers

External DNS servers are used to advertise IPREF addresses of local hosts for external access. If a local network wants to make some of its hosts available externally via IPREF addresses, it must setup an external DNS server listing these IPREF addresses. It must also setup a local DNS server that lists local standard IP addresses for the same hosts. Both servers are queried by the *DNS agent* which then passes related address information to the *address mapper*. External DNS servers are standard, unmodified DNS servers.

### Static address configuration

Sometimes DNS is not available or it may be undesirable. IPREF does not require DNS. The *address mapper* can learn static address mapping by reading configuration files. One such file may be /etc/hosts where mapping may be provided using extended syntax.

### *Our* addresses and *their* addresses

IPREF is an address rewriting technology. Each local network must interpret standard IP addresses and IPREF addresses, whether defined by its own network or defined by some other local network, according to *its* local rules. To avoid confusion, the term *our* is used when referring to addresses defined by the local network itself and the term *their* is used when referring to addresses defined by some other local networks. For example: the *DNS agent* returns mapping between *our* IP addresses and *our* IPREF addresses whereas the *caching DNS server* resolves DNS names to either *our* IP addresses or to *our* encoded addresses which correspond to *their* IPREF addresses.
