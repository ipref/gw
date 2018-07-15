+# IPREF gw
IPREF&#8482; is an IP addressing system where hosts are referred to by a combination of an IP address and a reference, hence ipref. It is used for communication between private networks. The IP portion of an IPREF address is usually an address of one of the gateways to a local network. The reference is an opaque unsigned integer assigned by that local network. References have no meaning beyond the local network they were assigned in. A local network _address mapper_ makes use of them to produce valid local IP addresses.

IPREF is for local networks wishing to exchange information with other local networks. It is about local-to-local, there is no intention to provide IPREF support for communication between local networks and public Internet. However, one may notice that virtually all services appearing on public Internet are actually hosted on local networks and then made public via Network Address Translation (NAT). IPREF allows to reach those same services on their local, private networks without NAT. It works with IPv4 and IPv6, or a mix thereof. IPREF is a better Internet.

Only gateways need to implement IPREF.  Hosts on the attached local networks are not aware of IPREF. There is no need to modify them in any way.

IPREF can be implemented in many different ways. This sample implementation uses random assignment of _references_ and _encoded local addresses_. It integrates _address mapper_ with IPREF _forwarder_. Such arrangement is suitable for local networks with single gateways.

The gateway is simple but quite capable. It can be used to test IPREF and to develop other services based on IPREF.

# Block diagram

Major components of the gateway implementation are shown in the diagram below. Blocks in the area between the dashed lines are part of the executable. For more realistic operations, DNS support is required. The gateway needs an IPREF aware resolver and a local dynamic DNS server. The resolver and the local DNS server must inform gateway's _address mapper_ of all IPREF addresses used by hosts on the local network.

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
                           ┗━━━━━━━━━━━┯━━━━━━━━━━━━━┛
                                       │
                     ┏━━━━━━━━━━━━━━━━━┷━━━━━━━━━━━━━━━━━━━┓
                     ┃                                     ┃
                     ┃   ┌───────────┐       ╔═════════╗   ┃
                     ┃   │   access  │ ─╴▷╶─ ║ address ║   ┃
                     ┃   │ functions │ ─╴◁╶─ ║ records ║   ┃
                     ┃   └───────────┘       ╚═════════╝   ┃
                     ┃                                     ┃
                     ┃                      address mapper ┃
                     ┗━━━━┯━━━━━━━━━━━━┯━━━━━━━━━━━━━━┯━━━━┛
                          │            │              │
                    ╭─────┴────╮   ╭───┴────╮   ╭─────┴──────╮
                    │ resolver │   │ expire │   │ dns AA rec │
                    │  agent   │   │ timer  │   │  watcher   │
                    ╰─────┬────╯   ╰────────╯   ╰─────┬──────╯
                          │                           │          IPREF gateway
     ━ ━ ━ ━ ━ ━ ━ ━ ━ ━╺━┿━╸━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━╺━┿━╸━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━
                          │                           │
                          │                       ╔═══╧════╗
                          │                       ║ DNS RR ║
                          │                       ╚═══╤════╝
     local resolver ╭─────┴────╮                 ╭────┴──────╮      advertise
              ──────┤ resolver ├──────┬──────────┤ local dns ├──    AA records
                    ╰──────────╯      │          ╰───────────╯
                                      │                          ╭────────────╮
                                      ╰──────────────────────────┤ public dns │
                                                                 ╰──────┬─────╯
                                                                    ╔═══╧════╗
                                                                    ║ DNS RR ║
                                                                    ╚════════╝
### IPREF forwarder

IPREF forwarder consists of two threads. One thread receives packets from the IPREF interface, maps addresses to IPREF, then sends packets to peer gateways via udp tunnel. Another thread operates in the opposite direction. It receives packets from peer gateways via udp tunnel, maps addresses back from IPREF, then sends packets to the IPREF interface.

### Address mapper
Address mapper manages mappings between local addresses and their IPREF equivalents. It allocates references and _encoding addresses_ which are standard IP addresses that are presented to local hosts in lieu of external IPREF addresses.  Address mapper also allocates full IPREF addresses for local hosts originating communication over IPREF. It takes into account IPREF addresses advertised by local DNS servers and IPREF addresses resolved on behalf of local networks' hosts. That information is presented to the _forwarder_ for proper address encoding and decoding.

### Resolver
IPREF, similarly to standard IP, does not require DNS for its operations but name mapping service is immensely useful making it a required component of any practical networking system. IPREF requires a resolver that is aware of the _address mapper_. The resolver must inform address mapper of all IPREF DNS queries issued by hosts on local networks. The resolver also must negotiate allocation of _references_ and _encoding addresses_ with the mapper.

### Local DNS server
Local DNS server is optional. It is used only if local networks wish to advertise some of their hosts for access via IPREF. In those cases, _address mapper_ must be informed of all advertised hosts. The DNS servers do not need to be modified in any special way but they must provide means for the mapper to learn advertised local hosts.
