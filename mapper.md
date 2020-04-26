### Block diagram

Major components.

```DejaVu
                     ╭─────────────╮
                     │             │      ╔═════════════╗
                     │  ifc → udp ━┿━╸▷╺━╸║ ea -> ipref ║
                     │      ╻      │      ╚═════════════╝
                     ╰──────╂──────╯
                            ┃
                            △
                            ┃
                     ╭──────╂──────╮
                     │      ╹      │      ╔═════════════╗
                     │  ifc ← udp ━┿━╸▷╺━╸║ ipref -> ea ║
   ╭─────────╮       │      ╻      │      ╚═════════════╝
   │         │       │    ╭─╂─╮    │
   │   gen  ╶┼───╴▷╶─┼────┼ ◯ │    │  create mapping: ipref -> ea
   │    ╷    │       │    ╰╂─┼╯    │
   ╰────┼────╯       ╰─────╂─┼─────╯
        ▽                  ▽ △
        │                  ┃ │           ╭─────────╮         ╭─────────╮
  ╔═══════════╗            ┃ ╰───────────┼╴       ╶┼───╴◁╶───┼╴coredns │
  ║ allocated ║            ┃             │ mbroker │         │ ipref   │
  ╚═══════════╝            ┣━━━━━╸▷╺━━━━━┿╸   ╻   ╺┿━━━╸▷╺━━━┿╸plugin  │
                           ┃             ╰────╂────╯         ╰─────────╯
                           ▽                  ▽
                           ┃                  ┃
                       ╭───╂───╮       ╔═════════════╗
                       │       │       ║ ipref -> ea ║
                       │  DB   │       ╚═════════════╝
                       │       │
                       ╰───╂───╯
                           ▽
                           ┃
                       ╔═══════╗
                       ║ file  ║
                       ╚═══════╝
```

### Mapping ipref -> ea

##### Allocation

The ipref -> ea mapping is created in function get_src_ea() which is called from forwarder fwd_to_tun(). There are two cases where the mapping cration is triggered.

The first case is when the forwarded encounters an incoming packet with source address being an ipref address. It needs to translate that ipref address into ea. More precisely it translates *their* ipref -> *our* ea. First a random ea is obtained from the generator *gen*. The generator keeps the list of dispensed eas in a data structure to assure uniqeness. Once an ea is obtained, it is associated with an ipref address  thus creating the mapping. The mapping is stored in the ipref -> ea structure of the forwarder. The mapping is then distributed via v1 protocol to the following destinations: the other forwarder fwd_to_gw(), mapper broker, and the data base DB.

The other forwarder, fwd_to_gw(), converts the original ipref -> ea mapping into the reverse mapping ea -> ipref and stores it in a data structure.

The mapper broker stores the mapping in its data structures for the purpose of responding to mapping requests from the ipref plugin.

The data base DB serves as a means of persistency over gateway restarts. The DB is backed by a file system. When the gateway starts, the contents of the DB is distributed to other structures within the gateway.

The second case is when a user queries DNS for an address and the returned address is an ipref address. In that case, the caching DNS server uses the ipref plugin to request mapping of that ipref address into an ea address which then can be returned to the user. The ipref plugin communicates with the mapper broker via a unix socket. When the broker receives a request for mapping, it examines its own data structures. If a match is found, the mapping is returned to the plugin. If it is not found, then the broker sends a v1 packet to fwd_to_tun() forwarder requesting the creation of the mapping. The forwarder then proceeds as in case 1 above which results in returning the mapping to the broker. The broker detects the new mapping and returns it to the plugin.

##### Refresh

Allocations made by the mapper are subject to ageing. If the mappings are not used, they expire and are removed from the data structures. The life of a mapping is extended if it is used in packets passing through the forwarders. This fact is communicated to other parts of the system so that all data structures expire their mappings at the same time. Not every mapping use triggers extension. Only if the remaining life reaches a certain threshold, messages are sent. This prevents excessive communication.

When the fwd_to_tun() extends its mapping, it informs of that action the other parts of the system: the other forwarder fwd_to_gw() and the data base DB.

When the fwd_to_gw() extends its mapping, it only sends the message to the other forwarder fwd_to_tun(). It is then its responsibility to send proper messages to the other parties.

##### Restore from disk
