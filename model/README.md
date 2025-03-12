# IPREF Gateway Test Model

This is a simple model of two IPREF Gateways for testing and demonstration.

A description of this model (with VM setup instructions) can be found in
`MODEL.md`. There are also scripts for testing on a single machine using network
namespaces.

## Using the scripts

First, setup the namespaces and virtual network interfaces:

```
./setup
```

Check that everything is configured:

```
# . common.sh
# gw7 ip -c addr
# gw7 cat /etc/hosts
127.0.0.1       gw7
192.168.10.98   gw8
192.168.97.11   host711    #= pub 192.168.10.97 + 10711
10.248.22.222   host822    #= ext 192.168.10.98 + 20822
# gw8 cat /etc/hosts
192.168.10.97   gw7
127.0.0.1       gw8
10.255.11.111   host711    #= ext 192.168.10.97 + 10711
192.168.98.22   host822    #= pub 192.168.10.98 + 20822
# host711 ping gw7
```

Then, in two different shells, run the gateways:

```
. common.sh
cd <ipref/gw repo dir>
run-gw7 # or run-gw8
```

And now:

```
. common.sh
host711 ping host822
```
