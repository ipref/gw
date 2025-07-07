DNS_AGENT := ../dns-agent
COREDNS := ../coredns
COREDNS_PLUGIN_IPREF := ../coredns-plugin-ipref

BINS :=
BINS += gw
BINS += dns-agent
BINS += coredns

PWD := $(shell pwd)

.PHONY: all
all: $(BINS:%=bin/%)

bin/gw: .FORCE | bin
	go build -o bin/gw .

bin/dns-agent: .FORCE | bin
	go -C $(DNS_AGENT) build -o $(PWD)/bin/dns-agent .

bin/coredns: .FORCE | build bin
	mkdir -p build/coredns/plugin/ipref
	rsync -v -rlp --delete --checksum \
		--exclude .git \
		--exclude /coredns \
		--exclude /core/dnsserver/zdirectives.go \
		--exclude /core/plugin/zplugin.go \
		--exclude /plugin/ipref \
		$(COREDNS)/ \
		build/coredns/
	echo "require github.com/ipref/common v1.3.1" >> build/coredns/go.mod
	sed -i -e '/auto:auto/a\' -e 'ipref:ipref' build/coredns/plugin.cfg
	rsync -v -rlp --delete --checksum \
		--exclude .git \
		$(COREDNS_PLUGIN_IPREF)/ \
		build/coredns/plugin/ipref/
	make -C build/coredns
	cp build/coredns/coredns $@

build bin:
	mkdir -p $@

.PHONY: clean
clean:
	rm -rf build bin

.PHONY: .FORCE
.FORCE:
