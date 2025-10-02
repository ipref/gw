DNS_AGENT := ../dns-agent
COREDNS := ../coredns
COREDNS_PLUGIN_IPREF := ../coredns-plugin-ipref

BINS :=
BINS += gw
BINS += dns-agent
BINS += coredns

PWD := $(shell pwd)

# Cross-compilation support
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)
PLATFORM := $(GOOS)-$(GOARCH)

# Build flags for releases
RELEASE_LDFLAGS := -s -w

.PHONY: all
all: $(BINS:%=bin/%)

# Release target for a specific platform
.PHONY: release-$(PLATFORM)
release-$(PLATFORM): $(BINS:%=bin/ipref-%-$(PLATFORM))

# Convenience targets for common platforms
.PHONY: release-linux-amd64
release-linux-amd64:
	@$(MAKE) GOOS=linux GOARCH=amd64 $(BINS:%=bin/ipref-%-linux-amd64)

bin/gw: .FORCE | bin
	go build -o bin/gw .

bin/dns-agent: .FORCE | bin
	go -C $(DNS_AGENT) build -o $(PWD)/bin/dns-agent .

# Release builds with cross-compilation
bin/ipref-gw-$(PLATFORM): .FORCE | bin
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -ldflags="$(RELEASE_LDFLAGS)" -o $@ .

bin/ipref-dns-agent-$(PLATFORM): .FORCE | bin
	GOOS=$(GOOS) GOARCH=$(GOARCH) go -C $(DNS_AGENT) build -ldflags="$(RELEASE_LDFLAGS)" -o $(PWD)/$@ .

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

bin/ipref-coredns-$(PLATFORM): .FORCE | build bin
	mkdir -p build/coredns-$(PLATFORM)/plugin/ipref
	rsync -v -rlp --delete --checksum \
		--exclude .git \
		--exclude /coredns \
		--exclude /core/dnsserver/zdirectives.go \
		--exclude /core/plugin/zplugin.go \
		--exclude /plugin/ipref \
		$(COREDNS)/ \
		build/coredns-$(PLATFORM)/
	echo "require github.com/ipref/common v1.3.1" >> build/coredns-$(PLATFORM)/go.mod
	sed -i -e '/auto:auto/a\' -e 'ipref:ipref' build/coredns-$(PLATFORM)/plugin.cfg
	rsync -v -rlp --delete --checksum \
		--exclude .git \
		$(COREDNS_PLUGIN_IPREF)/ \
		build/coredns-$(PLATFORM)/plugin/ipref/
	GOOS=$(GOOS) GOARCH=$(GOARCH) make -C build/coredns-$(PLATFORM)
	cp build/coredns-$(PLATFORM)/coredns $@

build bin:
	mkdir -p $@

.PHONY: clean
clean:
	rm -rf build bin

.PHONY: .FORCE
.FORCE:
