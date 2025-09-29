# Building IPREF Gateway from Source

For a complete IPREF gateway, you'll need three binaries: `gw`, `dns-agent`, and `coredns` (with the IPREF plugin).

## Quick Build (Recommended)

The easiest way to build all components is using the provided Makefile. This approach automatically builds all three required components and places them in a single `bin/` directory. This is also the approach used by the release workflow.

### Prerequisites

- Go 1.22 or later
- Git
- Make

### Steps

1. Clone all required repositories in the same parent directory:

```bash
# Clone all repositories
git clone https://github.com/ipref/gw
git clone https://github.com/ipref/dns-agent
git clone https://github.com/coredns/coredns
git clone https://github.com/ipref/coredns-plugin-ipref

# Checkout specific CoreDNS version
cd coredns
git checkout v1.12.1
cd ..
```

2. Build all components:

```bash
cd gw
make
```

3. Find binaries in `bin/` directory:

```bash
ls bin/
# Output: gw  dns-agent  coredns
```

The Makefile automatically:
- Builds the gateway binary
- Builds the DNS agent
- Configures and builds CoreDNS with the IPREF plugin
- Places all binaries in `bin/` directory

## Individual Component Builds

You can also build each component separately if needed.

### Building the Gateway

#### Prerequisites

- Go 1.22 or later
- Git

#### Steps

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

#### Verify Installation

```bash
./gw -h
```

You should see the help output with available command-line options.

### Building the DNS Agent

The DNS agent informs the gateway about the mappings between public IPREF addresses and private IP addresses by periodically querying DNS servers.

#### Steps

1. Clone the repository:
```bash
git clone https://github.com/ipref/dns-agent.git
cd dns-agent/
```

2. Build:
```bash
go build
```

The binary will be named `dns-agent`.

#### Verify Installation

```bash
./dns-agent -h
```

### Building CoreDNS with the IPREF Plugin

CoreDNS can be used to host the special resolver (using the `ipref` plugin) and also optionally your `*.internal` and/or your public nameservers.

The special resolver receives requests from the local network and translates AA records into A/AAAA records by asking `gw` to dynamically allocate addresses in the encoding network that are mapped to the IPREF address that appears in the AA record.

#### Prerequisites

- Go 1.22 or later
- Git

#### Steps

1. Clone CoreDNS:
```bash
git clone https://github.com/coredns/coredns.git
cd coredns/
git checkout v1.12.1
```

2. Add IPREF plugin dependency to `go.mod`:
```bash
echo "require github.com/ipref/common v1.3.1" >> go.mod
```

3. Clone the IPREF plugin into CoreDNS plugin directory:
```bash
cd plugin/
git clone https://github.com/ipref/coredns-plugin-ipref.git
mv coredns-plugin-ipref/ ipref/  # Rename to 'ipref'
cd ..
```

4. Register the plugin in `plugin.cfg`:

Add this line to `plugin.cfg` (recommended placement: after the `auto:auto` line):
```
ipref:ipref
```

The order in `plugin.cfg` determines the order that plugins apply.

5. Build CoreDNS:
```bash
make
```

#### Verify Installation

```bash
./coredns -plugins
```

Make sure `ipref` appears in the list of plugins. If not:
- Verify the plugin repo is in `plugin/ipref/` (correct name)
- Ensure the `require` line is still in `go.mod` (Go might remove it if plugin not found)
- Check that `ipref:ipref` is in `plugin.cfg`

## Cross-Platform Builds

### Linux ARM64

```bash
GOOS=linux GOARCH=arm64 go build -o gw-linux-arm64
```

### macOS (Darwin)

```bash
GOOS=darwin GOARCH=amd64 go build -o gw-darwin-amd64
GOOS=darwin GOARCH=arm64 go build -o gw-darwin-arm64
```

### Windows

```bash
GOOS=windows GOARCH=amd64 go build -o gw-windows-amd64.exe
```

## Build Options

### Static Binary

To create a statically-linked binary (useful for containers):

```bash
CGO_ENABLED=0 go build -ldflags="-s -w" -o gw
```

### Debug Build

To build with debug symbols and without optimizations:

```bash
go build -gcflags="all=-N -l" -o gw
```

### Version Information

To embed version information:

```bash
VERSION=$(git describe --tags --always --dirty)
go build -ldflags="-X main.Version=${VERSION}" -o gw
```

## Development Setup

### Running Tests

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run tests with race detection
go test -race ./...
```

### Code Formatting

```bash
# Format all Go files
go fmt ./...

# Run linter (requires golangci-lint)
golangci-lint run
```

### Dependency Management

```bash
# Update dependencies
go get -u ./...
go mod tidy

# Verify dependencies
go mod verify

# Vendor dependencies (optional)
go mod vendor
```

## Troubleshooting

### Build Errors

**Problem**: `package github.com/ipref/common is not in GOROOT`

**Solution**: Run `go mod download` to fetch dependencies.

---

**Problem**: CoreDNS build doesn't include `ipref` plugin

**Solution**:
1. Verify plugin directory is named `plugin/ipref/` (not `plugin/coredns-plugin-ipref/`)
2. Check that `ipref:ipref` line is in `plugin.cfg`
3. Ensure `require github.com/ipref/common v1.3.1` is in `go.mod`
4. Run `make clean && make`

---

**Problem**: `cannot find package` errors during build

**Solution**: Ensure you're using Go 1.22 or later:
```bash
go version
```

### Runtime Errors

**Problem**: `permission denied` when binding to port 1045

**Solution**: Either run as root or grant capabilities. SELinux may also prevent this binding without manual policy creation.
```bash
sudo setcap cap_net_bind_service=+ep ./gw
```

---

**Problem**: `cannot create directory /var/lib/ipref`

**Solution**: Create directories manually:
```bash
sudo mkdir -p /var/lib/ipref /run/ipref
```

## Release Builds

For official releases, use the GitHub Actions workflow (`.github/workflows/release.yml`).

To create a release:

```bash
# Tag the release
git tag v1.0.0
git push origin v1.0.0

# GitHub Actions will automatically build and create release
```

## Container Builds

### Dockerfile Example

```dockerfile
FROM golang:1.22-alpine AS builder

WORKDIR /build
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o gw

FROM scratch
COPY --from=builder /build/gw /gw
ENTRYPOINT ["/gw"]
```

### Build Container

```bash
docker build -t ipref-gw:latest .
```

## Contributing

When contributing code:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `go test ./...`
5. Format code: `go fmt ./...`
6. Commit with clear message
7. Submit pull request

### Code Style

- Follow standard Go conventions
- Use `gofmt` for formatting
- Write tests for new functionality
- Document exported functions and types
- Keep functions focused and concise

## Related Build Documentation

- [Makefile](../Makefile) - Integrated build configuration
- [Release Workflow](../.github/workflows/release.yml) - CI/CD pipeline
- [CoreDNS Plugin Development](https://coredns.io/manual/toc/#writing-plugins) - Plugin build details
