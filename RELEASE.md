# Release Process

This document describes how to create a new release of the IPREF gateway and all its components.

## Overview

The IPREF release process builds and packages three components from four repositories:

- `ipref/gw` - Gateway service (**versioned**)
- `ipref/dns-agent` - DNS synchronization agent (**versioned**)
- `coredns/coredns` - Upstream CoreDNS (**v1.12.1**)
- `ipref/coredns-plugin-ipref` - IPREF plugin for CoreDNS (**versioned**)

The release workflow in the `gw` repository orchestrates building all components together. Only the `gw` repository is tagged for releases; other components are built from their `main` branches.

## Prerequisites

- Write access to `ipref/gw` repository
- Git configured with appropriate credentials
- Local development environment for testing (optional but recommended)

## Release Steps

### 1. Test the Build Locally

Before creating tags, verify the build works:

```bash
cd /path/to/gw
make release-linux-amd64
```

This will build all three binaries:
- `bin/ipref-gw-linux-amd64`
- `bin/ipref-dns-agent-linux-amd64`
- `bin/ipref-coredns-linux-amd64`

### 2. Determine Version Number

Follow semantic versioning: `vMAJOR.MINOR.PATCH`

- **MAJOR**: Breaking changes
- **MINOR**: New features, backwards compatible
- **PATCH**: Bug fixes, backwards compatible

Example: `v0.1.0`, `v1.2.3`

### 3. Update Component Versions

Edit `.github/workflows/release.yml` and update the component versions at the top:

```yaml
# Component versions - update these when releasing
env:
  DNS_AGENT_REF: v0.1.0             # Update to desired dns-agent tag/branch
  COREDNS_REF: v1.12.1              # Update to desired coredns tag/branch
  COREDNS_PLUGIN_IPREF_REF: v0.1.0  # Update to desired plugin tag/branch
```

These can be tags, branches, or commit SHAs from their respective repositories.

### 4. Commit and Tag `dns-agent` and `coredns-plugin-ipref`

```bash
VERSION="v0.1.0"  # Replace with your version

# Commit the version updates
git add version.go
git commit -m "Release $VERSION: Update component versions"

# Tag the gw repository
git tag -a $VERSION -m "Release $VERSION"
git push --tags
```

### 4. Commit and Tag the Gateway

```bash
VERSION="v0.1.0"  # Replace with your version

# Commit the version updates
git add .github/workflows/release.yml
git commit -m "Release $VERSION: Update component versions"

# Tag the gw repository
git tag -a $VERSION -m "Release $VERSION"
git push origin main
git push origin $VERSION
```

### 5. Monitor the Release Workflow

1. Go to https://github.com/ipref/gw/actions
2. Watch the "Release" workflow run
3. The workflow will:
   - Checkout all four repositories at the specified versions
   - Build all components using the Makefile
   - Create a GitHub release with binaries

### 6. Verify the Release

1. Go to https://github.com/ipref/gw/releases
2. Verify the release contains:
   - `ipref-linux-amd64.tar.gz` (archive with all binaries)
   - `ipref-gw` (individual binary)
   - `ipref-dns-agent` (individual binary)
   - `ipref-coredns` (individual binary)
3. Download and test the binaries

## Testing in Forks

To test the release process without affecting production:

### 1. Fork All Repositories

Fork all four repos to your personal account or test organization.

### 2. Update Workflow Repository References

In your `gw` fork, edit `.github/workflows/release.yml`:

```yaml
# Change:
repository: ipref/dns-agent
# To:
repository: YOUR_USERNAME/dns-agent

# Repeat for coredns and coredns-plugin-ipref
```

### 3. Create Test Tags

```bash
VERSION="v0.0.0-test"

# Tag all four repos in your forks
# ... (same as step 3 above)
```

### 4. Optionally Create Draft Releases

In `.github/workflows/release.yml`, change:

```yaml
draft: false
# To:
draft: true
```

This creates draft releases you can review before publishing.

## Release Checklist

- [ ] Test build locally with `make release-linux-amd64`
- [ ] Determine version number following semver
- [ ] If needed, tag the `dns-agent` and `coredns-plugin-ipref` repositories with their updated versions.
- [ ] Update component versions in `.github/workflows/release.yml`
- [ ] Commit workflow changes
- [ ] Tag the `gw` repository with the release version
- [ ] Monitor GitHub Actions workflow
- [ ] Verify release artifacts are created
- [ ] Test downloaded binaries
- [ ] Update documentation if needed
- [ ] Announce release

## Future Improvements

Potential enhancements to the release process:

1. **Multi-platform builds**: Add ARM64, ARM support
2. **Release notes generation**: Auto-generate from commit messages
3. **Automated testing**: Run integration tests before creating release
4. **Component version tracking**: Document which component versions were used in each release
