# RONDA - Local Linux Security Scanner

Scan. Detect. Protect.

RONDA is a fast, single-binary Linux security scanner for VPS administrators.
It inspects web applications, PHP source, kernel state and system
configuration for backdoors, webshells, unauthorized modifications and known
kernel vulnerabilities.

It runs entirely on the local filesystem. Website source, scanned files and
private scan results are __never__ uploaded to external services. Network
access is only used for official vulnerability reference data (with your
explicit action, e.g. `ronda kernel`) and the update check; scans themselves
never transmit anything. There is no telemetry.

## What RONDA does and does not do

RONDA is strictly READ-ONLY. It never modifies, deletes, quarantines or
executes scanned files, never installs patches, never changes system
configuration and never reboots. It reports; remediation stays with you.
The installer and the updater are the only components that write anything,
and they only ever touch RONDA's own installation path.

## Features

- Recursive file discovery with bounded concurrency.
- Streaming SHA-256 hashing of every regular file.
- PHP static analysis for webshells, obfuscation and dangerous behaviours.
- Platform detection and integrity scanning (WordPress, Drupal, Joomla,
  Laravel, custom PHP).
- Linux kernel CVE intelligence against authoritative vendor security data
  (Debian Security Tracker, Ubuntu OSV, Alpine secdb, Arch security,
  Red Hat security data, AlmaLinux OSV) with distribution-aware package
  version comparison, kernel flavors, installed-vs-running kernel separation
  and evidence-based pending-reboot assessment.
- Linux persistence and backdoor detection (systemd, cron, SSH, shell
  startup, dynamic linker, PAM, kernel modules, udev, accounts).
- Linux system audit: SSH, cron, systemd, PHP configuration.
- Terminal, HTML and JSON reports.
- Works as root or a regular user.

## Supported platforms

- Linux on amd64 (x86_64) and arm64 (aarch64).
- CMS/framework detection: WordPress, Drupal, Joomla, Laravel, custom PHP.
- Kernel CVE matching: Debian, Ubuntu, Alpine, Arch. RPM-family kernels are
  inventoried from `/boot` and `/lib/modules`, but CVE matching is reported
  UNVERIFIED because the rpm database is not statically readable (RONDA never
  invokes rpm/dnf/yum).

## Requirements

- Linux (amd64 or arm64).
- No Go, PHP or Python runtime is required to run the binary.
- `curl` or `wget` only for downloads; `sha256sum` for verification;
  `openssl` only if you use installer signature verification.

## Installation

Download the official release binaries from the project's GitHub releases
page, verify them, and run the installer from a file (never pipe a remote
script into a shell):

    curl -fsSL -o install.sh https://raw.githubusercontent.com/Lutfifakee-Project/ronda/main/install.sh
    less install.sh                      # review it first
    sh install.sh                        # system-wide if root, else ~/.local/bin
    sh install.sh --prefix "$HOME/.local"  # explicit user-local install

The installer:

1. detects Linux and your architecture (amd64/arm64),
2. downloads the exact matching artifact from the official release only,
3. verifies the SHA-256 checksum against the published `SHA256SUMS`,
4. verifies the Ed25519 signature over `SHA256SUMS` when you pass `--pubkey`,
5. checks the artifact's ELF architecture,
6. refuses symlinked or unrelated destinations,
7. installs atomically and keeps the previous binary as `ronda.old`.

Options: `--prefix DIR`, `--version TAG`, `--arch amd64|arm64`,
`--source DIR` (install from a local release directory - for offline or
air-gapped VPS), `--pubkey FILE`, `--help`.

### Verifying release integrity

Checksums (always enforced) detect corruption; they do not authenticate the
publisher. Publisher authentication uses a detached Ed25519 signature over
`SHA256SUMS`, verified against a public key embedded in the binary at build
time. Current signature status: **NOT_CONFIGURED** - no production signing
key has been embedded yet, so RONDA refuses authenticated self-installation
and prints the manual verification steps instead. When a trusted key is
configured in a future release, `ronda update --install` becomes available.

### Build from source

Building from source needs a Go toolchain as declared in `go.mod`: the
module language level is `go 1.21` and the authoritative release toolchain
is `go1.27.3` (a supported, security-patched release; see docs/TOOLCHAIN.md).
With the default `GOTOOLCHAIN=auto`, any Go >= 1.21 automatically selects
the declared toolchain; the release targets refuse to build with a different
one. The resulting binary is standalone: it never needs Go on the target VPS.

    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o ronda .

`make release` builds the deterministic release candidate (amd64 + arm64,
archives, `SHA256SUMS`, `release-manifest.json`, `SBOM.cdx.json`);
`make repro-check` builds twice and proves the artifacts byte-identical.

## Usage

    ronda help            # overview
    ronda version         # binary version, rules version, build info, platform
    ronda scan /home/     # auto-detect and scan web applications
    ronda persist         # Linux persistence and backdoor scan
    ronda kernel          # kernel CVE assessment against vendor data
    ronda system          # system security audit
    ronda update --check  # check for a newer release (never installs)

### Scan

    ronda scan /home/
    ronda scan /home/user/ --wordpress
    ronda scan /home/user/ --drupal --joomla   # platform flags combine
    ronda scan /home/ --all
    ronda scan /home/ --format json --output report.json
    ronda scan /home/ --format html --output report.html

Platform flags: `--wordpress`, `--drupal`, `--joomla`, `--laravel`, `--php`
(combinable), `--all` (exclusive with explicit flags), `--persist` (also
treat the target as a root filesystem). Other options: `--format
terminal|json|html`, `--output PATH`, `--workers N`, `--wp-locale LOCALE`,
`--offline`. Exit codes: `0` no actionable findings, `1` actionable
findings, `2` invalid usage.

### WordPress core integrity

When a WordPress installation is found, RONDA reads its version statically
(never executing PHP) and compares every core file against the official
checksums from api.wordpress.org for that exact version and locale. Files
are reported as CLEAN, MODIFIED, MISSING, or UNVERIFIED, and unexpected
files under wp-admin/ and wp-includes/ are listed conservatively. wp-content,
plugins and themes are not treated as core.

### Kernel CVE intelligence

    ronda kernel [--root <path>] [--offline] [--refresh] [--upstream]
                 [--format terminal|json|html] [--timeout <secs>]

`ronda kernel` identifies the distribution, the running kernel and every
installed kernel package, then matches them against the vendor's own
advisory data. Distribution backports are respected: only the vendor's own
fixed-version decides, never an upstream version comparison. The running
kernel and installed packages are reported separately, and container
userlands are distinguished from the host kernel. An evidence-based pending
reboot assessment is included.

- **Debian/Ubuntu**: Debian Security Tracker / Ubuntu OSV, matched per
  release codename with the dpkg comparator.
- **Alpine**: secdb for the matching release.
- **Arch**: the Arch Security Tracker AVG.
- **RPM family (Rocky, Fedora, SUSE/openSUSE, ...)**: package inventory from
  `/boot` and `/lib/modules` with disclosed UNVERIFIED provenance; CVE
  matching stays UNVERIFIED - RONDA never invokes rpm/dnf/yum.
- Unknown distributions: everything UNVERIFIED, never guessed.

Vendor feed data is cached under `~/.cache/ronda/kernel-feeds` (0600
permissions) and reused offline; `ronda system` always runs kernel
intelligence cache-only. An empty CVE list is never a statement that the
system is secure - check the data trust level in the report
(`fresh-official-data`, `offline-cache`, stale, or missing).

## Reports

Formats: terminal (default), JSON (`--format json`), HTML
(`--format html --output report.html`). Findings carry a status
(CLEAN, MODIFIED, MISSING, EXTRA, SUSPICIOUS, VULNERABLE, AFFECTED, FIXED,
NOT_AFFECTED, UNDER_INVESTIGATION, UNVERIFIED), a severity
(CRITICAL, HIGH, MEDIUM, LOW, INFO), a confidence level and the data trust
level of any feed used. Reports never contain passwords, keys or tokens;
credentials found during persistence scans are redacted.

## Privacy

- Scans never send any data anywhere.
- `ronda kernel` (and WordPress checksum verification) contact official
  vendor hosts only: security-tracker.debian.org,
  security-metadata.canonical.com, api.osv.dev, secdb.alpinelinux.org,
  security.archlinux.org, access.redhat.com, security.almalinux.org,
  api.wordpress.org. Requests contain only package names and versions
  needed to query the feed - never file contents, credentials or hostnames.
- The persistent cache lives in `~/.cache/ronda/kernel-feeds` and never
  leaves the machine.
- The update check queries `api.github.com` for the latest release tag.
- There is no telemetry, accounting or crash reporting.

## Limitations (current version 0.1.0)

RONDA reports honestly what it can and cannot verify:

- Drupal, Joomla and Laravel release baselines are not implemented; their
  results are analysis, not proof of integrity.
- RPM package ownership is UNVERIFIED: Rocky Linux, Fedora and
  SUSE/openSUSE CVE matching is not implemented. These distributions are
  never described as fully scanned.
- Unknown distributions return UNVERIFIED data.
- No full VM-based distribution assessment was performed during validation.
- `ronda update` is check-only in this build: signature verification is
  NOT_CONFIGURED, so authenticated self-replacement stays disabled by
  design and the manual steps are printed instead.
- Memory guidance: kernel feed parsing on Debian-family hosts stays bounded
  (about 75-90 MiB peak RSS in validation); large filesystem scans run in
  the tens of MiB. Very low-memory VPS (<512 MB) should run kernel
  assessments with `--offline` after the cache is warm.

## License

MIT. Developed by Lutfifakee-Project.
