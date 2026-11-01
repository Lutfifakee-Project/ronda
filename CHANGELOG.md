# Changelog

All notable changes to RONDA are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/) and the project adheres to
[Semantic Versioning](https://semver.org/).

RONDA is a local, READ-ONLY Linux security scanner: it reports; it never
modifies, deletes, quarantines or executes scanned files.

## [0.1.0] — local release candidate (NOT PUBLISHED)

This is the first complete release candidate. It exists and has been
validated **locally only**: nothing has been committed beyond the initial
repository skeleton, no tag exists, and no public GitHub release has been
created. The public repository therefore does not yet represent the
complete accepted source (see "Publication blockers" in the release notes).

### Added

- Recursive file discovery with bounded concurrency and streaming SHA-256
  hashing of every regular file.
- PHP static analysis for webshells, obfuscation and dangerous behaviours
  (lexical-view signal matching, bounded intra-file source-to-sink flows,
  dynamic-callable resolution, webshell behavior chains, polyglot and
  appended-binary indicators).
- Platform detection and integrity scanning: WordPress (core file comparison
  against official checksums, static version reading, locale handling),
  Drupal, Joomla, Laravel, custom PHP projects.
- Linux persistence and backdoor detection: systemd units/timers/drop-ins,
  cron/anacron/at, SSH authorized keys and sshd configuration, shell startup
  files, dynamic-linker hijacking, PAM stacks, kernel modules, udev rules,
  local account checks, referenced-target inspection, cross-artifact
  correlation, MITRE ATT&CK mapping and secret redaction.
- Linux kernel CVE intelligence: distribution-aware running-kernel and
  installed-package inventory, os-release ecosystem and lifecycle
  resolution, vendor feed matching (Debian Security Tracker, Ubuntu OSV,
  Alpine secdb, Arch AVG, Red Hat security data, AlmaLinux OSV) with a
  persistent local cache, evidence-based pending-reboot assessment.
- System security audit (SSH, cron, systemd, PHP configuration).
- Terminal, HTML and JSON reports with severity/confidence metadata and
  documented exit codes (0 clean, 1 findings, 2 usage error).
- `install.sh`: offline/live installer with architecture detection, ELF
  verification, mandatory SHA-256 checks, optional `--pubkey` detached
  Ed25519 signature verification, atomic install with rollback backup.
- `ronda update --check` (metadata-only) and a fail-closed updater that
  refuses any authenticated installation while signing is NOT_CONFIGURED.
- Deterministic release engineering: `make release` / `make repro-check`
  (SOURCE_DATE_EPOCH normalization, two-build byte-identity proof),
  `SHA256SUMS`, `release-manifest.json`, CycloneDX 1.5 `SBOM.cdx.json`
  (zero third-party dependencies), toolchain enforcement
  (`check-toolchain` + CI assertion), installer/updater/toolchain test
  suites.
- GitHub CI workflow: fmt/build/vet/test/race, cross-arch release
  candidate build, artifact validation; pinned to immutable action SHAs,
  minimal permissions, never publishes.

### Security

- Strict READ-ONLY scanning verified by before/after tree-digest evidence.
- No telemetry; network access only for explicitly invoked feed refresh and
  update checks, restricted to official hosts over HTTPS with bounded
  redirects.
- Release toolchain pinned to a supported security-patched Go (go1.27.3)
  and enforced for release builds.

### Known limitations (unchanged by this release)

- Production Ed25519 signing is NOT_CONFIGURED (owner procedure in
  SIGNING.md).
- RPM package ownership provenance is UNVERIFIED (RONDA never invokes
  rpm/dnf/yum).
- Rocky Linux, Fedora and SUSE/openSUSE kernel CVE matching is not
  implemented (UNVERIFIED for those ecosystems).
- Unknown distributions return UNVERIFIED rather than guessed verdicts.
