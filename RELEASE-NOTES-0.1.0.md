# RONDA 0.1.0 — Release Notes (LOCAL RELEASE CANDIDATE)

**Status: LOCAL RELEASE READY — PUBLICATION BLOCKED.** This document
describes a locally validated release candidate. It is not a published
release: nothing has been uploaded to GitHub Releases, no tag exists, and
the public repository does not yet contain the complete application source.

- Application version: 0.1.0 (unchanged; never bumped automatically)
- Detection rules: builtin-5
- Release toolchain: go1.27.3 (supported, security-patched; sha256-verified
  download from go.dev)
- Validated targets: Linux AMD64 and Linux ARM64 (static, stripped, ELF64)
- Signing: **NOT_CONFIGURED** — checksum-verified only, publisher identity
  NOT authenticated (see SIGNING.md)

## Implemented features

- Recursive file discovery with bounded concurrency; streaming SHA-256 of
  every regular file; strict READ-ONLY scanning (tree digests verified
  unchanged before/after scans).
- PHP webshell/obfuscation/behaviour analysis with lexical-view signal
  matching, bounded source-to-sink flows, behavior chains and polyglot
  indicators.
- Platform integrity scanning for WordPress (official-checksum core
  comparison, static version reading, locale variants), Drupal, Joomla,
  Laravel and custom PHP projects.
- Linux persistence/backdoor detection across systemd, cron/anacron/at,
  SSH, shell startup, dynamic linker, PAM, kernel modules, udev and local
  accounts, with cross-artifact correlation, MITRE ATT&CK mapping and
  secret redaction.
- Kernel CVE intelligence with vendor feeds (Debian Security Tracker,
  Ubuntu OSV, Alpine secdb, Arch AVG, Red Hat security data, AlmaLinux
  OSV), persistent offline cache, running-vs-installed kernel separation
  and pending-reboot assessment.
- Terminal/HTML/JSON reports; documented exit codes (0/1/2).
- Safe installer (architecture detection, ELF check, mandatory SHA-256,
  optional detached-signature verification, atomic install, rollback) and
  a fail-closed updater (`ronda update --check` never modifies anything;
  authenticated installation is disabled without a trusted embedded key).
- Deterministic, reproducible release engineering: two-build byte-identity
  proof, SHA256SUMS, release manifest, CycloneDX 1.5 SBOM (stdlib-only,
  zero third-party dependencies), toolchain enforcement with regression
  tests, CI that never publishes.

## Partially supported features

- **Kernel CVE matching for RPM-family distributions**: kernel packages on
  Rocky Linux, Fedora and SUSE/openSUSE are inventoried from `/boot` and
  `/lib/modules`, but CVE matching for these ecosystems is **not
  implemented** and is reported UNVERIFIED. RONDA never invokes rpm/dnf/yum
  (READ-ONLY rule), so RPM package ownership provenance stays UNVERIFIED.
- **Unknown distributions** return UNVERIFIED verdicts instead of guessed
  ones; matching exists for Debian, Ubuntu, Alpine and Arch ecosystems.
- **Publisher authentication**: the detached-signature implementation,
  installer `--pubkey` verification and the embedded-key updater path are
  implemented and tested, but remain **disabled/NOT_CONFIGURED** until the
  project owner supplies and embeds a genuine production public key
  (procedure: SIGNING.md). Until then every artifact is checksum-verified
  but not publisher-authenticated.

## What is NOT supported (do not assume otherwise)

- Rocky Linux / Fedora / SUSE/openSUSE kernel CVE verdicts (UNVERIFIED).
- RPM package database provenance (UNVERIFIED by design).
- Any malware removal, quarantine, patching, service restart or reboot —
  RONDA is strictly read-only and remediation stays with the operator.
- Telemetry of any kind; scan traffic leaves the machine never.

## Verification status of this candidate

- 584 Go test functions across 20 test packages, `-count=1` and `-race`
  green; installer suite 20/20; updater suite green; toolchain enforcement
  suite 12/12; govulncheck (source + both binaries) clean.
- Three independent release builds byte-identical (binaries, archives,
  SHA256SUMS, manifest, SBOM).
- Source archive (`dist-go127/source/`) rebuilds the identical binaries
  independently of the original workspace (see ARCHIVE-MANIFEST.json).

## Publication blockers (must be resolved by the owner before release)

1. The complete accepted source is still untracked in Git; the public
   repository contains only the initial skeleton. The source must be
   committed/pushed by an authorized person — no commit or push has been
   performed or authorized from the agent workspace.
2. Production Ed25519 signing is NOT_CONFIGURED; without it the release can
   ship checksum-only (explicitly labeled) or wait for SIGNING.md steps.
3. No release tag exists; tagging is an owner decision.
4. The release notes must be re-checked at publication time against the
   actual published assets (names, hashes, SIGNING status).

## Verifying this candidate locally

    cd dist-go127
    sha256sum -c SHA256SUMS          # corruption check (not authentication)
    cat release-manifest.json        # toolchain, flags, hashes, signing status

Signature verification will print NOT_CONFIGURED until a production key is
embedded; see SIGNING.md for the owner procedure and for what changes then.
