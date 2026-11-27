# RONDA 0.1.0 — Release Notes (LOCAL RELEASE CANDIDATE)

**Status: LOCAL RELEASE READY — PUBLICATION PENDING (owner action).** This
document describes a locally validated release candidate. It is not a
published release: nothing has been uploaded to GitHub Releases and no tag
exists. The complete application source IS committed and pushed —
origin/main matches the local HEAD (7e2396f); tagging and publishing
remain owner decisions.

- Application version: 0.1.0 (unchanged; never bumped automatically)
- Detection rules: builtin-5
- Release toolchain: go1.27.4 (supported, security-patched; sha256-verified
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

- 591 Go test functions across 21 test packages, `-count=1` and `-race`
  green; installer suite 20/20; updater suite green; toolchain enforcement
  suite 12/12; govulncheck (source + both binaries) clean.
- Three independent release builds byte-identical (binaries, archives,
  SHA256SUMS, manifest, SBOM).
- Source archive (`dist-go127/source/`) rebuilds the identical binaries
  independently of the original workspace (see ARCHIVE-MANIFEST.json).

## Publication blockers (must be resolved by the owner before release)

1. [RESOLVED] The complete source is committed and pushed: origin/main
   matches the local HEAD (7e2396f, "fix(installer): preserve Ed25519
   bytes under UTF-8 locales"). Publication now needs only a tag, a
   GitHub release, and the owner's signing decision (blockers 2-4).
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

## Post-publication verification checklist (owner)

Run these only AFTER the release exists on GitHub; before publication none of
them can pass:

1. GitHub Release `v0.1.0` exists and is public.
2. The tag points to the approved source commit.
3. All release assets are present: `main.sh`, `ronda-linux-amd64`,
   `ronda-linux-arm64`, `ronda-linux-amd64.tar.gz`, `ronda-linux-arm64.tar.gz`,
   `SHA256SUMS`, `release-manifest.json`, `SBOM.cdx.json`,
   `ronda-0.1.0-source.tar.gz` (+`.sha256`, `ARCHIVE-MANIFEST.json`),
   `release-notes.md`.
4. `main.sh` is reachable at
   https://github.com/Lutfifakee-Project/ronda/releases/latest/download/main.sh
5. `ronda-linux-amd64` downloads correctly from the same `latest/download` URL.
6. `ronda-linux-arm64` downloads correctly.
7. `sha256sum -c SHA256SUMS` passes on the downloaded assets.
8. The exact Quick Start command works on a clean Linux machine (no Go, no
   compiler): `curl -fsSL https://github.com/Lutfifakee-Project/ronda/releases/latest/download/main.sh | sh`
9. The installed binary reports `RONDA 0.1.0` (`ronda version`).
10. A basic scan (`ronda scan <dir>`, `ronda persist`) works after installation
    and exits 0/1/2 per the documented contract.
