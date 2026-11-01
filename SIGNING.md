# RONDA release signing — owner procedure (production status: NOT_CONFIGURED)

RONDA currently ships release candidates whose signature status is
**NOT_CONFIGURED**: no production Ed25519 public key is embedded in the
binary, SHA-256 checksums detect corruption only, and publisher identity is
**not** authenticated. Every automatic authenticated path (in-binary
self-install, `ronda update --install`) stays disabled until the steps in
this document have been performed by the project owner.

This file describes the owner-controlled procedure. The signing key never
touches the agent workspace, CI, or this repository.

## 1. Threat model in one paragraph

An attacker who can substitute a download can also substitute its checksum
file, so SHA-256 verification alone cannot authenticate a release. A detached
Ed25519 signature over `SHA256SUMS`, verified against a public key that is
embedded in the RONDA binary at build time, closes this gap — provided the
private key exists only where the owner controls it and the public key's
provenance is confirmed before it is embedded. RONDA never accepts a trust
key at runtime, from the environment, or from downloaded metadata.

## 2. Checksum verification vs publisher authentication

| Guarantee | SHA-256 checksums | Ed25519 detached signature |
|---|---|---|
| Detects accidental corruption (bad download, truncation) | YES | YES |
| Detects a maliciously replaced artifact + matching checksum file | NO | YES |
| Identifies who produced the artifact set | NO | YES (the holder of the private key) |
| Available in RONDA today | YES (installer always enforces) | NO (NOT_CONFIGURED) |

Checksums and signatures answer different questions; the installer prints
which one applied to every install.

## 3. Key creation (owner, outside the agent workspace)

Perform on a trusted, preferably air-gapped machine that the owner controls
— never in the development sandbox, never on shared CI infrastructure:

    # 3a. Create the production private key.
    umask 077
    openssl genpkey -algorithm ed25519 -out ronda-release-signing.key

    # 3b. Derive the public key and convert it to RONDA's 64-hex-char form
    #     (raw 32-byte Ed25519 public key, no ASN.1 prefix).
    openssl pkey -in ronda-release-signing.key -pubout -outform DER \
      | od -An -tx1 -v | tr -d ' \n' | sed 's/^302a300506032b6570032100//' \
      > ronda-release-signing.pub.hex

Ed25519 keys are single-purpose; generate a key dedicated to RONDA releases
rather than reusing an existing identity key.

## 4. Private key protection (offline)

- Keep `ronda-release-signing.key` on encrypted, offline storage (encrypted
  USB drive or encrypted home directory on an air-gapped machine).
- Never copy it to the development machine, the VPS, CI secrets storage, or
  the repository. Nothing in the release pipeline ever needs it.
- Back it up encrypted in at least two physically separate locations; losing
  the key without a backup means losing the ability to sign (recovery then
  requires rotation, section 8).
- `chmod 600` wherever it rests; consider a hardware token or an OS keychain
  for additional protection. The key file itself has no passphrase (openssl
  Ed25519 PKCS#8); the encryption of its storage is the protection layer.
- Sign on the offline machine only, and move the signature files (and the
  public hex string) to the publishing machine by removable media.

## 5. Public key verification before embedding

The public key becomes the root of trust for every future user, so its
provenance must be established independently:

1. Recompute the hex string from the private key on the offline machine
   (command in 3b) and compare it character-by-character with the value you
   intend to embed.
2. Publish the hex string through a second, independent channel the owner
   controls (e.g. a signed message from an existing long-lived identity, a
   printout, a commit signed with the owner's established GPG key) so users
   can cross-check that the embedded value is really the owner's.
3. Record the fingerprint of the public key (SHA-256 of the 64-hex string)
   in the release notes of the first signed release.

## 6. Integrating the public key into RONDA

The single integration point is a build-time ldflags variable in
`internal/release` (see trust.go / verify.go; there is deliberately no
runtime or environment way to set it):

    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
      -ldflags "-s -w \
        -X github.com/Lutfifakee-Project/ronda/internal/version.Version=0.1.0 \
        -X github.com/Lutfifakee-Project/ronda/internal/version.RulesVersion=builtin-5 \
        -X github.com/Lutfifakee-Project/ronda/internal/release.TrustedPublicKeyHex=<64-hex public key>" \
      -o dist/ronda-linux-amd64 .

After the first build with an embedded key:

- `ronda version` / `ronda update --check` must report
  `Signature verification: CONFIGURED`.
- `go test ./internal/release/` must still pass (the NOT_CONFIGURED test
  skips itself when a key is embedded).
- Rebuild BOTH architectures and confirm `SigningStatus` in the release
  manifest/notes changes only after this intentional, owner-authorized
  build. Until then every release keeps `signingStatus: NOT_CONFIGURED`.

## 7. Producing detached signatures

Sign the checksum file (the artifact set is bound to the signature through
it — every artifact listed in `SHA256SUMS` is covered). The signature is the
raw 64-byte Ed25519 value, hex-encoded, stored as `SHA256SUMS.sig` next to
`SHA256SUMS`:

    openssl pkeyutl -sign -inkey ronda-release-signing.key -rawin \
      -in SHA256SUMS -out sig.raw
    od -An -tx1 -v < sig.raw | tr -d ' \n' > SHA256SUMS.sig
    rm -f sig.raw

Release directory then contains: binaries, `.tar.gz` archives,
`SHA256SUMS`, `SHA256SUMS.sig`, `release-manifest.json`, `SBOM.cdx.json`.

## 8. How installer and updater validate

- **Installer (`install.sh`)** — signature verification is opt-in per run
  with `--pubkey FILE` (the file holds the 64-hex public key). It refuses to
  proceed if openssl is missing, the release has no `SHA256SUMS.sig`, the
  key is malformed, the signature is invalid, or the checksums were tampered
  with. Without `--pubkey` it installs with checksum verification only and
  says explicitly that the publisher was NOT verified. The offline `--source`
  mode uses the same verification path.
- **Updater (in-binary)** — uses only the key embedded at build time
  (section 6). With a key embedded, `ronda update --install` downloads the
  new `SHA256SUMS` and `SHA256SUMS.sig` from the official hosts
  (internal/release allowlist: HTTPS only, pinned paths, bounded redirects),
  verifies the detached signature, then the SHA-256 checksums, then the ELF
  architecture and version monotonicity, and only then atomically replaces
  the binary with a rollback backup. Without an embedded key the updater
  reports NOT_CONFIGURED and refuses any authenticated installation.
- A signature failure is always fatal: no partial installation, no
  fallback to checksum-only for the same download.

## 9. Key rotation

Rotate on a predictable schedule (recommended: annually) or on demand:

1. Generate a NEW key pair (section 3) on the offline machine.
2. Build and publish one transition release that embeds BOTH keys (requires
   a small, reviewed change to internal/release to hold a primary and a
   previous key) signed with the OLD key, announcing the rotation.
3. Build the following release embedding only the NEW key and sign all its
   artifacts with the NEW key.
4. Publish the new public hex string and fingerprint through the independent
   channel (section 5) BEFORE the rotation release ships.
5. Destroy the old private key after the transition window; keep the old
   public key recorded so users can verify historical releases.

## 10. Compromise and revocation

If the private key is suspected or known compromised:

1. Stop signing immediately; quarantine the compromised key.
2. Build and publish a revocation release embedding the replacement key only
   (or key pair during transition), signed by the new key. Because the trust
   root is the embedded key, a compromised key is neutralized by no longer
   embedding it and by shipping updates that embed the successor.
3. Announce the compromise through every independent channel (project site,
   repository README, release notes) with the affected fingerprint and the
   affected version range, so users can re-verify any artifact signed during
   the window against the new key.
4. Do not attempt to "undo" already-published signatures; artifacts signed
   during the compromise window must be treated as untrusted and re-downloaded
   from the revocation release.

## 11. Current status

- Production signing: **NOT_CONFIGURED**. No production key exists in this
  workspace; none was generated; none may be generated on the owner's behalf.
- The signature implementation and its rejection paths are regression-tested
  (internal/release, internal/update, install.sh suite) using disposable,
  clearly non-production test keypairs that are generated inside test
  sandboxes and never committed.
- The one end-to-end demonstration in the Phase 7.2 evidence (sign → verify
  → tamper-reject) used such a disposable keypair in `/tmp`, deleted
  afterwards. No test key material exists in the repository or its history.
