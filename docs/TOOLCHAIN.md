# RONDA build toolchain policy

RONDA is released as a standalone static binary. The Go toolchain that
builds the release artifacts is part of the release's security surface: it
determines which compiler and standard-library code (including all security
fixes) ends up in the shipped binary. This document states exactly how the
toolchain is selected, enforced, and upgraded.

## The three version layers

| Layer | Where declared | Current value | Meaning |
|---|---|---|---|
| Module language level | `go` directive in go.mod | `go 1.21` | Minimum language/stdlib semantics the source requires. This is a floor, not a build instruction. |
| Release build toolchain | `toolchain` directive in go.mod | `go1.27.3` | The exact toolchain that builds release artifacts. Selected automatically by GOTOOLCHAIN=auto; verified by `make check-toolchain`. |
| CI toolchain | `.github/workflows/ci.yml` | setup-go v6 (SHA-pinned), reads go.mod | CI installs the `toolchain` directive's version and asserts the selection. |

The compiled binary never needs Go at runtime.

## How selection works (GOTOOLCHAIN)

Go's toolchain management is documented upstream at
<https://go.dev/doc/toolchain>. In short:

- **`GOTOOLCHAIN=auto` (the Go default):** any Go >= 1.21 that runs a
  command inside this module selects the version named by the `toolchain`
  directive (downloading it on demand if it is not installed). Building on
  a machine whose only Go is older or newer still produces artifacts from
  the declared toolchain. `go env GOVERSION` then reports the selected
  toolchain.
- **`GOTOOLCHAIN=local`:** no switching ever happens; the installed Go is
  used as-is. If it differs from the declared toolchain, the release targets
  fail closed (see below) instead of silently shipping a differently built
  binary.

Important technical distinction: the `toolchain` directive is a *selector*,
not by itself an unconditional hard requirement. It guarantees the version
used under the default `auto` mode; it does not stop a person from running
a raw `go build` with `GOTOOLCHAIN=local` and a different toolchain.

## What is enforced, and what is not

Enforced (fail-closed):

- `make check-toolchain` compares `go env GOVERSION` with the `toolchain`
  directive and exits non-zero on any mismatch (older *or* newer).
- `make package` (and therefore `make release` and `make repro-check`)
  depends on `check-toolchain`; a mismatch aborts before any artifact is
  built. The release manifest records the toolchain that actually built the
  artifacts, and CI cross-checks it against go.mod.
- CI asserts the toolchain selected by setup-go equals the go.mod
  declaration before building anything.

NOT enforced (documented gaps — do not overstate the guarantees):

- A hand-typed `go build ./...` or `CGO_ENABLED=0 go build ... -o ronda .`
  bypasses the Makefile entirely. Under `GOTOOLCHAIN=auto` (the default) it
  still uses the declared toolchain, but under `GOTOOLCHAIN=local` it uses
  whatever is installed. Raw developer builds are therefore *convenience*
  builds, not release builds.
- The `toolchain` line alone does not force the exact patch version; the
  enforcement for releases comes from `check-toolchain` + CI assertion.

Regression tests for the enforcement live in `scripts/test-toolchain.sh`
(`make test-toolchain`). They hermetically verify the mismatch rejection
with a fake `go` shim, so no second Go installation is required.

## Developer builds vs release builds

- Developer build: `make build` (or a raw `go build`). The embedded
  `Go:` version string and the build's provenance reflect whatever toolchain
  actually ran; these builds are for local iteration only.
- Release build: `make release` (or `make DIST=<dir> release`). Requires the
  declared toolchain, normalizes timestamps via `SOURCE_DATE_EPOCH`, records
  the toolchain and flags in `release-manifest.json`, and leaves signing
  status `NOT_CONFIGURED` until a production key exists.

## Upgrading to a future security patch (predictable procedure)

1. Check <https://go.dev/dl/> for the latest stable release and note its
   official SHA-256 from the same page's JSON feed.
2. Download the archive only from `https://go.dev/dl/`, verify the SHA-256,
   and install it alongside (not over) the previous toolchain.
3. Change exactly one line in go.mod: `toolchain go1.27.3` becomes
   `toolchain go1.<next>.<patch>`. Do not change the `go 1.21` language
   directive unless the source genuinely needs newer language features.
4. `make lint && make test && make race`, then `make repro-check`.
5. Rebuild the release candidate (`make DIST=dist-go127 release` — or a new
   directory when the previous one must stay frozen), regenerate the SBOM
   and manifest (automatic), and re-run `make test-installer` and
   `make test-toolchain`.
6. Record the new toolchain, its checksum verification, and the new artifact
   hashes in the release evidence. CI picks the version up from go.mod.

The Makefile `check-toolchain` target and the CI assertion make the upgrade
a one-line change: everything else fails loudly until the environment
matches.
