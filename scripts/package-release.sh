#!/bin/sh
# Package a RONDA release candidate.
#
# Inputs:  dist/ronda-linux-amd64 and dist/ronda-linux-arm64 (built by make)
# Outputs (all inside $DIST):
#   ronda-linux-<arch>.tar.gz    binary + README.md + LICENSE + install.sh
#   SHA256SUMS                   checksums of binaries and archives
#   release-manifest.json        build metadata and artifact hashes
#   SBOM.cdx.json                CycloneDX 1.5 bill of materials
#
# The packaging is deterministic when SOURCE_DATE_EPOCH is exported: tar
# member metadata is normalized and gzip runs without a timestamp.
set -eu

DIST=${DIST:-dist}
HERE=$(cd "$(dirname "$0")/.." && pwd)
cd "$HERE"

[ -f "$DIST/ronda-linux-amd64" ] || { echo "package-release: missing $DIST/ronda-linux-amd64 (run: make amd64)" >&2; exit 1; }
[ -f "$DIST/ronda-linux-arm64" ] || { echo "package-release: missing $DIST/ronda-linux-arm64 (run: make arm64)" >&2; exit 1; }
[ -f README.md ] && [ -f LICENSE ] && [ -f install.sh ] || { echo "package-release: README.md, LICENSE and install.sh are required" >&2; exit 1; }

# Version/Rules/Commit/Date are supplied by the Makefile via the environment.
: "${RONDA_VERSION:?RONDA_VERSION must be set by make package}"
: "${RONDA_RULES:?RONDA_RULES must be set by make package}"
: "${RONDA_COMMIT:?RONDA_COMMIT must be set by make package}"
: "${RONDA_DATE:?RONDA_DATE must be set by make package}"
: "${RONDA_GOVERSION:?RONDA_GOVERSION must be set by make package}"
: "${RONDA_LDFLAGS:?RONDA_LDFLAGS must be set by make package}"
: "${RONDA_SIGNING:?RONDA_SIGNING must be set by make package}"

EPOCH=${SOURCE_DATE_EPOCH:-}
if [ -n "$EPOCH" ]; then
  TAR_MTIME="--mtime=@$EPOCH"
  REPRO=source-date-epoch
else
  TAR_MTIME="--mtime=0"
  REPRO=not-normalized
fi

# --- archives ---------------------------------------------------------------
# Layout inside each archive (top-level directory):
#   ronda-linux-<arch>/ronda          the binary
#   ronda-linux-<arch>/README.md      overview and usage
#   ronda-linux-<arch>/LICENSE        MIT license text
#   ronda-linux-<arch>/install.sh     the safe installer
STAGE=$DIST/.stage
rm -rf "$STAGE"
trap 'rm -rf "$STAGE"' EXIT
for ARCH in amd64 arm64; do
  mkdir -p "$STAGE/ronda-linux-$ARCH"
  cp "$DIST/ronda-linux-$ARCH" "$STAGE/ronda-linux-$ARCH/ronda"
  cp README.md LICENSE install.sh "$STAGE/ronda-linux-$ARCH/"
  ( cd "$STAGE" && tar \
      --sort=name \
      --owner=0 --group=0 --numeric-owner \
      $TAR_MTIME \
      -cf - "ronda-linux-$ARCH" \
      | gzip -n > "$HERE/$DIST/ronda-linux-$ARCH.tar.gz" )
done
rm -rf "$STAGE"

# --- checksums ---------------------------------------------------------------
# SHA256SUMS covers the distributable artifacts (binaries + archives).
cd "$DIST"
rm -f SHA256SUMS
for f in ronda-linux-amd64 ronda-linux-arm64 ronda-linux-amd64.tar.gz ronda-linux-arm64.tar.gz; do
  sha256sum "$f" >> SHA256SUMS
done
cd "$HERE"

# --- manifest and SBOM (deterministic Go generators) --------------------------
TIMESTAMP=$RONDA_DATE
EPOCH_FLAG=""
if [ -n "$EPOCH" ]; then
  EPOCH_FLAG="-source-date-epoch $EPOCH"
fi
# shellcheck disable=SC2086
go run ./tools/genmanifest \
  -dist "$DIST" \
  -version "$RONDA_VERSION" \
  -rules "$RONDA_RULES" \
  -commit "$RONDA_COMMIT" \
  -date "$RONDA_DATE" \
  -go-version "$RONDA_GOVERSION" \
  -signing-status "$RONDA_SIGNING" \
  -ldflags "$RONDA_LDFLAGS" \
  $EPOCH_FLAG

# shellcheck disable=SC2086
go run ./tools/gensbom \
  -out "$DIST/SBOM.cdx.json" \
  -version "$RONDA_VERSION" \
  -rules "$RONDA_RULES" \
  -commit "$RONDA_COMMIT" \
  -go-version "$RONDA_GOVERSION" \
  -timestamp "$TIMESTAMP"

# --- summary ------------------------------------------------------------------
say() { printf '%s\n' "$*"; }
say "Packaged $DIST:"
ls -1 "$DIST" | while IFS= read -r f; do say "  $f"; done
say "Reproducibility: $REPRO"
say "Signing: $RONDA_SIGNING"
