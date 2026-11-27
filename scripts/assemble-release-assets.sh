#!/bin/sh
# Assemble the 12 official RONDA release assets from a TAGGED application
# source checkout, using the release tooling of a separate BUILDER checkout.
#
# Two-revision architecture (the v0.1.0 tag predates the release builder):
#   SOURCE_DIR   application source, checked out at the EXACT release tag.
#                Every application input comes from here: the 7 core assets
#                (binaries, archives, SHA256SUMS, release-manifest.json,
#                SBOM.cdx.json — built by make inside SOURCE_DIR with that
#                tree's own Makefile and scripts), install.sh and
#                RELEASE-NOTES-<version>.md.
#   BUILDER_DIR  release-builder tooling checkout (default branch). Only
#                scripts/make-source-archive.sh is invoked from here, so the
#                source archive carries the corrected toolchain guidance
#                while its CONTENT stays the tagged source.
#   DIST_ROOT    build-output directory under SOURCE_DIR (default
#                $SOURCE_DIR/dist). It must be one of the build directories
#                the archiver excludes, so build output can never leak into
#                the published source archive.
#   OUTDIR       final flat asset directory (default $DIST_ROOT/upload).
#
# Uses the existing project packaging logic wherever it exists:
#   make package (scripts/package-release.sh, run in SOURCE_DIR)
#       -> ronda-linux-<arch>, ronda-linux-<arch>.tar.gz, SHA256SUMS,
#          release-manifest.json, SBOM.cdx.json
#   make-source-archive.sh (invoked from BUILDER_DIR over SOURCE_DIR)
#       -> ronda-<version>-source.tar.gz, .sha256 sidecar,
#          ARCHIVE-MANIFEST.json
# Added here (no generator existed in the repo):
#   main.sh          self-contained installer for `curl ... | sh`:
#                    fixed 4-line header + install.sh, byte-deterministic
#   release-notes.md copy of RELEASE-NOTES-<version>.md
#
# The final name set is reconciled against the approved release asset list
# (HANDOFF-v0.1.0.md §7): any missing, extra or renamed asset fails loudly.
# The source-archive name is derived from the Makefile VERSION, so a future
# version bump makes the reconciliation fail here instead of shipping a
# wrongly named archive.
#
# Determinism: every output is a deterministic function of the tagged source
# tree (SOURCE_DATE_EPOCH-normalized tar/gzip, fixed header text, plain
# copies), so two runs on the same tree produce byte-identical assets.
set -eu

HERE=$(cd "$(dirname "$0")/.." && pwd)
SOURCE_DIR=${SOURCE_DIR:-$HERE}
BUILDER_DIR=${BUILDER_DIR:-$HERE}
DIST_ROOT=${DIST_ROOT:-$SOURCE_DIR/dist}
OUTDIR=${OUTDIR:-$DIST_ROOT/upload}

# --- root validation (fail closed) ---------------------------------------------
[ -f "$SOURCE_DIR/Makefile" ] || { echo "assemble: SOURCE_DIR='$SOURCE_DIR' is not an application source tree" >&2; exit 1; }
[ -f "$BUILDER_DIR/scripts/make-source-archive.sh" ] || { echo "assemble: BUILDER_DIR='$BUILDER_DIR' lacks the release tooling (apply the release-builder patch there)" >&2; exit 1; }
# Build outputs must live in a directory the archiver excludes relative to
# SOURCE_DIR — otherwise they would be archived as "source".
case "$DIST_ROOT" in
  "$SOURCE_DIR"/dist|"$SOURCE_DIR"/dist-go127|"$SOURCE_DIR"/dist-repro-1|"$SOURCE_DIR"/dist-repro-2) : ;;
  *) echo "assemble: DIST_ROOT='$DIST_ROOT' is not excluded by make-source-archive.sh; use $SOURCE_DIR/dist or $SOURCE_DIR/dist-go127" >&2; exit 1 ;;
esac

VERSION=$(sed -n 's/^VERSION ?= //p' "$SOURCE_DIR/Makefile")
[ -n "$VERSION" ] || { echo "assemble: cannot read VERSION from $SOURCE_DIR/Makefile" >&2; exit 1; }
ARCHIVE_NAME="ronda-$VERSION-source.tar.gz"
NOTES_NAME="RELEASE-NOTES-$VERSION.md"

# --- approved asset names (must equal HANDOFF-v0.1.0.md §7; 12 entries) -----
APPROVED='ARCHIVE-MANIFEST.json
SBOM.cdx.json
SHA256SUMS
main.sh
release-manifest.json
release-notes.md
ronda-0.1.0-source.tar.gz
ronda-0.1.0-source.tar.gz.sha256
ronda-linux-amd64
ronda-linux-amd64.tar.gz
ronda-linux-arm64
ronda-linux-arm64.tar.gz'

# --- inputs -------------------------------------------------------------------
[ -f "$DIST_ROOT/ronda-linux-amd64" ] && [ -f "$DIST_ROOT/ronda-linux-arm64" ] \
  || { echo "assemble: run 'make -C $SOURCE_DIR DIST=<d> release' first" >&2; exit 1; }
[ -f "$SOURCE_DIR/$NOTES_NAME" ] || { echo "assemble: missing $SOURCE_DIR/$NOTES_NAME" >&2; exit 1; }
[ -f "$SOURCE_DIR/install.sh" ] || { echo "assemble: missing $SOURCE_DIR/install.sh" >&2; exit 1; }

# --- 1. source archive + sidecar + ARCHIVE-MANIFEST (builder tooling over the
#        tagged source; SOURCE_DATE_EPOCH is inherited from the environment and
#        must come from the tagged commit) --------------------------------------
rm -rf "$DIST_ROOT/source"
SOURCE_DIR="$SOURCE_DIR" DIST="$DIST_ROOT" sh "$BUILDER_DIR/scripts/make-source-archive.sh"
[ -f "$DIST_ROOT/source/$ARCHIVE_NAME" ] && [ -f "$DIST_ROOT/source/$ARCHIVE_NAME.sha256" ] \
  && [ -f "$DIST_ROOT/source/ARCHIVE-MANIFEST.json" ] \
  || { echo "assemble: make-source-archive.sh did not produce the expected outputs" >&2; exit 1; }

# --- 2. main.sh: fixed header + install.sh from the tagged tree (deterministic)
mkdir -p "$OUTDIR"
{
  echo "#!/bin/sh"
  echo "# RONDA release installer (main.sh)"
  echo "# Quick Start: curl -fsSL https://github.com/Lutfifakee-Project/ronda/releases/latest/download/main.sh | sh"
  echo "# Generated from install.sh in the RONDA v$VERSION source tree."
  cat "$SOURCE_DIR/install.sh"
} > "$OUTDIR/main.sh"
# prove the payload is exactly the tagged installer (4 header lines)
tail -n +5 "$OUTDIR/main.sh" | cmp - "$SOURCE_DIR/install.sh"

# --- 3. copy every generated asset under its official release name ------------
cp "$DIST_ROOT/ronda-linux-amd64"             "$OUTDIR/ronda-linux-amd64"
cp "$DIST_ROOT/ronda-linux-arm64"             "$OUTDIR/ronda-linux-arm64"
cp "$DIST_ROOT/ronda-linux-amd64.tar.gz"      "$OUTDIR/ronda-linux-amd64.tar.gz"
cp "$DIST_ROOT/ronda-linux-arm64.tar.gz"      "$OUTDIR/ronda-linux-arm64.tar.gz"
cp "$DIST_ROOT/SHA256SUMS"                    "$OUTDIR/SHA256SUMS"
cp "$DIST_ROOT/release-manifest.json"         "$OUTDIR/release-manifest.json"
cp "$DIST_ROOT/SBOM.cdx.json"                 "$OUTDIR/SBOM.cdx.json"
cp "$DIST_ROOT/source/$ARCHIVE_NAME"          "$OUTDIR/$ARCHIVE_NAME"
cp "$DIST_ROOT/source/$ARCHIVE_NAME.sha256"   "$OUTDIR/$ARCHIVE_NAME.sha256"
cp "$DIST_ROOT/source/ARCHIVE-MANIFEST.json"  "$OUTDIR/ARCHIVE-MANIFEST.json"
cp "$SOURCE_DIR/$NOTES_NAME"                  "$OUTDIR/release-notes.md"

# --- 4. reconcile: exactly the approved 12, no extras, no renames -------------
LIST=$(mktemp); APPROVEDF=$(mktemp)
trap 'rm -f "$LIST" "$APPROVEDF"' EXIT
ls -1 "$OUTDIR" | sort > "$LIST"
printf '%s\n' "$APPROVED" | sort > "$APPROVEDF"
if ! diff -u "$APPROVEDF" "$LIST"; then
  echo "assemble: asset name set does not match the approved 12 (see diff above)" >&2
  exit 1
fi
count=$(wc -l < "$LIST" | tr -d ' ')
[ "$count" = 12 ] || { echo "assemble: expected exactly 12 assets, found $count" >&2; exit 1; }

# --- 5. integrity verification -------------------------------------------------
( cd "$OUTDIR" && sha256sum -c SHA256SUMS )               # 4 core artifacts
( cd "$OUTDIR" && sha256sum -c "$ARCHIVE_NAME.sha256" )   # source archive
tar -tzf "$OUTDIR/ronda-linux-amd64.tar.gz" > /dev/null
tar -tzf "$OUTDIR/ronda-linux-arm64.tar.gz" > /dev/null
tar -tzf "$OUTDIR/$ARCHIVE_NAME" > /dev/null
sh -n "$OUTDIR/main.sh"

say() { printf '%s\n' "$*"; }
say "Assembled $count release assets in $OUTDIR (name set = approved 12)."
say "Application source: $SOURCE_DIR — builder tooling: $BUILDER_DIR"
