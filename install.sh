#!/bin/sh
# RONDA installer.
#
# Installs the RONDA Linux binary from an official release, or from a local
# release-candidate directory (--source), after verifying:
#   1. the SHA-256 checksum against SHA256SUMS (mandatory), and
#   2. the detached Ed25519 signature over SHA256SUMS when --pubkey is given
#      (requires openssl; the signature file is SHA256SUMS.sig, hex-encoded).
#
# The installer never runs sudo, never pipes remote content into a shell,
# never disables TLS verification and never installs an unverifiable binary
# silently. An existing RONDA binary is preserved as <dest>.old until the
# new one is fully in place.
#
# Usage:
#   ./install.sh                        install the latest official release
#   ./install.sh --version v0.1.1       install a specific release
#   ./install.sh --prefix "$HOME/.local"  install into $PREFIX/bin/ronda
#   ./install.sh --source ./dist        install from a local release directory
#   ./install.sh --pubkey ronda.pub     verify the Ed25519 signature first
#   ./install.sh --arch arm64           override architecture detection
#   ./install.sh --help
#
# Supported environments: Linux amd64 or arm64, POSIX sh (dash, bash, ash),
# curl or wget for downloads, sha256sum for verification, openssl only when
# signature verification is requested. Offline machines must use --source.
set -eu

REPO=Lutfifakee-Project/ronda
BASE=https://github.com/$REPO/releases
BIN=ronda

PREFIX=""
SRC=""
PUBKEY=""
WANT_VERSION=""
WANT_ARCH=""

say() { printf '%s\n' "$*"; }
die() { printf 'install.sh: %s\n' "$*" >&2; exit 1; }
trap 'rm -rf "$TMP"' EXIT
TMP=""

usage() {
  cat <<EOF
RONDA installer - install the RONDA Linux security scanner.

Usage: ./install.sh [options]

Options:
  --prefix DIR    Install into DIR/bin/ronda (default: /usr/local/bin when
                  root, otherwise \$HOME/.local/bin)
  --version TAG   Install a specific release tag, e.g. --version v0.1.1
                  (default: the latest published release)
  --source DIR    Install from a local release directory that contains
                  ronda-linux-<arch>, SHA256SUMS and optionally
                  SHA256SUMS.sig. No download is performed.
  --pubkey FILE   Verify the Ed25519 signature over SHA256SUMS against the
                  public key in FILE (64 hex characters). Requires openssl.
  --arch ARCH     Force amd64 or arm64 instead of auto-detection.
  --help          Show this help.

Security notes:
  - Downloads use HTTPS only from the official repository hosts.
  - The SHA-256 checksum is always verified against SHA256SUMS.
  - Without --pubkey the publisher identity is NOT verified; the installer
    prints this limitation explicitly.
  - The previous binary is kept as <dest>.old for manual rollback.

Examples:
  sudo ./install.sh
  ./install.sh --prefix "\$HOME/.local"
  ./install.sh --source ./dist --pubkey ronda-release.pub
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --help|-h) usage; exit 0 ;;
    --prefix) [ $# -ge 2 ] || die "--prefix requires a value"; PREFIX=$2; shift 2 ;;
    --version) [ $# -ge 2 ] || die "--version requires a value"; WANT_VERSION=$2; shift 2 ;;
    --source) [ $# -ge 2 ] || die "--source requires a value"; SRC=$2; shift 2 ;;
    --pubkey) [ $# -ge 2 ] || die "--pubkey requires a value"; PUBKEY=$2; shift 2 ;;
    --arch) [ $# -ge 2 ] || die "--arch requires a value"; WANT_ARCH=$2; shift 2 ;;
    *) usage >&2; die "unknown option: $1" ;;
  esac
done

# --- platform ---------------------------------------------------------------

OS=$(uname -s)
[ "$OS" = "Linux" ] || die "RONDA supports Linux only (found $OS). The installer does not support macOS, BSD or Windows."

MACHINE=$(uname -m)
case "${WANT_ARCH:-$MACHINE}" in
  x86_64|amd64)  ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "unsupported architecture: ${WANT_ARCH:-$MACHINE} (supported: x86_64/aarch64)" ;;
esac
ASSET=$BIN-linux-$ARCH

# --- destination ------------------------------------------------------------

if [ -n "$PREFIX" ]; then
  DEST_DIR=$PREFIX/bin
elif [ "$(id -u)" -eq 0 ]; then
  DEST_DIR=/usr/local/bin
else
  DEST_DIR=$HOME/.local/bin
fi
DEST=$DEST_DIR/$BIN

if [ -L "$DEST" ]; then
  die "$DEST is a symlink; refusing to install through it. Remove the link or choose another --prefix."
fi
if [ -e "$DEST" ] && [ ! -f "$DEST" ]; then
  die "$DEST exists and is not a regular file; refusing to touch it."
fi
if [ -e "$DEST" ] && [ ! -x "$DEST" ]; then
  die "$DEST exists but is not executable; refusing to replace an unrelated file."
fi
# Refuse to overwrite a non-RONDA executable that happens to sit at $DEST.
if [ -x "$DEST" ] && ! "$DEST" version 2>/dev/null | head -n 1 | grep -q '^RONDA '; then
  die "$DEST exists and is not RONDA (its 'version' output was unrecognized); refusing to overwrite it."
fi
if ! mkdir -p "$DEST_DIR" 2>/dev/null; then
  die "cannot create $DEST_DIR (permission denied). Re-run with --prefix \"\$HOME/.local\" for a user-local install."
fi
if [ ! -w "$DEST_DIR" ]; then
  die "$DEST_DIR is not writable by the current user. Re-run with --prefix \"\$HOME/.local\", or use sudo explicitly if you intend a system-wide install."
fi

TMP=$(mktemp -d "${TMPDIR:-/tmp}/ronda-install.XXXXXX")

# --- acquisition ------------------------------------------------------------

if [ -n "$SRC" ]; then
  [ -d "$SRC" ] || die "--source $SRC is not a directory"
  cp "$SRC/$ASSET" "$TMP/$BIN" || die "no artifact for $ARCH in $SRC (expected $ASSET)"
  cp "$SRC/SHA256SUMS" "$TMP/SHA256SUMS" || die "no SHA256SUMS in $SRC; refusing to install unverified files"
  [ -f "$SRC/SHA256SUMS.sig" ] && cp "$SRC/SHA256SUMS.sig" "$TMP/SHA256SUMS.sig" || true
  say "Source: local release directory $SRC"
else
  if [ -n "$WANT_VERSION" ]; then
    REL=$BASE/download/$WANT_VERSION
  else
    REL=$BASE/latest/download
  fi
  command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 \
    || die "curl or wget is required to download RONDA (or use --source with a local release directory)."
  fetch() {
    if command -v curl >/dev/null 2>&1; then
      curl -fsSL --max-redirs 5 --max-time 300 "$1" -o "$2"
    else
      wget -qT300 -O "$2" "$1"
    fi
  }
  say "Source: $REL/$ASSET"
  fetch "$REL/$ASSET" "$TMP/$BIN" \
    || die "download failed. Check the release exists ($REL) and your network connection."
  fetch "$REL/SHA256SUMS" "$TMP/SHA256SUMS" \
    || die "no SHA256SUMS published for this release; refusing to install an unverified binary."
  fetch "$REL/SHA256SUMS.sig" "$TMP/SHA256SUMS.sig" 2>/dev/null || rm -f "$TMP/SHA256SUMS.sig"
fi

# --- verification -----------------------------------------------------------

WANT=$(awk -v a="$ASSET" '$2 == a || $2 == "*"a {print $1}' "$TMP/SHA256SUMS")
[ -n "$WANT" ] || die "no checksum entry for $ASSET in SHA256SUMS; refusing to install."
GOT=$(sha256sum "$TMP/$BIN" | awk '{print $1}')
[ "$WANT" = "$GOT" ] || die "SHA-256 mismatch for $ASSET (want $WANT, got $GOT); the download is corrupt or tampered with. Refusing to install."
say "Checksum: OK ($GOT)"

# --- ELF architecture check -------------------------------------------------
# A checksum can only prove the bytes match the manifest; verify the binary
# can actually run on this machine before replacing anything. e_machine is
# the unsigned 16-bit field at ELF offset 18 (little-endian on the targets
# RONDA ships): 62 = x86-64, 183 = AArch64.
ELFARCH=$(od -An -tu2 -j18 -N2 "$TMP/$BIN" | tr -d ' ')
case "$ARCH:$ELFARCH" in
  amd64:62)  : ;;
  arm64:183) : ;;
  *) die "ELF architecture mismatch: the artifact targets e_machine ${ELFARCH:-unknown}, expected $( [ "$ARCH" = amd64 ] && echo 62 || echo 183 ). The release does not match this machine." ;;
esac
say "ELF architecture: OK ($ARCH)"

# --- optional signature verification ----------------------------------------

SIG_STATUS=SKIPPED
if [ -n "$PUBKEY" ]; then
  command -v openssl >/dev/null 2>&1 \
    || die "--pubkey was given but openssl is not installed; signature verification is mandatory in this mode."
  [ -f "$TMP/SHA256SUMS.sig" ] || die "--pubkey was given but this release has no SHA256SUMS.sig; refusing to verify against a missing signature."
  hex2bin() {
    # LC_ALL=C is mandatory and must stay scoped to this awk subprocess: in a
    # UTF-8 locale gawk renders printf "%c" with a value > 127 as that
    # character's multi-byte UTF-8 encoding (0x80 -> c2 80), which corrupts
    # every binary blob this function produces and breaks Ed25519
    # verification. The surrounding locale of the user must not leak in here.
    printf '%s' "$1" | LC_ALL=C awk '
      BEGIN { split("0 1 2 3 4 5 6 7 8 9 a b c d e f", v, " "); for (i in v) d[v[i]] = i - 1 }
      { for (i = 1; i < length($0); i += 2) printf "%c", d[substr($0, i, 1)] * 16 + d[substr($0, i + 1, 1)] }
    '
  }
  KEYHEX=$(tr -d ' \n\r\t' < "$PUBKEY" | tr 'A-F' 'a-f')
  case "$KEYHEX" in
    *[!0-9a-f]*|"") die "$PUBKEY does not contain a clean hex public key." ;;
  esac
  [ "${#KEYHEX}" -eq 64 ] || die "$PUBKEY must hold exactly 64 hex characters (a raw Ed25519 public key), found ${#KEYHEX}."
  # SubjectPublicKeyInfo DER for a raw Ed25519 key is a fixed 12-byte prefix
  # followed by the 32 key bytes.
  hex2bin "302a300506032b6570032100$KEYHEX" > "$TMP/pub.der"
  base64 < "$TMP/pub.der" > "$TMP/pub.b64"
  { printf -- '-----BEGIN PUBLIC KEY-----\n'; sed 's/.\{64\}/&\n/' "$TMP/pub.b64" | sed '/^$/d'; printf -- '-----END PUBLIC KEY-----\n'; } > "$TMP/pub.pem"
  hex2bin "$(cat "$TMP/SHA256SUMS.sig" | tr -d ' \n\r')" > "$TMP/sig.raw"
  if openssl pkeyutl -verify -pubin -inkey "$TMP/pub.pem" -rawin -in "$TMP/SHA256SUMS" -sigfile "$TMP/sig.raw" >/dev/null 2>&1; then
    SIG_STATUS=VERIFIED
    say "Signature: VERIFIED (Ed25519)"
  else
    die "signature verification FAILED: this artifact set did not come from the holder of the trusted key. Refusing to install."
  fi
else
  if [ -f "$TMP/SHA256SUMS.sig" ]; then
    say "Signature: NOT_CONFIGURED (a signature file is present, but no --pubkey was given; publisher identity was NOT verified)"
  else
    say "Signature: NOT_CONFIGURED (no signature file and no --pubkey; publisher identity was NOT verified)"
  fi
fi

# --- atomic install ----------------------------------------------------------

STAGE=$DEST_DIR/.ronda-install.$$.tmp
cleanup_stage() { rm -f "$STAGE"; }
trap 'rm -rf "$TMP"; cleanup_stage' EXIT

cat "$TMP/$BIN" > "$STAGE" || die "cannot write the staging file in $DEST_DIR (disk full?)"
chmod 0755 "$STAGE" || die "cannot set permissions on the staging file."
if [ -e "$DEST" ]; then
  mv "$DEST" "$DEST.old" || die "cannot preserve the current binary at $DEST.old."
fi
if mv "$STAGE" "$DEST"; then
  :
else
  if [ -e "$DEST.old" ]; then mv "$DEST.old" "$DEST" || true; fi
  die "cannot move the new binary into place; the previous installation was restored."
fi
# Post-install sanity: the replaced binary must identify as RONDA.
if ! "$DEST" version 2>/dev/null | head -n 1 | grep -q '^RONDA '; then
  if [ -e "$DEST.old" ]; then
    mv "$DEST.old" "$DEST" || true
  else
    rm -f "$DEST"
  fi
  die "the installed binary failed its post-install version check; the previous installation was restored."
fi

say ""
say "RONDA installed to $DEST"
if [ -e "$DEST.old" ]; then
  say "Previous version kept at $DEST.old (remove it once the new version works)."
fi
say "Signature verification: $SIG_STATUS"
"$DEST" version | sed 's/^/  /'
case ":$PATH:" in
  *":$DEST_DIR:"*) : ;;
  *) say "Add $DEST_DIR to your PATH to run ronda directly." ;;
esac
