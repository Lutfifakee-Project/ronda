#!/bin/sh
# Installer security and failure-mode tests for install.sh.
#
# Every test drives the real installer against a fixture release directory
# built from the real RONDA binary, using --source (offline) mode so the
# suite needs no network. The live-download failure path and the missing
# fetch-tools path are exercised as well.
#
# Usage: scripts/test-install.sh [path-to-ronda-binary]
set -u

HERE=$(cd "$(dirname "$0")/.." && pwd)
INSTALLER=$HERE/install.sh
BIN=${1:-$HERE/dist/ronda-linux-amd64}
WORK=$(mktemp -d)
PASS=0
FAIL=0

cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

if [ ! -x "$BIN" ]; then
  echo "test-install: missing RONDA binary at $BIN (build it first: make amd64)" >&2
  exit 1
fi

say() { printf '%s\n' "$*"; }

# expect_fail NAME EXPECTED_SUBSTRING CMD...
expect_fail() {
  name=$1; shift
  needle=$1; shift
  out=$("$@" 2>&1)
  rc=$?
  if [ "$rc" -eq 0 ]; then
    say "FAIL $name: expected failure, got success"
    FAIL=$((FAIL + 1))
  elif [ -n "$needle" ] && ! printf '%s' "$out" | grep -q "$needle"; then
    say "FAIL $name: message did not mention '$needle':"
    printf '%s\n' "$out" | sed 's/^/    /'
    FAIL=$((FAIL + 1))
  else
    say "ok   $name"
    PASS=$((PASS + 1))
  fi
}

# expect_ok NAME CMD...
expect_ok() {
  name=$1; shift
  if out=$("$@" 2>&1); then
    say "ok   $name"
    PASS=$((PASS + 1))
  else
    say "FAIL $name (exit $?):"
    printf '%s\n' "$out" | sed 's/^/    /'
    FAIL=$((FAIL + 1))
  fi
}

# make_fixture DIR SUMS_CONTENT [SIG]
# Lays out a release directory: artifact + SHA256SUMS (+ .sig as hex).
make_fixture() {
  dir=$1; shift
  mkdir -p "$dir"
  cp "$BIN" "$dir/ronda-linux-amd64"
  printf '%s' "$1" > "$dir/SHA256SUMS"
  if [ $# -ge 2 ]; then
    printf '%s' "$2" > "$dir/SHA256SUMS.sig"
  fi
}

# make_fixture_noartifact DIR SUMS_CONTENT — sums present, artifact absent.
make_fixture_noartifact() {
  dir=$1; shift
  mkdir -p "$dir"
  printf '%s' "$1" > "$dir/SHA256SUMS"
}

# make_fixture_crossarch DIR SUMS_CONTENT — an arm64-named artifact that is
# really the amd64 binary, so the ELF check must catch the mismatch.
make_fixture_crossarch() {
  dir=$1; shift
  mkdir -p "$dir"
  cp "$BIN" "$dir/ronda-linux-arm64"
  printf '%s' "$1" > "$dir/SHA256SUMS"
}

GOOD_DIGEST=$(sha256sum "$BIN" | awk '{print $1}')
# POSIX sh: no $'...' escapes; build with printf.
GOOD_SUMS=$(printf '%s  ronda-linux-amd64\n' "$GOOD_DIGEST")
GOOD_SUMS_ARM=$(printf '%s  ronda-linux-arm64\n' "$GOOD_DIGEST")

# A real Ed25519 keypair for signature tests. The public key is emitted as
# raw 64-hex exactly like the release pipeline documents.
PUBHEX=$(openssl genpkey -algorithm ed25519 -out "$WORK/signer.pem" 2>/dev/null \
  && openssl pkey -in "$WORK/signer.pem" -pubout -outform DER 2>/dev/null | od -An -tx1 | tr -d ' \n' | sed 's/^302a300506032b6570032100//')
printf '%s\n' "$PUBHEX" > "$WORK/pub.hex"

sign_sums() { # sums-content -> hex signature via the test signer
  printf '%s' "$1" > "$WORK/sums.in"
  openssl pkeyutl -sign -inkey "$WORK/signer.pem" -rawin -in "$WORK/sums.in" -out "$WORK/sig.raw" 2>/dev/null \
    && od -An -tx1 -v < "$WORK/sig.raw" | tr -d ' \n'
}

# --- help and argument handling ---------------------------------------------

expect_ok   "help exits zero"            sh "$INSTALLER" --help
expect_fail "unknown option rejected"    "unknown option" sh "$INSTALLER" --bogus
expect_fail "unsupported architecture"   "unsupported architecture" sh "$INSTALLER" --arch mips --source "$WORK/none"

# --- offline source-mode failures --------------------------------------------

make_fixture_noartifact "$WORK/fx-missing-asset" "$GOOD_SUMS"
expect_fail "missing artifact detected" "no artifact" \
  sh "$INSTALLER" --source "$WORK/fx-missing-asset" --prefix "$WORK/p1"

mkdir -p "$WORK/fx-no-sums"
cp "$BIN" "$WORK/fx-no-sums/ronda-linux-amd64"
expect_fail "missing SHA256SUMS detected" "SHA256SUMS" \
  sh "$INSTALLER" --source "$WORK/fx-no-sums" --prefix "$WORK/p2"

make_fixture "$WORK/fx-bad-digest" "$(printf '%s  ronda-linux-amd64\n' 0000000000000000000000000000000000000000000000000000000000000000)"
expect_fail "invalid checksum refused" "SHA-256 mismatch" \
  sh "$INSTALLER" --source "$WORK/fx-bad-digest" --prefix "$WORK/p3"

make_fixture "$WORK/fx-no-entry" "$(printf '%s  some-other-asset\n' "$GOOD_DIGEST")"
expect_fail "no checksum entry refused" "no checksum entry" \
  sh "$INSTALLER" --source "$WORK/fx-no-entry" --prefix "$WORK/p4"

# Wrong-architecture artifact: reuse the amd64 binary but claim arm64.
make_fixture_crossarch "$WORK/fx-crossarch" "$GOOD_SUMS_ARM"
expect_fail "cross-architecture artifact refused" "ELF architecture mismatch" \
  sh "$INSTALLER" --source "$WORK/fx-crossarch" --arch arm64 --prefix "$WORK/p5"

# --- successful installs ------------------------------------------------------

P6=$WORK/p6
make_fixture "$WORK/fx-good" "$GOOD_SUMS"
expect_ok "fresh install succeeds" \
  sh "$INSTALLER" --source "$WORK/fx-good" --prefix "$P6"
if [ -x "$P6/bin/ronda" ] && "$P6/bin/ronda" version | grep -q '^RONDA '; then
  say "ok   installed binary runs and identifies as RONDA"
  PASS=$((PASS + 1))
else
  say "FAIL installed binary missing or not RONDA"
  FAIL=$((FAIL + 1))
fi
case $(od -An -tu1 -j4 -N1 "$P6/bin/ronda" | tr -d ' ') in
  2) say "ok   installed ELF is 64-bit class"; PASS=$((PASS + 1)) ;;
  *) say "FAIL installed ELF class unexpected"; FAIL=$((FAIL + 1)) ;;
esac

# Re-install over an existing RONDA: must keep a .old backup and still work.
expect_ok "reinstall over existing RONDA succeeds" \
  sh "$INSTALLER" --source "$WORK/fx-good" --prefix "$P6"
if [ -x "$P6/bin/ronda.old" ]; then
  say "ok   previous binary preserved as ronda.old"
  PASS=$((PASS + 1))
else
  say "FAIL ronda.old backup missing"
  FAIL=$((FAIL + 1))
fi

# --- destination safety -------------------------------------------------------

# Symlink refusal is only exercised where the environment permits creating
# symlinks (some sandboxes forbid it entirely).
if ln -s /bin/true "$WORK/p7/bin/ronda" 2>/dev/null; then
  expect_fail "symlink destination refused" "symlink" \
    sh "$INSTALLER" --source "$WORK/fx-good" --prefix "$WORK/p7"
else
  say "SKIP symlink destination refused (environment forbids symlink creation)"
fi

mkdir -p "$WORK/p8/bin"
printf '#!/bin/sh\necho other-program\n' > "$WORK/p8/bin/ronda"
chmod 0755 "$WORK/p8/bin/ronda"
expect_fail "non-RONDA executable not overwritten" "not RONDA" \
  sh "$INSTALLER" --source "$WORK/fx-good" --prefix "$WORK/p8"

mkdir -p "$WORK/p9/bin"
if [ "$(id -u)" -eq 0 ]; then
  say "SKIP read-only prefix refused (running as root bypasses permission checks)"
else
  chmod 0555 "$WORK/p9/bin"
  expect_fail "read-only prefix refused" "not writable" \
    sh "$INSTALLER" --source "$WORK/fx-good" --prefix "$WORK/p9"
  chmod 0755 "$WORK/p9/bin"
fi

# --- signature verification ----------------------------------------------------

if [ -n "$PUBHEX" ] && [ "${#PUBHEX}" -eq 64 ]; then
  SIG=$(sign_sums "$GOOD_SUMS")
  if [ -n "$SIG" ]; then
    TAMPERED=$(printf '%s\n# tampered\n%s\n' "$GOOD_SUMS" "$SIG")
    make_fixture "$WORK/fx-signed" "$GOOD_SUMS" "$SIG"
    expect_ok "valid signature accepted" \
      sh "$INSTALLER" --source "$WORK/fx-signed" --pubkey "$WORK/pub.hex" --prefix "$WORK/p10"

    make_fixture "$WORK/fx-tampered" "$TAMPERED" "$SIG"
    expect_fail "tampered sums rejected under pubkey" "signature verification FAILED" \
      sh "$INSTALLER" --source "$WORK/fx-tampered" --pubkey "$WORK/pub.hex" --prefix "$WORK/p11"

    openssl genpkey -algorithm ed25519 -out "$WORK/other.pem" 2>/dev/null
    OTHERHEX=$(openssl pkey -in "$WORK/other.pem" -pubout -outform DER 2>/dev/null | od -An -tx1 | tr -d ' \n' | sed 's/^302a300506032b6570032100//')
    printf '%s\n' "$OTHERHEX" > "$WORK/other.hex"
    make_fixture "$WORK/fx-signed2" "$GOOD_SUMS" "$SIG"
    expect_fail "wrong-key signature rejected" "signature verification FAILED" \
      sh "$INSTALLER" --source "$WORK/fx-signed2" --pubkey "$WORK/other.hex" --prefix "$WORK/p12"

    # --pubkey with no signature file at all must stay fail-closed.
    make_fixture "$WORK/fx-nosig" "$GOOD_SUMS"
    expect_fail "missing signature rejected under pubkey" "SHA256SUMS.sig" \
      sh "$INSTALLER" --source "$WORK/fx-nosig" --pubkey "$WORK/pub.hex" --prefix "$WORK/p15"

    # A syntactically valid hex signature over the wrong content (here:
    # garbage bytes) must never verify; the installer must die loudly.
    MAL_SIG=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
    make_fixture "$WORK/fx-malsig" "$GOOD_SUMS" "$MAL_SIG"
    expect_fail "malformed signature rejected under pubkey" "signature verification FAILED" \
      sh "$INSTALLER" --source "$WORK/fx-malsig" --pubkey "$WORK/pub.hex" --prefix "$WORK/p16"
  else
    say "SKIP signature tests (openssl signing unavailable)"
  fi
else
  say "SKIP signature tests (openssl key derivation unavailable)"
fi

# --- hex2bin byte-exactness (UTF-8 locale regression) ---------------------------
# Under GNU awk in a UTF-8 locale, printf "%c" with a value > 127 renders that
# character's multi-byte UTF-8 encoding (0x80 -> c2 80 ...), which corrupted
# every binary blob hex2bin produced and made the installer reject a valid
# Ed25519 signature. The fix pins LC_ALL=C on the awk subprocess inside
# install.sh. These tests extract the REAL function from install.sh and assert
# exact bytes in the ambient locale of this test run, so removing the guard
# fails here in any UTF-8 locale (run with: LC_ALL=en_US.UTF-8 make
# test-installer and gawk forced through PATH).
HEX2BIN_FILE=$WORK/hex2bin.extracted.sh
sed -n '/^  hex2bin()/,/^  }$/p' "$INSTALLER" > "$HEX2BIN_FILE"
if [ -s "$HEX2BIN_FILE" ]; then
  # shellcheck disable=SC1090
  . "$HEX2BIN_FILE"
  # Reproduction vector from the incident report.
  GOT=$(hex2bin "80ff41c3a9" | od -An -v -tx1 | tr -d ' \n')
  if [ "$GOT" = "80ff41c3a9" ]; then
    say "ok   hex2bin keeps high bytes exact under the ambient locale"
    PASS=$((PASS + 1))
  else
    say "FAIL hex2bin corrupts bytes under the ambient locale (got $GOT)"
    FAIL=$((FAIL + 1))
  fi
  # Every representable byte value, in order, must round-trip untouched.
  ALLHEX=$(awk 'BEGIN { for (i = 0; i < 256; i++) printf "%02x", i }')
  GOTALL=$(hex2bin "$ALLHEX" | od -An -v -tx1 | tr -d ' \n')
  if [ "$GOTALL" = "$ALLHEX" ]; then
    say "ok   hex2bin round-trips all 256 byte values"
    PASS=$((PASS + 1))
  else
    say "FAIL hex2bin round-trip of 00..ff mismatched"
    FAIL=$((FAIL + 1))
  fi
else
  say "FAIL hex2bin could not be extracted from install.sh (layout changed?)"
  FAIL=$((FAIL + 1))
fi

# --- live download path (no release published yet) -----------------------------

expect_fail "live download of unpublished release fails cleanly" "download failed" \
  sh "$INSTALLER" --prefix "$WORK/p13"

# --- missing fetch tools --------------------------------------------------------

# A machine without curl AND wget must get a clear error instead of a
# partial install. Build a minimal tool directory (copies, not symlinks:
# sandboxes may forbid links) containing everything the installer needs
# EXCEPT curl and wget, then run it in download mode.
NOFETCH=$WORK/nofetch
mkdir -p "$NOFETCH"
for b in sh ash dash bash uname id mktemp rm mkdir cp mv chmod cat sed grep head tail tr awk od sha256sum base64 openssl ls basename dirname true false sleep; do
  for d in /usr/bin /bin; do
    if [ -x "$d/$b" ]; then cp "$d/$b" "$NOFETCH/$b" 2>/dev/null; break; fi
  done
done
expect_fail "missing fetch tools reported clearly" "curl or wget is required" \
  env PATH="$NOFETCH" sh "$INSTALLER" --prefix "$WORK/p14"

say ""
say "install.sh tests: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
