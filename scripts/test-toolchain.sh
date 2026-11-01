#!/bin/sh
# Regression tests for RONDA release toolchain enforcement.
#
# What is under test (Phase 7.2, section 4):
#   1. go.mod declares the authoritative release toolchain (toolchain
#      directive) and the module language level (go directive).
#   2. `make check-toolchain` passes when the PATH toolchain matches the
#      declaration.
#   3. `make check-toolchain` FAILS when the selected Go version differs
#      from the declaration (tested hermetically with a fake `go` shim; no
#      second Go installation is required).
#   4. Every supported release entry point depends on check-toolchain.
#   5. The CI workflow verifies the exact selected Go version.
#   6. The enforcement gap is documented: plain `go build ...` invoked by
#      hand is NOT protected by the Makefile check, and the toolchain
#      directive alone is a selector, not a hard gate (GOTOOLCHAIN=local
#      plus an older Go fails closed only inside the release targets).
#
# The fake shim reports a version that is NOT the declared toolchain, so
# check-toolchain must reject it. This keeps the test hermetic: it never
# downloads a toolchain and never needs a second Go installation.
set -u

HERE=$(cd "$(dirname "$0")/.." && pwd)
cd "$HERE"
PASS=0
FAIL=0

say() { printf '%s\n' "$*"; }
ok()   { say "ok   $1"; PASS=$((PASS + 1)); }
bad()  { say "FAIL $1"; FAIL=$((FAIL + 1)); }

expect_ok() {
  if "$@" >/dev/null 2>&1; then ok "$*"; else bad "$* (expected success)"; fi
}

expect_fail() {
  if "$@" >/dev/null 2>&1; then bad "$1 (expected failure)"; else ok "$1"; fi
}

# --- 1. go.mod declarations ---------------------------------------------------
WANT_TOOLCHAIN=$(sed -n 's/^toolchain //p' go.mod)
WANT_GO=$(sed -n 's/^go //p' go.mod)
[ -n "$WANT_TOOLCHAIN" ] && ok "go.mod declares toolchain $WANT_TOOLCHAIN" \
                         || bad "go.mod missing toolchain directive"
[ -n "$WANT_GO" ] && ok "go.mod declares module language level go $WANT_GO" \
                  || bad "go.mod missing go directive"

# --- 2. matching toolchain passes ----------------------------------------------
if command -v go >/dev/null 2>&1; then
  GOT=$(go env GOVERSION 2>/dev/null || echo unknown)
  if [ "$GOT" = "$WANT_TOOLCHAIN" ]; then
    expect_ok make check-toolchain
  else
    # The PATH toolchain differs (e.g. the test runs on a different host);
    # with GOTOOLCHAIN=auto go env GOVERSION still selects the declared
    # toolchain, so reaching here means auto-switching is disabled or broken.
    expect_fail "make check-toolchain rejects $GOT (declared $WANT_TOOLCHAIN)"
  fi
else
  bad "no go on PATH: cannot exercise the matching case"
fi

# --- 3. mismatched toolchain rejected (hermetic fake shim) ---------------------
SHIM=$(mktemp -d)
trap 'rm -rf "$SHIM"' EXIT
cat > "$SHIM/go" <<EOF
#!/bin/sh
case "\$1" in
  env) if [ "\$2" = "GOVERSION" ]; then echo go1.21.0; fi ;;
  version) echo "go version go1.21.0 linux/amd64" ;;
esac
exit 0
EOF
chmod +x "$SHIM/go"
expect_fail "env PATH=$SHIM make check-toolchain rejects fake go1.21.0"

# The failure message must name both versions.
OUT=$(PATH="$SHIM:/usr/bin:/bin" make check-toolchain 2>&1)
case "$OUT" in
  *"requires $WANT_TOOLCHAIN"*"provides go1.21.0"*)
    ok "rejection message names required and provided toolchains" ;;
  *) bad "rejection message unclear: $OUT" ;;
esac

# --- 4. release entry points invoke the check ----------------------------------
for target in package release; do
  deps=$(sed -n "s/^$target: //p" Makefile)
  case "$deps" in
    *check-toolchain*) ok "make $target depends on check-toolchain" ;;
    *) bad "make $target does not depend on check-toolchain ($deps)" ;;
  esac
done

# --- 5. CI asserts the selected Go version -------------------------------------
WF=.github/workflows/ci.yml
grep -q "Assert the authoritative toolchain" "$WF" \
  && ok "CI asserts the selected toolchain" \
  || bad "CI lacks the toolchain assertion step"
grep -q "goVersion == \$want" "$WF" \
  && ok "CI checks release manifest goVersion against go.mod" \
  || bad "CI does not check manifest goVersion"
grep -q "actions/setup-go@" "$WF" && ! grep -q "actions/setup-go@v" "$WF" \
  && ok "setup-go pinned to an immutable commit SHA" \
  || bad "setup-go is not SHA-pinned"

# --- 6. documented enforcement gap ---------------------------------------------
grep -q "GOTOOLCHAIN=auto" docs/TOOLCHAIN.md 2>/dev/null \
  && ok "GOTOOLCHAIN=auto behavior documented" \
  || bad "docs/TOOLCHAIN.md missing GOTOOLCHAIN=auto documentation"
grep -q "GOTOOLCHAIN=local" docs/TOOLCHAIN.md 2>/dev/null \
  && ok "GOTOOLCHAIN=local behavior documented" \
  || bad "docs/TOOLCHAIN.md missing GOTOOLCHAIN=local documentation"

say ""
say "toolchain enforcement tests: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
