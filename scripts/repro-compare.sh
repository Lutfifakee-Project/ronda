#!/bin/sh
# Compare two release builds for reproducibility.
# Usage: scripts/repro-compare.sh dist-repro-1 dist-repro-2
set -eu

A=${1:?first dist directory required}
B=${2:?second dist directory required}
rc=0

for f in ronda-linux-amd64 ronda-linux-arm64 ronda-linux-amd64.tar.gz ronda-linux-arm64.tar.gz SHA256SUMS; do
  if [ ! -f "$A/$f" ] || [ ! -f "$B/$f" ]; then
    echo "repro-compare: missing $f in one of the build directories" >&2
    exit 1
  fi
  ha=$(sha256sum "$A/$f" | awk '{print $1}')
  hb=$(sha256sum "$B/$f" | awk '{print $1}')
  if [ "$ha" = "$hb" ]; then
    echo "identical  $f  $ha"
  else
    echo "DIFFERS    $f"
    echo "  build 1: $ha"
    echo "  build 2: $hb"
    rc=1
  fi
done

if [ "$rc" -eq 0 ]; then
  echo "repro-compare: all artifacts byte-identical across the two builds"
else
  echo "repro-compare: REPRODUCIBILITY FAILURE" >&2
fi
exit $rc
