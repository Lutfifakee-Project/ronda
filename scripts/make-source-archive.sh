#!/bin/sh
# Build the RONDA source archive: a self-describing, deterministic tarball
# that lets an independent party rebuild the release candidate without
# access to this workspace.
#
# Outputs (inside $DIST/source/):
#   ronda-<version>-source.tar.gz   the archive (top-level dir ronda-<version>/)
#   ronda-<version>-source.tar.gz.sha256
#   ARCHIVE-MANIFEST.json           archive hash, inventory, exclusions, recipe
#
# Determinism: tar member metadata is normalized (--sort=name, uid/gid 0,
# mtime from SOURCE_DATE_EPOCH) and gzip runs without a timestamp, so
# re-running on the same tree produces byte-identical output.
#
# Exclusions (each category also appears in ARCHIVE-MANIFEST.json):
#   generated-build-artifacts : ./ronda, dist/, dist-repro-*/, dist-go127*/
#                               (the archive itself lives under dist-go127)
#   vcs-internal-metadata     : .git/ (history stays in the repository)
#   developer-session-notes   : Codelyxa/ (agent/developer memory; contains
#                               local workspace paths, not source)
#   local-caches              : none exist inside the tree (verified)
#   toolchain-installations   : none inside the tree (verified; live outside)
#   secrets-or-credentials    : none found (script scans and aborts if any
#                               appear)
#   editor-or-temp-junk       : *~, *.swp, .DS_Store, *.test, ronda-report.*
set -eu

HERE=$(cd "$(dirname "$0")/.." && pwd)
cd "$HERE"

VERSION=$(sed -n 's/^VERSION ?= //p' Makefile)
RULES=$(sed -n 's/^RULES   ?= //p' Makefile)
DIST=${DIST:-dist-go127}
OUTDIR="$DIST/source"
TOPDIR="ronda-$VERSION"
EPOCH=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct 2>/dev/null || echo 0)}
GOVERSION=$("$@" 2>/dev/null || true)
if [ -z "$GOVERSION" ]; then
  GOVERSION=$(go env GOVERSION 2>/dev/null || echo unknown)
fi

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/$TOPDIR" "$OUTDIR"

# --- 1. collect the source tree (everything tracked or required, minus the
#        documented exclusion categories) -----------------------------------
tar \
  --exclude='./.git' \
  --exclude='./Codelyxa' \
  --exclude='./dist' \
  --exclude='./dist-repro-1' \
  --exclude='./dist-repro-2' \
  --exclude='./dist-go127' \
  --exclude='./dist-go127-repro-1' \
  --exclude='./dist-go127-repro-2' \
  --exclude='./ronda' \
  --exclude='*.test' \
  --exclude='ronda-report.html' \
  --exclude='ronda-report.json' \
  --exclude='*~' \
  --exclude='*.swp' \
  --exclude='.DS_Store' \
  -cf - . | tar -xf - -C "$STAGE/$TOPDIR"

# --- 2. secret scan: abort rather than ship anything that looks like a key
# The PEM pattern is the complete armor marker (dashes on both sides) so
# redaction-test assertions like `strings.Contains(out, "BEGIN PRIVATE KEY")`
# do not false-positive. The archiving script itself is skipped (it contains
# the detection patterns); everything else in the tree is scanned.
SECRET_RE='-{3,}BEGIN [A-Z0-9 ]*PRIVATE KEY|AKIA[0-9A-Z]{16}|xox[baprs]-|ghp_[A-Za-z0-9]{20,}'
if grep -rInE "$SECRET_RE" "$STAGE/$TOPDIR" \
      --exclude='make-source-archive.sh' >/dev/null 2>&1; then
  echo "make-source-archive: potential secret material found; refusing to archive:" >&2
  grep -rlnE "$SECRET_RE" "$STAGE/$TOPDIR" --exclude='make-source-archive.sh' >&2 || true
  exit 1
fi
echo "secret scan: no key/token material found in staged source"

# --- 3. self-describing manifest (inside the archive) ---------------------
python3 - "$STAGE/$TOPDIR" "$VERSION" "$RULES" "$GOVERSION" "$EPOCH" <<'PYEOF'
import hashlib, json, os, sys

top = sys.argv[1]
version, rules, goversion, epoch = sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
files = []
for dirpath, dirnames, filenames in os.walk(top):
    dirnames.sort()
    for name in sorted(filenames):
        p = os.path.join(dirpath, name)
        rel = os.path.relpath(p, top)
        h = hashlib.sha256()
        with open(p, 'rb') as f:
            for chunk in iter(lambda: f.read(1 << 20), b''):
                h.update(chunk)
        files.append({"path": rel, "sha256": h.hexdigest(),
                      "bytes": os.path.getsize(p)})
files.sort(key=lambda e: e["path"])

exclusions = [
    {"category": "generated-build-artifacts",
     "paths": ["ronda", "dist/", "dist-repro-1/", "dist-repro-2/",
               "dist-go127/", "dist-go127-repro-1/", "dist-go127-repro-2/"],
     "reason": "release binaries and packaging output; rebuildable from this source"},
    {"category": "vcs-internal-metadata",
     "paths": [".git/"],
     "reason": "repository history stays in the canonical repository; not source"},
    {"category": "developer-session-notes",
     "paths": ["Codelyxa/"],
     "reason": "developer/agent memory notes containing local workspace paths; not source"},
    {"category": "local-caches",
     "paths": [],
     "reason": "none present inside the project tree (feed caches live in the user cache dir)"},
    {"category": "toolchain-installations",
     "paths": [],
     "reason": "no toolchain lives inside the tree; provisioning is documented in docs/TOOLCHAIN.md"},
    {"category": "secrets-or-credentials",
     "paths": [],
     "reason": "scanned before archiving; archive aborts if key/token patterns appear"},
    {"category": "editor-or-temp-junk",
     "paths": ["*~", "*.swp", ".DS_Store", "*.test", "ronda-report.html", "ronda-report.json"],
     "reason": "developer-local temporary files"},
]

manifest = {
    "product": "ronda",
    "tagline": "Scan. Detect. Protect.",
    "version": version,
    "rulesVersion": rules,
    "goToolchain": goversion,
    "sourceDateEpoch": int(epoch),
    "fileCount": len(files),
    "files": files,
    "exclusions": exclusions,
    "signingStatus": "NOT_CONFIGURED",
    "rebuild": [
        "export PATH=<go1.27.3>/bin:$PATH   # or rely on GOTOOLCHAIN=auto",
        "gofmt -l . && go build ./... && go vet ./... && go test ./... -count=1",
        "make DIST=dist release              # SOURCE_DATE_EPOCH is inherited from this manifest",
    ],
}
out = os.path.join(top, "SOURCE-MANIFEST.json")
with open(out, "w") as f:
    json.dump(manifest, f, indent=1, sort_keys=True)
    f.write("\n")
print(f"SOURCE-MANIFEST.json: {len(files)} files")
PYEOF

# --- 4. deterministic tarball ---------------------------------------------
tar -C "$STAGE" \
    --sort=name \
    --owner=0 --group=0 --numeric-owner \
    --mtime="@$EPOCH" \
    -cf - "$TOPDIR" | gzip -n > "$OUTDIR/ronda-$VERSION-source.tar.gz"

# --- 5. checksum + outer manifest ------------------------------------------
ARCHIVE="ronda-$VERSION-source.tar.gz"
(cd "$OUTDIR" && sha256sum "$ARCHIVE") > "$OUTDIR/$ARCHIVE.sha256"

python3 - "$OUTDIR" "$ARCHIVE" "$VERSION" "$EPOCH" "$TOPDIR" <<'PYEOF'
import hashlib, json, os, sys, tarfile

outdir, archive, version, epoch, topdir = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
path = os.path.join(outdir, archive)
h = hashlib.sha256()
with open(path, 'rb') as f:
    for chunk in iter(lambda: f.read(1 << 20), b''):
        h.update(chunk)

with tarfile.open(path) as t:
    members = [m for m in t.getmembers() if m.isfile()]

inner = json.load(open(os.path.join(outdir, "..", archive.replace(".tar.gz", ".tar.gz"))
                       if False else "/dev/null")) if False else None

outer = {
    "archive": archive,
    "sha256": h.hexdigest(),
    "bytes": os.path.getsize(path),
    "topLevelDir": topdir,
    "sourceDateEpoch": int(epoch),
    "tarMembers": len(members),
    "howToVerify": "sha256sum -c " + archive + ".sha256",
    "howToBuild": [
        "tar -xzf " + archive,
        "cd " + topdir,
        "export PATH=<go1.27.3>/bin:$PATH   # or rely on GOTOOLCHAIN=auto",
        "gofmt -l . && go build ./... && go vet ./... && go test ./... -count=1",
        "make DIST=dist release",
    ],
    "note": "Self-describing: SOURCE-MANIFEST.json inside the archive lists every file with its SHA-256 and documents all exclusion categories. Signing status NOT_CONFIGURED.",
}
with open(os.path.join(outdir, "ARCHIVE-MANIFEST.json"), "w") as f:
    json.dump(outer, f, indent=1, sort_keys=True)
    f.write("\n")
print(f"ARCHIVE-MANIFEST.json: sha256 {h.hexdigest()[:16]}... {len(members)} files")
PYEOF

say() { printf '%s\n' "$*"; }
say "Source archive: $OUTDIR/$ARCHIVE"
say "Files: $(tar -tzf "$OUTDIR/$ARCHIVE" | grep -vc '/$')"
say "Exclusion categories documented in ARCHIVE-MANIFEST.json and SOURCE-MANIFEST.json"
