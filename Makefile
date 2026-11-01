# RONDA build, test and release engineering targets.
# Run "make help" to list targets.
#
# VERSION AND BUILD METADATA
#   VERSION is the single authoritative application version (also the
#   default in internal/version). RULES must match internal/version's
#   RulesVersion default; a mismatch would make release binaries misreport
#   their detection rules and is rejected below.
#
#   COMMIT stays "dev" unless explicitly overridden. The canonical working
#   tree is mostly untracked (one initial commit contains only LICENSE and
#   README), so a git-derived revision would misrepresent the build; embed
#   it only when the full source is actually committed and tagged.
#
#   DATE is derived from SOURCE_DATE_EPOCH for release builds so artifacts
#   are reproducible; it stays "unknown" for plain developer builds.
VERSION ?= 0.1.0
RULES   ?= builtin-5
COMMIT  ?= dev
PKG     := github.com/Lutfifakee-Project/ronda/internal/version

GO ?= go
DIST ?= dist

# Toolchain consistency: go.mod declares the authoritative release build
# toolchain (toolchain directive). A release must be built by exactly that
# toolchain; anything else (GOTOOLCHAIN=local on an older Go, or a newer
# default toolchain) would silently ship artifacts whose compiler/stdlib
# differ from the validated, security-patched one.
TOOLCHAIN_WANT := $(shell sed -n 's/^toolchain //p' go.mod)
TOOLCHAIN_GOT  := $(shell $(GO) env GOVERSION)

# SOURCE_DATE_EPOCH: explicit value wins; otherwise fall back to the last
# commit timestamp (the reproducible-builds convention). Neither is required
# for developer builds.
ifeq ($(origin SOURCE_DATE_EPOCH), undefined)
SOURCE_DATE_EPOCH := $(shell git log -1 --format=%ct 2>/dev/null || echo 0)
endif
BUILD_DATE := $(shell date -u -d @$(SOURCE_DATE_EPOCH) +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)

LDFLAGS := -s -w -X $(PKG).Version=$(VERSION) -X $(PKG).RulesVersion=$(RULES) -X $(PKG).Commit=$(COMMIT) -X $(PKG).Date=$(BUILD_DATE)

RELEASE_ENV := RONDA_VERSION=$(VERSION) RONDA_RULES=$(RULES) RONDA_COMMIT=$(COMMIT) \
	       RONDA_DATE=$(BUILD_DATE) RONDA_GOVERSION="$(shell $(GO) env GOVERSION)" \
	       RONDA_LDFLAGS="$(LDFLAGS)" RONDA_SIGNING=NOT_CONFIGURED \
	       SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) DIST=$(DIST)

.PHONY: help fmt vet lint test race build amd64 arm64 release package \
	check-toolchain test-toolchain repro-check test-installer clean install

help:
	@echo 'RONDA targets:'
	@echo '  make fmt            gofmt -l . (empty output = clean)'
	@echo '  make vet            go vet ./...'
	@echo '  make lint           fmt + vet'
	@echo '  make test           go test ./... -count=1'
	@echo '  make race           go test -race ./...'
	@echo '  make build          build for the current platform (./ronda)'
	@echo '  make amd64          cross-compile linux/amd64 into $(DIST)'
	@echo '  make arm64          cross-compile linux/arm64 into $(DIST)'
	@echo '  make release        amd64 + arm64 + package (deterministic)'
	@echo '  make package        archives + SHA256SUMS + manifest + SBOM'
	@echo '  make repro-check    two identical release builds, compare hashes'
	@echo '  make test-installer run scripts/test-install.sh'
	@echo '  make test-toolchain run scripts/test-toolchain.sh'
	@echo '  make clean          remove generated build artifacts (dist only)'
	@echo '  make install        build and install to /usr/local/bin (root)'

check-toolchain:
	@if [ -n "$(TOOLCHAIN_WANT)" ] && [ "$(TOOLCHAIN_GOT)" != "$(TOOLCHAIN_WANT)" ]; then \
	  echo "check-toolchain: go.mod requires $(TOOLCHAIN_WANT), but PATH provides $(TOOLCHAIN_GOT)" >&2; \
	  echo "  install $(TOOLCHAIN_WANT) and put it first on PATH (or keep GOTOOLCHAIN=auto)" >&2; \
	  exit 1; \
	fi

fmt:
	@out=$$($(GO)fmt -l .); if [ -n "$$out" ]; then echo "$$out"; exit 1; fi

vet:
	$(GO) vet ./...

lint: fmt vet

test:
	$(GO) test ./... -count=1

race:
	$(GO) test -race ./...

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o ronda .

amd64:
	mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST)/ronda-linux-amd64 .

arm64:
	mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST)/ronda-linux-arm64 .

package: check-toolchain amd64 arm64
	$(RELEASE_ENV) sh scripts/package-release.sh

release: check-toolchain package
	@echo "release candidate ready in $(DIST) (signing: NOT_CONFIGURED)"

# Two controlled builds from identical source conditions; every artifact
# covered by SHA256SUMS must hash identically.
repro-check:
	@$(RELEASE_ENV) $(MAKE) --no-print-directory DIST=dist-repro-1 release
	@$(RELEASE_ENV) $(MAKE) --no-print-directory DIST=dist-repro-2 release
	@sh scripts/repro-compare.sh dist-repro-1 dist-repro-2
	@cmp dist-repro-1/release-manifest.json dist-repro-2/release-manifest.json
	@cmp dist-repro-1/SBOM.cdx.json dist-repro-2/SBOM.cdx.json
	@echo "repro-check: manifest and SBOM byte-identical across the two builds"

test-toolchain:
	@sh scripts/test-toolchain.sh

test-installer:
	sh scripts/test-install.sh $(DIST)/ronda-linux-amd64

clean:
	rm -rf $(DIST) dist-repro-1 dist-repro-2
	rm -f ronda

# Convenience target for developer machines; VPS users should use install.sh
# so checksums and architecture are verified.
install: build
	install -m 0755 ronda /usr/local/bin/ronda
