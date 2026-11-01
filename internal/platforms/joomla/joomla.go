// Package joomla verifies the integrity of a Joomla installation against the
// official Joomla full-package release archive.
//
// Trust model (Phase 3.1, explicit): downloads.joomla.org publishes only MD5
// and SHA-1 signatures per package — collision-broken legacy digests. The
// published pair is therefore always verified first, and the SHA-256 that the
// official joomla/joomla-cms GitHub release publishes for the identical
// prebuilt full package is cross-checked against the exact downloaded archive
// when reachable. Both digests describe the same installation artifact: the
// GitHub release hosts the same prebuilt packages, not a source archive. A
// matching SHA-256 yields SHA256_AUTHENTICATED; when the strong digest is
// unavailable the reference stays honest as LEGACY_DIGEST_MATCH with an
// explicit warning in every report format. Official sources that disagree are
// refused outright. The update server's SHA-256 entries cover update
// packages only and are never conflated with the full installation package.
// Everything is read-only.
package joomla

import (
	"os"
	"path/filepath"

	"github.com/Lutfifakee-Project/ronda/internal/platforms/refcheck"
)

// Marker paths used to recognise a Joomla installation root.
const (
	MarkerManifest   = "administrator/manifests/files/joomla.xml"
	MarkerVersion    = "libraries/src/Version.php"
	MarkerVersionOld = "libraries/cms/version/version.php"
)

// Result is the integrity outcome for one Joomla installation.
type Result struct {
	Root string

	Version        string
	VersionSources []VersionSource

	Verified bool
	Reason   string

	Reference          Reference
	VerificationMethod string

	// Warnings carry explicit trust-model caveats, e.g. the weak-digest
	// warning when only legacy MD5+SHA-1 authentication was available. They
	// are surfaced by every report format and never silently dropped.
	Warnings []string

	TotalFiles   int
	SkippedCount int
	CleanCount   int
	Modified     []FileState
	Missing      []FileState
	Unverified   []FileState
	Unexpected   []string
	CleanFiles   []string
	SkippedAreas []string
}

// VersionSource is one static version signal with its origin.
type VersionSource = refcheck.VersionSource

// Reference records which official material the manifest came from, plus the
// explicit trust level of the authentication evidence.
type Reference struct {
	SourcePage  string
	ArchiveURL  string
	Algorithm   string // digest(s) used, e.g. "md5+sha1"
	Digest      string // published digest pair, for display
	ArchiveSize int64
	Cached      bool
	Created     string
	// Trust is the explicit strength of the archive authentication, one of
	// the refcheck.Strength* categories with its provenance metadata.
	Trust refcheck.Trust
}

// FileState mirrors refcheck.FileState.
type FileState = refcheck.FileState

// IsJoomla reports whether root looks like a Joomla installation root by
// checking the manifest plus a version marker. It uses only stat calls.
func IsJoomla(root string) bool {
	if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(MarkerManifest))); err != nil {
		return false
	}
	for _, m := range []string{MarkerVersion, MarkerVersionOld} {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(m))); err == nil {
			return true
		}
	}
	return false
}
