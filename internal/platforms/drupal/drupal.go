// Package drupal verifies the integrity of a modern Drupal (8+) installation
// against the official drupal.org release archive.
//
// Unlike WordPress, Drupal publishes no per-file checksum API. The trusted
// reference is therefore the official release tarball on ftp.drupal.org,
// authenticated against the SHA-256 hash published on the release page at
// www.drupal.org. Only after the archive digest matches is a per-file
// SHA-256 manifest derived from it. Everything is read-only: RONDA parses
// version files statically, never executes PHP, never bootstraps Drupal and
// never touches its database.
package drupal

import (
	"os"
	"path/filepath"

	"github.com/Lutfifakee-Project/ronda/internal/platforms/refcheck"
)

// Marker paths used to recognise a Drupal document root (relative to root).
const (
	MarkerCoreLib = "core/lib/Drupal.php"
	MarkerLock    = "composer.lock"
)

// Layout values for Result.Layout.
const (
	LayoutTarball  = "tarball"
	LayoutComposer = "composer"
)

// Result is the integrity outcome for one Drupal installation.
type Result struct {
	// Root is the Drupal document root (the directory holding core/).
	Root string
	// ProjectRoot is the Composer project root when a parent composer.lock
	// pins drupal/core; empty for tarball-extracted installations.
	ProjectRoot string
	// Layout is LayoutComposer or LayoutTarball.
	Layout string

	Version        string
	VersionSources []VersionSource

	Verified bool
	Reason   string

	Reference          Reference
	VerificationMethod string

	TotalFiles int
	// SkippedCount mirrors the manifest paths excluded from comparison by
	// the layout policy (composer-managed areas).
	SkippedCount int
	CleanCount   int
	Modified     []FileState
	Missing      []FileState
	Unverified   []FileState
	Unexpected   []string
	CleanFiles   []string
	SkippedAreas []string
}

// VersionSource is one static version signal with its origin, kept separate
// so conflicting signals are visible instead of silently resolved.
type VersionSource = refcheck.VersionSource

// Reference records which official material the manifest came from.
type Reference struct {
	SourcePage  string
	ArchiveURL  string
	Algorithm   string
	Digest      string
	ArchiveSize int64
	Cached      bool
	Created     string
	// Trust is the explicit strength of the archive authentication. Drupal
	// derives its manifests from SHA-256-authenticated release archives, so
	// this is SHA256_AUTHENTICATED for every verified reference.
	Trust refcheck.Trust
}

// FileState mirrors refcheck.FileState so callers stay decoupled.
type FileState = refcheck.FileState

// IsDrupal reports whether root looks like a Drupal document root by
// checking for the core library marker. It uses only stat calls.
func IsDrupal(root string) bool {
	_, err := os.Stat(filepath.Join(root, filepath.FromSlash(MarkerCoreLib)))
	return err == nil
}

// HasComposerLock reports whether a composer.lock exists at dir.
func HasComposerLock(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, MarkerLock))
	return err == nil
}
