// Package wordpress verifies the integrity of a WordPress core installation
// against the official WordPress.org checksum API.
//
// Everything here is read-only: RONDA reads version.php statically (it never
// executes PHP), downloads checksums over HTTPS and compares local file digests.
// No scanned file is ever modified, deleted, executed or uploaded.
package wordpress

import (
	"os"
	"path/filepath"
)

// CoreFile is one file described by an official checksum manifest.
type CoreFile struct {
	Path   string
	MD5    string
	Status Status
	Actual string
	Reason string
}

// Status describes the verification outcome for one expected file.
type Status string

const (
	Clean      Status = "CLEAN"
	Modified   Status = "MODIFIED"
	Missing    Status = "MISSING"
	Extra      Status = "EXTRA"
	Unverified Status = "UNVERIFIED"
)

// Locale confidence levels.
const (
	ConfidenceHigh   = "high"
	ConfidenceMedium = "medium"
	ConfidenceLow    = "low"
)

// Result is the integrity outcome for one WordPress installation.
type Result struct {
	Root string

	Version string

	// Locale is the package locale used for checksum lookup.
	Locale string
	// LocaleSource records how Locale was determined.
	LocaleSource string
	// LocaleConfidence is high, medium or low.
	LocaleConfidence string
	// LocaleInferred is true when Locale was derived rather than explicit.
	LocaleInferred bool
	// RuntimeLanguage is the WPLANG runtime site language, when configured.
	// It is NOT the package locale and does not affect core file checksums.
	RuntimeLanguage string

	Verified        bool
	Reason          string
	TotalFiles      int
	CleanCount      int
	CleanFiles      []string
	ModifiedFiles   []CoreFile
	MissingFiles    []CoreFile
	ExtraFiles      []string
	RootExtraFiles  []string
	UnverifiedCount int
	UnverifiedFiles []CoreFile
	ManifestSource  string
}

// IsWordPress reports whether root looks like a WordPress core root by checking
// for the standard entry files. It uses only stat calls.
func IsWordPress(root string) bool {
	markers := []string{"wp-load.php", "wp-includes/version.php"}
	for _, m := range markers {
		if _, err := os.Stat(filepath.Join(root, m)); err != nil {
			return false
		}
	}
	return true
}

// Version, package-locale and runtime-language detection live in
// locale_scan.go, backed by the wplocale masked lexical scanner.
