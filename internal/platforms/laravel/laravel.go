// Package laravel implements the Laravel framework profile.
//
// Laravel is a PHP application framework, not a CMS: application code,
// routes, configuration, views and business logic are project-owned rather
// than generic framework core. RONDA therefore treats Laravel differently
// from WordPress/Drupal/Joomla:
//
//   - The Composer package inventory is parsed statically (composer.json,
//     composer.lock, vendor/composer/installed.json). Composer is never
//     executed and no external package registry is contacted.
//   - Package integrity is reported UNVERIFIED unless an independently
//     authenticated package archive is available: a lock file pins versions
//     but does not prove installed files are unchanged, and the dist URLs
//     and hashes inside composer.lock are target-controlled metadata that
//     RONDA must not trust or fetch.
//   - Structural deployment checks follow Laravel's own guidance: sensitive
//     root files must never be exposed through the public directory.
//     Secret-bearing files are only inspected in a strictly redacted way:
//     key names and line numbers are reported, never values.
package laravel

import (
	"context"
	"os"
	"path/filepath"
)

// Confidence levels for Laravel detection.
const (
	ConfidenceHigh   = "high"
	ConfidenceMedium = "medium"
	ConfidenceLow    = "low"
)

// IntegrityStatus is always UNVERIFIED in this phase: RONDA has no
// authenticated reference for Composer packages.
const IntegrityStatus = "UNVERIFIED"

// Check is one structural security observation about the project layout.
type Check struct {
	Name     string `json:"name"`
	Status   string `json:"status"` // CRITICAL, HIGH, MEDIUM, LOW, INFO, OK
	Detail   string `json:"detail"`
	Path     string `json:"path,omitempty"`
	Line     int    `json:"line,omitempty"`
	Evidence string `json:"evidence,omitempty"`
}

// PackageInfo is one inventory entry worth reporting.
type PackageInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Dev     bool   `json:"dev,omitempty"`
}

// Result is the outcome for one Laravel project.
type Result struct {
	Root string

	// Confidence expresses how surely this is a Laravel project.
	Confidence string
	// FrameworkRequired is true when composer.json requires laravel/framework.
	FrameworkRequired bool

	Version           string
	VersionSource     string
	SourceRef         string
	PackagesLocked    int
	PackagesInstalled int
	Require           []PackageInfo
	VersionConflicts  []string

	IntegrityStatus string
	IntegrityReason string

	// InventoryComplete is true when lock and installed metadata were both
	// readable; it never implies file-level integrity.
	InventoryComplete bool

	// Checks holds the structural security observations.
	Checks []Check

	Notes []string
}

// VerificationMethod is reported for all Laravel results.
const VerificationMethod = "composer inventory (static); no file-level verification available"

// Marker paths used to recognise a Laravel project root.
const (
	MarkerArtisan   = "artisan"
	MarkerBootstrap = "bootstrap/app.php"
)

// IsLaravel reports whether root looks like a Laravel project root. Two
// independent markers are required so a matching single filename never
// misidentifies an arbitrary PHP application.
func IsLaravel(root string) bool {
	for _, m := range []string{MarkerArtisan, MarkerBootstrap} {
		if _, err := os.Stat(filepath.Join(root, m)); err != nil {
			return false
		}
	}
	return true
}

// Verify inspects one Laravel project: Composer inventory plus structural
// security checks. It never executes Artisan, PHP or Composer, and never
// touches a database.
func Verify(_ context.Context, root string) Result {
	res := inventoryResult(root)
	res.Confidence = detectConfidence(root, res.FrameworkRequired)
	res.Checks = runStructuralChecks(root)
	res.Notes = append(res.Notes,
		"PHP sources are analyzed by the generic PHP analyzer separately; integrity and threat analysis are independent systems")
	return res
}

// detectConfidence grades how surely root is a Laravel project.
func detectConfidence(root string, frameworkRequired bool) string {
	if !frameworkRequired {
		return ConfidenceLow
	}
	if _, err := os.Stat(filepath.Join(root, "vendor", "laravel", "framework")); err == nil {
		return ConfidenceHigh
	}
	return ConfidenceMedium
}

// inventoryResult runs the static Composer inventory.
func inventoryResult(root string) Result {
	res, err := inventory(root)
	if err != nil {
		return Result{
			Root:            root,
			Confidence:      ConfidenceLow,
			IntegrityStatus: IntegrityStatus,
			IntegrityReason: "composer metadata unreadable: " + err.Error(),
		}
	}
	return res
}
