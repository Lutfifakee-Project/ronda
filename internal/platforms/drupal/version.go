package drupal

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// drupalVersionRE matches the VERSION constant in core/lib/Drupal.php.
var drupalVersionRE = regexp.MustCompile(`const[[:space:]]+VERSION[[:space:]]*=[[:space:]]*['"]([^'"]+)['"]`)

// stableVersionRE accepts only stable semantic releases; pre-releases and
// development snapshots have no supported official reference and yield
// UNVERIFIED instead of a guessed archive.
var stableVersionRE = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)

// DetectVersion collects static version signals from the document root and,
// when present, the Composer project root. Signals are never merged: the
// caller decides whether they agree.
func DetectVersion(docroot, projectRoot string) []VersionSource {
	var sources []VersionSource

	if data, err := os.ReadFile(filepath.Join(docroot, "core", "lib", "Drupal.php")); err == nil {
		if m := drupalVersionRE.FindSubmatch(data); m != nil {
			sources = append(sources, VersionSource{Value: string(m[1]), Source: "core/lib/Drupal.php"})
		}
	}

	for dir, label := range composerLockCandidates(docroot, projectRoot) {
		if v, err := composerCoreVersion(dir); err == nil && v != "" {
			sources = append(sources, VersionSource{Value: v, Source: label})
		}
	}
	return sources
}

// composerLockCandidates lists composer.lock locations with their source
// labels, most specific first, without duplicates.
func composerLockCandidates(docroot, projectRoot string) map[string]string {
	out := make(map[string]string)
	if HasComposerLock(docroot) {
		out[docroot] = "composer.lock (document root)"
	}
	if projectRoot != "" && projectRoot != docroot && HasComposerLock(projectRoot) {
		out[projectRoot] = "composer.lock (project root)"
	}
	return out
}

// EstablishVersion returns the version every source agrees on, or "" with a
// reason when the signals conflict, are absent or are not a stable release.
func EstablishVersion(sources []VersionSource) (string, string) {
	if len(sources) == 0 {
		return "", "could not read the Drupal version from core/lib/Drupal.php or composer.lock"
	}
	first := sources[0].Value
	for _, s := range sources[1:] {
		if s.Value != first {
			return "", "conflicting version signals: " + describeSources(sources)
		}
	}
	if !stableVersionRE.MatchString(first) {
		return "", "version " + first + " is not a stable release; refusing to guess a reference"
	}
	return first, ""
}

func describeSources(sources []VersionSource) string {
	parts := make([]string, 0, len(sources))
	for _, s := range sources {
		parts = append(parts, s.Source+"="+s.Value)
	}
	return strings.Join(parts, ", ")
}

// composerCoreVersion reads the pinned drupal/core (or drupal/core-recommended)
// version from composer.lock. The lock file is only ever read statically.
func composerCoreVersion(dir string) (string, error) {
	data, err := os.ReadFile(filepath.Join(dir, MarkerLock))
	if err != nil {
		return "", err
	}
	var lock struct {
		Packages []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return "", err
	}
	// drupal/core-recommended first: it is what recommended-project pins.
	priority := map[string]int{"drupal/core-recommended": 0, "drupal/core": 1}
	best, bestRank := "", 2
	for _, p := range lock.Packages {
		rank, ok := priority[p.Name]
		if !ok || rank >= bestRank || p.Version == "" {
			continue
		}
		best, bestRank = p.Version, rank
	}
	if best == "" {
		return "", errors.New("composer.lock does not pin drupal/core")
	}
	return best, nil
}

// FindComposerProjectRoot walks up from the document root (bounded) looking
// for a composer.lock that pins drupal/core. It returns "" when none exists,
// meaning the installation is treated as a tarball extraction.
func FindComposerProjectRoot(docroot string) string {
	dir := docroot
	for i := 0; i < 3; i++ {
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
		if v, err := composerCoreVersion(dir); err == nil && v != "" {
			return dir
		}
	}
	return ""
}
