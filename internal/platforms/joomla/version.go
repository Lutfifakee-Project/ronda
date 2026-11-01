package joomla

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	// constIntRE matches both Joomla 4/5 class constants (MAJOR_VERSION = 5)
	// and Joomla 3 public properties (public $RELEASE = '3.10'). The value
	// token is captured whole and unquoted in code, so quoted values with
	// dots ('3.10') are not truncated to their leading digits.
	constIntRE   = regexp.MustCompile(`(?:const|public[[:space:]]+\$)[[:space:]]*([A-Z_]+)[[:space:]]*=[[:space:]]*('(?:[^']*)'|"(?:[^"]*)"|[0-9]+)`)
	xmlVersionRE = regexp.MustCompile(`<version>([^<]+)</version>`)
)

// stableVersionRE accepts only stable releases; development and pre-release
// markers refuse verification.
var stableVersionRE = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)

// DetectVersion collects static version signals:
//  1. libraries/src/Version.php class constants (Joomla 3.8+, 4, 5)
//  2. legacy libraries/cms/version/version.php RELEASE/DEV_LEVEL (Joomla 3.x)
//  3. administrator/manifests/files/joomla.xml <version>
func DetectVersion(root string) []VersionSource {
	var sources []VersionSource

	if v, ok := versionFromModernPHP(filepath.Join(root, filepath.FromSlash(MarkerVersion))); ok {
		sources = append(sources, VersionSource{Value: v, Source: MarkerVersion})
	}
	if v, ok := versionFromLegacyPHP(filepath.Join(root, filepath.FromSlash(MarkerVersionOld))); ok {
		sources = append(sources, VersionSource{Value: v, Source: MarkerVersionOld})
	}
	if data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(MarkerManifest))); err == nil {
		if m := xmlVersionRE.FindSubmatch(data); m != nil {
			v := strings.TrimSpace(string(m[1]))
			if v != "" {
				sources = append(sources, VersionSource{Value: v, Source: MarkerManifest})
			}
		}
	}
	return sources
}

// versionFromModernPHP reads MAJOR_VERSION/MINOR_VERSION/PATCH_VERSION and
// EXTRA_VERSION from a Version.php file.
func versionFromModernPHP(path string) (string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	get := func(name string) (string, bool) {
		for _, m := range constIntRE.FindAllSubmatch(data, -1) {
			if string(m[1]) == name {
				v := strings.Trim(string(m[2]), `"'`)
				return v, true
			}
		}
		return "", false
	}
	major, ok1 := get("MAJOR_VERSION")
	minor, ok2 := get("MINOR_VERSION")
	patch, ok3 := get("PATCH_VERSION")
	if !ok1 || !ok2 || !ok3 {
		return "", false
	}
	version := major + "." + minor + "." + patch
	if extra, ok := get("EXTRA_VERSION"); ok && extra != "" {
		if isDevMarker(extra) {
			return version + extra, true // caller refuses dev markers
		}
		version += extra
	}
	return version, true
}

// versionFromLegacyPHP reads RELEASE/DEV_LEVEL from a pre-3.8 Version.php.
func versionFromLegacyPHP(path string) (string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	release := ""
	level := ""
	for _, m := range constIntRE.FindAllSubmatch(data, -1) {
		switch string(m[1]) {
		case "RELEASE":
			release = strings.Trim(string(m[2]), `"'`)
		case "DEV_LEVEL":
			level = strings.Trim(string(m[2]), `"'`)
		}
	}
	if release == "" || level == "" {
		return "", false
	}
	return release + "." + level, true
}

// isDevMarker reports whether a version suffix marks a development or
// pre-release build that has no supported official full-package reference.
func isDevMarker(s string) bool {
	l := strings.ToLower(s)
	for _, marker := range []string{"dev", "rc", "beta", "alpha", "nightly", "testing"} {
		if strings.Contains(l, marker) {
			return true
		}
	}
	return false
}

// EstablishVersion returns the version all sources agree on, or "" plus a
// reason when signals conflict, are missing, or are not a stable release.
func EstablishVersion(sources []VersionSource) (string, string) {
	if len(sources) == 0 {
		return "", "could not read the Joomla version from Version.php or joomla.xml"
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
