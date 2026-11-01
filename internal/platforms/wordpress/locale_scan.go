package wordpress

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/Lutfifakee-Project/ronda/internal/wplocale"
)

// maxLocaleScanBytes caps the size of PHP files accepted by the locale
// scanners. wp-includes/version.php and wp-config.php are far smaller in any
// real installation; a file beyond this bound is treated as unreadable for
// locale analysis rather than scanned.
const maxLocaleScanBytes = 4 << 20

// localeResolution is the outcome of static package-locale detection.
type localeResolution struct {
	Locale     string
	Source     string
	Confidence string
	Inferred   bool
	// Established is true only when the package locale was determined from
	// authoritative metadata: an explicit, well-formed override or a static,
	// well-formed $wp_local_package marker. When false, checksum selection
	// must not proceed.
	Established bool
	// RuntimeLanguage is the WPLANG runtime site language from wp-config.php.
	// It is recorded for reporting only and never selects core checksums.
	RuntimeLanguage string
	// Detail explains a refusal in human-readable form.
	Detail string
}

// resolveLocale determines the core package locale using static signals only.
//
// Precedence (highest first):
//  1. explicit locale override, validated before it is applied;
//  2. a reliable $wp_local_package marker in wp-includes/version.php;
//  3. nothing. A missing marker is consistent with the base en_US package but
//     is never treated as proof of it: the resolution stays unestablished so
//     verification reports UNVERIFIED until --wp-locale is supplied.
//
// Runtime WPLANG is recorded separately and never establishes the package
// locale. All detection is lexical: assignments are read from the masked,
// code-only view of the file, so commented-out assignments, marker text
// inside comments, strings, heredocs and nowdocs can never establish a
// locale.
func resolveLocale(root, override string) localeResolution {
	res := localeResolution{RuntimeLanguage: DetectRuntimeLanguage(root)}

	// 1. Explicit override: highest priority, validated before use.
	ov := strings.TrimSpace(override)
	if ov != "" {
		res.Locale = ov
		res.Source = "override"
		if validLocale(ov) {
			res.Confidence = ConfidenceHigh
			res.Established = true
			return res
		}
		res.Confidence = ConfidenceLow
		res.Detail = "explicit locale override is not a well-formed WordPress locale"
		return res
	}

	vf := analyzeVersionFile(root)
	if vf == nil {
		res.Source = "missing_marker"
		res.Confidence = ConfidenceLow
		res.Inferred = true
		res.Detail = "could not read wp-includes/version.php"
		return res
	}

	// 2. Package marker: authoritative only when statically reliable.
	switch vf.Marker.State {
	case wplocale.MarkerPresent:
		res.Locale = vf.Marker.Value
		res.Source = "wp_local_package"
		if validLocale(vf.Marker.Value) {
			res.Confidence = ConfidenceHigh
			res.Established = true
			return res
		}
		res.Confidence = ConfidenceLow
		res.Detail = "$wp_local_package value is not a well-formed WordPress locale"
		return res

	case wplocale.MarkerAbsent:
		// 3. Nothing establishes the locale. The base en_US package omits
		// the marker, but a localized package could have lost it too, so
		// absence is never treated as en_US.
		res.Source = "missing_marker"
		res.Confidence = ConfidenceLow
		res.Inferred = true
		res.Detail = "missing marker does not establish en_US"
		return res

	default:
		// The marker exists but is empty, dynamic, malformed or conflicting:
		// ambiguous metadata must not silently become en_US.
		res.Source = "wp_local_package"
		res.Confidence = ConfidenceLow
		res.Detail = markerDetail(vf.Marker)
		return res
	}
}

// markerDetail explains why a present-but-unreliable marker was refused.
func markerDetail(m wplocale.MarkerInfo) string {
	switch m.State {
	case wplocale.MarkerEmpty:
		return "$wp_local_package is empty or null; an empty marker is not a reliable locale signal"
	case wplocale.MarkerDynamic:
		return "$wp_local_package is not a static string literal"
	case wplocale.MarkerInvalid:
		return "$wp_local_package value " + m.Value + " is not a well-formed WordPress locale"
	case wplocale.MarkerConflicting:
		return "conflicting $wp_local_package definitions"
	}
	return "$wp_local_package is unreliable"
}

// analyzeVersionFile statically parses wp-includes/version.php through the
// wplocale masked scanner. It returns nil when the file is missing, not a
// regular file or beyond the size cap.
func analyzeVersionFile(root string) *wplocale.VersionFile {
	src, ok := readCapped(filepath.Join(root, "wp-includes", "version.php"), maxLocaleScanBytes)
	if !ok {
		return nil
	}
	return wplocale.ParseVersionPHP(src)
}

// DetectVersion reads the WordPress version from wp-includes/version.php
// without executing PHP, using masked lexical scanning: commented-out or
// string-embedded assignments never produce a version. It returns "" when no
// static version can be determined.
func DetectVersion(root string) string {
	vf := analyzeVersionFile(root)
	if vf == nil || !vf.HasWPVersion {
		return ""
	}
	return vf.WPVersion
}

// DetectLocalPackage reads the wp_local_package marker from
// wp-includes/version.php. Localized WordPress packages set this to their
// locale (for example id_ID); the base en_US package omits it. Only a static,
// well-formed code-level assignment counts: commented-out, empty, dynamic,
// malformed or conflicting markers return "". Use resolveLocale to distinguish
// these cases.
func DetectLocalPackage(root string) string {
	vf := analyzeVersionFile(root)
	if vf == nil || vf.Marker.State != wplocale.MarkerPresent {
		return ""
	}
	return vf.Marker.Value
}

// DetectRuntimeLanguage reads WPLANG from wp-config.php. This is the runtime
// site language, not the core package locale, and must not be used to select
// core checksums. It returns "" when no static WPLANG value is configured.
func DetectRuntimeLanguage(root string) string {
	src, ok := readCapped(filepath.Join(root, "wp-config.php"), maxLocaleScanBytes)
	if !ok {
		return ""
	}
	info := wplocale.ExtractWPLANG(src)
	if !info.Found || !info.Static {
		return ""
	}
	return info.Value
}

// readCapped reads a regular file up to the byte limit. Anything else
// (missing file, directory, oversized file, read error) reports false.
func readCapped(path string, limit int64) ([]byte, bool) {
	st, err := os.Stat(path)
	if err != nil || !st.Mode().IsRegular() || st.Size() > limit {
		return nil, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	return data, true
}

// validLocale accepts the WordPress locale shapes: ll, ll_CC, ll_CC_variant,
// using lowercase or uppercase letters, digits and underscores only.
func validLocale(s string) bool {
	if len(s) < 2 || len(s) > 20 {
		return false
	}
	underscores := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		isLetter := (c >= 97 && c <= 122) || (c >= 65 && c <= 90)
		isDigit := c >= 48 && c <= 57
		if c == 95 {
			underscores++
			if underscores > 2 {
				return false
			}
			continue
		}
		if !isLetter && !isDigit {
			return false
		}
	}
	return true
}
