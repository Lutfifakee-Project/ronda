package wplocale

import (
	"regexp"
	"strings"
)

// WPLANGInfo is the static-analysis result for the WPLANG constant in
// wp-config.php. WPLANG is a RUNTIME language setting: it is recorded for
// reporting and must never be used to establish the package locale.
type WPLANGInfo struct {
	// Found is true when at least one code-level define('WPLANG', ...)
	// was found.
	Found bool
	// Value is the runtime language value ('' means the classic
	// "default/en_US" wp-config setting). It is only populated when the
	// value is a static, non-interpolated string.
	Value string
	// Static is false when the define exists but its value could not be
	// resolved statically (dynamic expression, interpolation, ...).
	Static bool
	// Conflicting is true when multiple defines disagree.
	Conflicting bool
	// Values lists every statically resolved value, in order.
	Values []string
	// Ambiguities holds advisory notes.
	Ambiguities []string
}

var reDefine = regexp.MustCompile(`(?i)\bdefine\b`)

// ExtractWPLANG statically extracts the WPLANG constant from the content of
// wp-config.php. Commented-out defines are ignored; string contents never
// produce defines (all scanning happens on masked, code-only offsets).
func ExtractWPLANG(src []byte) WPLANGInfo {
	segs := Segments(src)
	masked := MaskSource(src, segs)

	info := WPLANGInfo{}

	for _, loc := range reDefine.FindAllIndex(masked, -1) {
		p := loc[0]

		// Skip method calls ($x->define, Foo::define).
		if isMethodCall(masked, p) {
			continue
		}

		i := loc[1]
		i = skipSpaces(masked, i)
		if i >= len(masked) || masked[i] != '(' {
			continue
		}
		i = skipSpaces(masked, i+1)
		if i >= len(masked) || masked[i] != 0 {
			continue // constant name must be a quoted string
		}
		keySeg := StringSegmentAt(segs, i)
		if keySeg == nil || keySeg.Interpolated || keySeg.Heredoc {
			continue
		}
		if !strings.EqualFold(keySeg.Value, "WPLANG") {
			continue
		}

		i = skipSpaces(masked, keySeg.End)
		if i >= len(masked) || masked[i] != ',' {
			continue
		}

		a, end := readRHS(masked, segs, i)
		// Consume up to the closing paren so weird trailing syntax does
		// not get re-interpreted.
		j := end
		for j < len(masked) && masked[j] != ')' {
			j++
		}

		info.Found = true
		switch a.kind {
		case rhsLiteral:
			info.Values = append(info.Values, a.value)
			info.Static = true
		case rhsNull:
			info.Values = append(info.Values, "")
			info.Static = true
		case rhsEmpty:
			info.Ambiguities = append(info.Ambiguities,
				"WPLANG define with empty right-hand side (malformed)")
		default:
			info.Ambiguities = append(info.Ambiguities,
				"WPLANG define with non-static value; runtime language unresolved")
		}
	}

	if len(info.Values) > 0 {
		info.Value = info.Values[0]
		for _, v := range info.Values[1:] {
			if v != info.Value {
				info.Conflicting = true
			}
		}
	}
	if info.Conflicting {
		info.Ambiguities = append(info.Ambiguities,
			"conflicting WPLANG definitions: "+strings.Join(info.Values, ", "))
	}
	return info
}

func skipSpaces(masked []byte, i int) int {
	for i < len(masked) && isSpaceByte(masked[i]) {
		i++
	}
	return i
}

// isMethodCall reports whether the identifier starting at pos is preceded by
// -> or :: (a method named define rather than the define() call).
func isMethodCall(masked []byte, pos int) bool {
	i := pos - 1
	for i >= 0 && isSpaceByte(masked[i]) {
		i--
	}
	if i < 0 {
		return false
	}
	if masked[i] == '>' && i > 0 && masked[i-1] == '-' {
		return true
	}
	if masked[i] == ':' && i > 0 && masked[i-1] == ':' {
		return true
	}
	return false
}

// Analyze is the one-call entry point: it statically parses the contents of
// wp-includes/version.php and wp-config.php (either may be nil) and resolves
// the package-locale assessment and checksum decision.
func Analyze(versionPHP, wpConfig []byte, opts Options) (*LocaleAssessment, *ChecksumDecision, *VersionFile, WPLANGInfo) {
	var vf *VersionFile
	if versionPHP != nil {
		vf = ParseVersionPHP(versionPHP)
	} else {
		vf = &VersionFile{Marker: MarkerInfo{State: MarkerAbsent}}
	}
	wpl := WPLANGInfo{}
	if wpConfig != nil {
		wpl = ExtractWPLANG(wpConfig)
	}
	assessment := Assess(vf, wpl, opts)
	gate := ChecksumGate(assessment, opts)
	return assessment, gate, vf, wpl
}
