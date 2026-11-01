package wplocale

import (
	"regexp"
	"strings"
)

// MarkerState summarizes what static analysis can establish about
// $wp_local_package in wp-includes/version.php.
type MarkerState int

const (
	// MarkerAbsent: no code-level assignment to $wp_local_package exists.
	MarkerAbsent MarkerState = iota
	// MarkerEmpty: assigned an empty string (or null); not a reliable marker.
	MarkerEmpty
	// MarkerPresent: assigned a static, well-formed locale string.
	MarkerPresent
	// MarkerDynamic: assigned a non-literal expression (variable, function
	// call, interpolation, shell-exec string); static analysis cannot
	// resolve it.
	MarkerDynamic
	// MarkerInvalid: assigned a static string that is not a well-formed
	// WordPress locale.
	MarkerInvalid
	// MarkerConflicting: multiple assignments disagree, or static and
	// dynamic assignments are mixed.
	MarkerConflicting
)

func (m MarkerState) String() string {
	switch m {
	case MarkerAbsent:
		return "absent"
	case MarkerEmpty:
		return "empty"
	case MarkerPresent:
		return "present"
	case MarkerDynamic:
		return "dynamic"
	case MarkerInvalid:
		return "invalid"
	case MarkerConflicting:
		return "conflicting"
	}
	return "unknown"
}

// MarkerInfo is the static-analysis result for $wp_local_package.
type MarkerInfo struct {
	State       MarkerState
	Value       string   // locale value when State == MarkerPresent
	Occurrences int      // number of code-level assignments seen
	Ambiguities []string // advisory notes; do not change State by themselves
}

// VersionFile is the statically extracted content of
// wp-includes/version.php.
type VersionFile struct {
	WPVersion      string
	HasWPVersion   bool
	WPDBVersion    string
	HasWPDBVersion bool
	Marker         MarkerInfo
}

var varMarker = regexp.MustCompile(`\$wp_local_package\b`)
var varWPVersion = regexp.MustCompile(`\$wp_version\b`)
var varWPDBVersion = regexp.MustCompile(`\$wp_db_version\b`)
var commentAssignment = regexp.MustCompile(`wp_local_package\s*=`)

// validWPLocale reports whether s is a structurally valid WordPress locale
// tag: a 2-3 letter language, optionally followed by a region and/or
// suffixes (en_US, ja, de_DE, pt_BR, zh_CN, de_DE_informal, ...). It
// deliberately rejects values that cannot be a WordPress locale.
func validWPLocale(s string) bool {
	if len(s) < 2 || len(s) > 32 {
		return false
	}
	if s[0] < 'a' || s[0] > 'z' {
		return false
	}
	parts := strings.Split(s, "_")
	// Primary language: 2-3 lowercase letters.
	if len(parts[0]) < 2 || len(parts[0]) > 3 {
		return false
	}
	for _, c := range parts[0] {
		if c < 'a' || c > 'z' {
			return false
		}
	}
	// Optional remainder: region is 2-3 letters (usually uppercase),
	// further suffixes are alphanumerics (e.g. "informal").
	for i, part := range parts[1:] {
		if part == "" {
			return false
		}
		if i == 0 {
			if len(part) < 2 || len(part) > 3 {
				return false
			}
			for _, c := range part {
				if !isLocaleAlnum(c) {
					return false
				}
			}
			continue
		}
		for _, c := range part {
			if !isLocaleAlnum(c) {
				return false
			}
		}
	}
	return true
}

func isLocaleAlnum(c rune) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// assignment is one statically resolved assignment to a PHP variable.
type assignment struct {
	kind  rhsKind
	value string
	notes []string
}

type rhsKind int

const (
	rhsEmpty rhsKind = iota // malformed: nothing between '=' and ';'
	rhsLiteral
	rhsNull
	rhsNumeric
	rhsDynamic
	rhsInterpolated
	rhsExecString
)

var identStart = func(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c >= 0x80
}
var identByte = func(c byte) bool {
	return identStart(c) || (c >= '0' && c <= '9')
}

// readRHS statically resolves the right-hand side of an assignment whose '='
// sits at eqPos (offset into the original source). masked is the offset-
// preserving masked source; segs are the lexical segments. It returns the
// resolved assignment and the offset where scanning of the RHS ended.
func readRHS(masked []byte, segs []Segment, eqPos int) (assignment, int) {
	i := eqPos + 1
	for i < len(masked) && isSpaceByte(masked[i]) {
		i++
	}
	if i >= len(masked) {
		return assignment{kind: rhsEmpty}, i
	}

	// Non-string RHS: a code token (null, number, identifier, ...).
	if masked[i] != 0 {
		j := i
		for j < len(masked) && masked[j] != ';' && masked[j] != 0 && !isSpaceByte(masked[j]) {
			j++
		}
		tok := string(masked[i:j])
		switch {
		case strings.EqualFold(tok, "null"):
			return assignment{kind: rhsNull, notes: []string{"$wp_local_package assigned null"}}, j
		case isNumericToken(tok):
			return assignment{kind: rhsNumeric, value: tok}, j
		case tok == "":
			return assignment{kind: rhsEmpty}, j
		default:
			return assignment{kind: rhsDynamic, value: tok}, j
		}
	}

	// String literal RHS.
	s := StringSegmentAt(segs, i)
	if s == nil {
		return assignment{kind: rhsEmpty}, i
	}
	a := assignment{kind: rhsLiteral, value: s.Value}
	if s.Quote == '`' {
		return assignment{kind: rhsExecString, value: s.Value,
			notes: []string{"$wp_local_package assigned a shell-exec (backtick) string"}}, s.End
	}
	if s.Interpolated && !s.Nowdoc {
		a.kind = rhsInterpolated
		return a, s.End
	}

	// Simple '.' concatenation of further literals.
	i = s.End
	for {
		j := i
		for j < len(masked) && isSpaceByte(masked[j]) {
			j++
		}
		if j < len(masked) && masked[j] == '.' && !(j+1 < len(masked) && masked[j+1] == '.') {
			k := j + 1
			for k < len(masked) && isSpaceByte(masked[k]) {
				k++
			}
			if k < len(masked) && masked[k] == 0 {
				s2 := StringSegmentAt(segs, k)
				if s2 == nil || s2.Interpolated && !s2.Nowdoc {
					a.kind = rhsDynamic
					a.notes = append(a.notes, "concatenated value is not a static literal")
					return a, k
				}
				a.value += s2.Value
				i = s2.End
				continue
			}
			a.kind = rhsDynamic
			a.notes = append(a.notes, "concatenated value is not a static string literal")
			return a, k
		}
		i = j
		break
	}

	// Sanity: the next code character should end the statement.
	for i < len(masked) && isSpaceByte(masked[i]) {
		i++
	}
	if i < len(masked) && masked[i] != 0 && masked[i] != ';' {
		a.notes = append(a.notes, "unexpected trailing expression after marker value")
	}
	return a, i
}

func isNumericToken(tok string) bool {
	if tok == "" {
		return false
	}
	dot := false
	for idx := 0; idx < len(tok); idx++ {
		c := tok[idx]
		if c == '.' {
			if dot {
				return false
			}
			dot = true
			continue
		}
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// scanAssignments finds every code-level assignment to the named variable
// and statically resolves each right-hand side.
func scanAssignments(masked []byte, segs []Segment, re *regexp.Regexp) []assignment {
	var out []assignment
	for _, loc := range re.FindAllIndex(masked, -1) {
		end := loc[1]
		i := end
		for i < len(masked) && isSpaceByte(masked[i]) {
			i++
		}
		if i >= len(masked) {
			continue
		}
		c := masked[i]
		if c == '=' {
			if i+1 < len(masked) && (masked[i+1] == '=' || masked[i+1] == '>') {
				continue // ==, =>
			}
			a, _ := readRHS(masked, segs, i)
			out = append(out, a)
			continue
		}
		if (c == '.' || c == '+' || c == '?') && i+1 < len(masked) && masked[i+1] == '=' {
			out = append(out, assignment{kind: rhsDynamic,
				value: string(masked[i : i+2]),
				notes: []string{"compound assignment to $wp_local_package; result depends on prior value"}})
			continue
		}
		// Comparison or usage, not an assignment: skip.
	}
	return out
}

func mergeAssignments(as []assignment) MarkerInfo {
	mi := MarkerInfo{Occurrences: len(as)}
	if len(as) == 0 {
		mi.State = MarkerAbsent
		return mi
	}

	literal := ""
	literals := 0
	dynamic := 0
	conflict := false
	for _, a := range as {
		mi.Ambiguities = append(mi.Ambiguities, a.notes...)
		switch a.kind {
		case rhsLiteral, rhsNumeric:
			if literals == 0 {
				literal = a.value
			} else if a.value != literal {
				conflict = true
			}
			literals++
		case rhsNull:
			// Explicit null: semantically "no package", but ambiguous as a
			// marker.
			mi.Ambiguities = append(mi.Ambiguities, "$wp_local_package assigned null")
		case rhsEmpty:
			mi.Ambiguities = append(mi.Ambiguities, "$wp_local_package assignment with empty right-hand side (malformed)")
			conflict = true
		case rhsInterpolated:
			mi.Ambiguities = append(mi.Ambiguities, "$wp_local_package assigned an interpolated string; value not static")
			dynamic++
		case rhsExecString:
			mi.Ambiguities = append(mi.Ambiguities, "$wp_local_package assigned a shell-exec (backtick) string")
			dynamic++
		default:
			dynamic++
		}
	}

	switch {
	case conflict:
		mi.State = MarkerConflicting
		mi.Value = ""
		return mi
	case dynamic > 0 && literals > 0:
		mi.State = MarkerConflicting
		return mi
	case dynamic > 0:
		mi.State = MarkerDynamic
		return mi
	case literals == 0:
		// Only null assignments.
		mi.State = MarkerEmpty
		return mi
	}

	if literal == "" {
		mi.State = MarkerEmpty
		return mi
	}
	if !validWPLocale(literal) {
		mi.State = MarkerInvalid
		mi.Value = literal
		mi.Ambiguities = append(mi.Ambiguities, "$wp_local_package value is not a well-formed WordPress locale")
		return mi
	}
	mi.State = MarkerPresent
	mi.Value = literal
	if literals > 1 {
		mi.Ambiguities = append(mi.Ambiguities, "duplicate identical $wp_local_package definitions")
	}
	return mi
}

// ParseVersionPHP statically analyzes the content of wp-includes/version.php
// and extracts the WordPress version, database revision and the
// $wp_local_package marker. Comments, string contents, heredocs, nowdocs and
// backtick strings never contribute assignments.
func ParseVersionPHP(src []byte) *VersionFile {
	segs := Segments(src)
	masked := MaskSource(src, segs)

	vf := &VersionFile{}

	if as := scanAssignments(masked, segs, varWPVersion); len(as) > 0 {
		a := as[0]
		if a.kind == rhsLiteral || a.kind == rhsNumeric {
			vf.WPVersion, vf.HasWPVersion = a.value, true
		}
	}
	if as := scanAssignments(masked, segs, varWPDBVersion); len(as) > 0 {
		a := as[0]
		if a.kind == rhsLiteral || a.kind == rhsNumeric {
			vf.WPDBVersion, vf.HasWPDBVersion = a.value, true
		}
	}

	mi := mergeAssignments(scanAssignments(masked, segs, varMarker))

	// Commented-out definitions are advisory signals only: they never
	// establish a locale, but they may indicate a stripped or tampered
	// metadata block.
	for _, s := range segs {
		if s.Kind != SegComment {
			continue
		}
		if commentAssignment.Match(src[s.Start:s.End]) {
			mi.Ambiguities = append(mi.Ambiguities,
				"commented-out assignment to $wp_local_package found in PHP comments (metadata may have been stripped)")
			break
		}
	}

	vf.Marker = mi
	return vf
}
