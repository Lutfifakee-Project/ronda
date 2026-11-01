// Package versioncmp implements distribution-specific package version
// comparison semantics.
//
// RONDA never compares distribution package versions with generic string,
// numeric or SemVer rules: every ecosystem has its own ordering, and a wrong
// ordering would turn a fixed kernel into a vulnerable one. A comparator is
// implemented here only when its semantics are documented and testable:
//
//   - Debian (dpkg): epoch:upstream-revision with tilde ordering.
//   - RPM (RHEL/Fedora/Rocky/Alma/SUSE): [epoch:]version[-release] EVR
//     comparison with the rpmvercmp segment algorithm, including tilde and
//     caret segments.
//   - Alpine (apk): digit/letter/suffix/revision tokens with the apk-tools
//     suffix table (alpha < beta < pre < rc < none < cvs < svn < git < hg < p).
//   - Arch (pacman): rpmvercmp-family segment comparison with tilde support.
//
// Every comparator returns an error for syntax it does not fully understand.
// Callers must turn that error into an UNVERIFIED result instead of guessing.
package versioncmp

import (
	"errors"
	"strconv"
	"strings"
)

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isAlnum(c byte) bool { return isDigit(c) || isAlpha(c) }

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}

// compareNumeric compares two decimal digit runs numerically. Leading zeros
// are stripped first; the run with more digits is larger; equal-width runs
// compare bytewise.
func compareNumeric(a, b string) int {
	i := 0
	for i < len(a) && a[i] == '0' {
		i++
	}
	a = a[i:]
	j := 0
	for j < len(b) && b[j] == '0' {
		j++
	}
	b = b[j:]
	if len(a) != len(b) {
		return sign(len(a) - len(b))
	}
	return strings.Compare(a, b)
}

// ---------------------------------------------------------------------------
// Debian
// ---------------------------------------------------------------------------

// DebianVersion is a parsed Debian package version.
type DebianVersion struct {
	Epoch    int
	Upstream string
	Revision string
}

// ParseDebian splits a Debian package version into epoch, upstream version
// and Debian revision. The epoch ("1:2.4.1-1") is optional and must be
// numeric; the revision is optional and defaults to "0" per Debian policy.
func ParseDebian(v string) (DebianVersion, error) {
	var out DebianVersion
	v = strings.TrimSpace(v)
	if v == "" {
		return out, errors.New("empty Debian version")
	}
	if i := strings.IndexByte(v, ':'); i >= 0 {
		ep := v[:i]
		n, err := strconv.Atoi(ep)
		if err != nil || n < 0 {
			return out, errors.New("invalid Debian epoch " + strconv.Quote(ep))
		}
		out.Epoch = n
		v = v[i+1:]
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		out.Upstream = v[:i]
		out.Revision = v[i+1:]
	} else {
		out.Upstream = v
		out.Revision = "0"
	}
	if out.Upstream == "" {
		return out, errors.New("missing Debian upstream version")
	}
	return out, nil
}

// CompareDebian compares two Debian package versions with dpkg semantics:
// epoch numerically, then upstream version and revision with the dpkg
// character order in which '~' sorts before everything (including the end of
// the string), letters sort before other non-digits, and digit runs compare
// numerically.
func CompareDebian(a, b string) (int, error) {
	va, err := ParseDebian(a)
	if err != nil {
		return 0, err
	}
	vb, err := ParseDebian(b)
	if err != nil {
		return 0, err
	}
	if va.Epoch != vb.Epoch {
		return sign(va.Epoch - vb.Epoch), nil
	}
	if c := dpkgOrder(va.Upstream, vb.Upstream); c != 0 {
		return c, nil
	}
	return dpkgOrder(va.Revision, vb.Revision), nil
}

// dpkgOrder compares two version parts with the dpkg algorithm.
func dpkgOrder(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		// Non-digit characters compare one by one. When one side has no
		// non-digit left, its character is treated as end-of-part (0).
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			var ac, bc byte
			if i < len(a) && !isDigit(a[i]) {
				ac = a[i]
				i++
			}
			if j < len(b) && !isDigit(b[j]) {
				bc = b[j]
				j++
			}
			if c := dpkgCharOrder(ac, bc); c != 0 {
				return c
			}
		}
		// Digit runs compare numerically.
		si, sj := i, j
		for i < len(a) && isDigit(a[i]) {
			i++
		}
		for j < len(b) && isDigit(b[j]) {
			j++
		}
		if i == si && j == sj {
			continue
		}
		if c := compareNumeric(a[si:i], b[sj:j]); c != 0 {
			return c
		}
	}
	return 0
}

// dpkgCharOrder implements the dpkg ordering for one pair of non-digit
// characters. 0 means end-of-part.
func dpkgCharOrder(ac, bc byte) int {
	if ac == bc {
		return 0
	}
	if ac == '~' {
		return -1
	}
	if bc == '~' {
		return 1
	}
	if ac == 0 {
		return -1
	}
	if bc == 0 {
		return 1
	}
	if isAlpha(ac) && !isAlpha(bc) {
		return -1
	}
	if !isAlpha(ac) && isAlpha(bc) {
		return 1
	}
	return sign(int(ac) - int(bc))
}

// ---------------------------------------------------------------------------
// RPM
// ---------------------------------------------------------------------------

// RPMVersion is a parsed RPM EVR triple.
type RPMVersion struct {
	Epoch   int
	Version string
	Release string
}

// ParseRPM splits an RPM EVR string ("[epoch:]version[-release]") into its
// three fields. A missing epoch or release is 0 / empty, as rpm treats them.
func ParseRPM(v string) (RPMVersion, error) {
	var out RPMVersion
	v = strings.TrimSpace(v)
	if v == "" {
		return out, errors.New("empty RPM version")
	}
	if i := strings.IndexByte(v, ':'); i >= 0 {
		n, err := strconv.Atoi(v[:i])
		if err != nil || n < 0 {
			return out, errors.New("invalid RPM epoch")
		}
		out.Epoch = n
		v = v[i+1:]
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		out.Version = v[:i]
		out.Release = v[i+1:]
	} else {
		out.Version = v
	}
	if out.Version == "" {
		return out, errors.New("missing RPM version")
	}
	return out, nil
}

// CompareRPM compares two RPM EVR strings with rpm semantics: the epoch
// compares numerically, then the version and release compare with the
// rpmvercmp segment algorithm (tilde sorts before everything, caret marks a
// post-release snapshot, numeric segments beat alpha segments and digit runs
// compare numerically).
func CompareRPM(a, b string) (int, error) {
	va, err := ParseRPM(a)
	if err != nil {
		return 0, err
	}
	vb, err := ParseRPM(b)
	if err != nil {
		return 0, err
	}
	if va.Epoch != vb.Epoch {
		return sign(va.Epoch - vb.Epoch), nil
	}
	if c, err := rpmvercmp(va.Version, vb.Version, true); err != nil {
		return 0, err
	} else if c != 0 {
		return c, nil
	}
	return rpmvercmp(va.Release, vb.Release, true)
}

// rpmvercmp ports the rpm segment comparison. allowCaret selects the rpm
// flavour (caret = post-release snapshot); the pacman flavour used for Arch
// versions supports tilde only.
func rpmvercmp(a, b string, allowCaret bool) (int, error) {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for i < len(a) && !isAlnum(a[i]) && a[i] != '~' && (!allowCaret || a[i] != '^') {
			i++
		}
		for j < len(b) && !isAlnum(b[j]) && b[j] != '~' && (!allowCaret || b[j] != '^') {
			j++
		}
		aTilde, bTilde := i < len(a) && a[i] == '~', j < len(b) && b[j] == '~'
		if aTilde || bTilde {
			if !aTilde {
				return 1, nil
			}
			if !bTilde {
				return -1, nil
			}
			i++
			j++
			continue
		}
		if allowCaret {
			aCaret, bCaret := i < len(a) && a[i] == '^', j < len(b) && b[j] == '^'
			if aCaret || bCaret {
				// A base version (nothing left) sorts below a caret
				// continuation; an alphanumeric continuation sorts above a
				// caret marker.
				if i >= len(a) {
					return -1, nil
				}
				if j >= len(b) {
					return 1, nil
				}
				if !aCaret {
					return 1, nil
				}
				if !bCaret {
					return -1, nil
				}
				i++
				j++
				continue
			}
		}
		if i >= len(a) || j >= len(b) {
			break
		}
		si, sj := i, j
		if isDigit(a[i]) {
			for i < len(a) && isDigit(a[i]) {
				i++
			}
		} else {
			for i < len(a) && isAlpha(a[i]) {
				i++
			}
		}
		if isDigit(b[j]) {
			for j < len(b) && isDigit(b[j]) {
				j++
			}
		} else {
			for j < len(b) && isAlpha(b[j]) {
				j++
			}
		}
		aDig, bDig := isDigit(a[si]), isDigit(b[sj])
		switch {
		case aDig && bDig:
			if c := compareNumeric(a[si:i], b[sj:j]); c != 0 {
				return c, nil
			}
		case !aDig && !bDig:
			if c := strings.Compare(a[si:i], b[sj:j]); c != 0 {
				return c, nil
			}
		case aDig:
			// Numeric segments beat alpha segments.
			return 1, nil
		default:
			return -1, nil
		}
	}
	// Whichever string still has a meaningful segment left is greater.
	if i < len(a) || j < len(b) {
		for i < len(a) && !isAlnum(a[i]) {
			i++
		}
		for j < len(b) && !isAlnum(b[j]) {
			j++
		}
		if i < len(a) {
			return 1, nil
		}
		if j < len(b) {
			return -1, nil
		}
	}
	return 0, nil
}

// ---------------------------------------------------------------------------
// Arch (pacman)
// ---------------------------------------------------------------------------

// CompareArch compares two Arch package versions ("[epoch:]pkgver-pkgrel")
// with pacman semantics as documented in vercmp(8):
//
//   - the epoch, when present on both sides, overrules every other
//     comparison ("2:1.0-1" > "1:3.6-1");
//   - the pkgrel is only compared when present on both sides ("2.0" equals
//     "2.0-13");
//   - an alpha continuation that directly abuts the previous segment sorts
//     BELOW the base version ("1.0a" < "1.0"), while a separated one sorts
//     above it ("1.0" < "1.0.a"); the documented order is
//     1.0a < 1.0b < 1.0beta < 1.0p < 1.0pre < 1.0rc < 1.0 < 1.0.a < 1.0.1;
//   - '~' still sorts before everything, as in pacman's tilde support.
func CompareArch(a, b string) (int, error) {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	if a == "" || b == "" {
		return 0, errors.New("empty Arch version")
	}
	// Optional epoch prefix, compared numerically. Only decisive when both
	// sides carry one, matching pacman.
	ea, eb := 0, 0
	hasA, hasB := false, false
	if i := strings.IndexByte(a, ':'); i >= 0 {
		n, err := strconv.Atoi(a[:i])
		if err != nil || n < 0 {
			return 0, errors.New("invalid Arch epoch")
		}
		ea, hasA = n, true
		a = a[i+1:]
	}
	if i := strings.IndexByte(b, ':'); i >= 0 {
		n, err := strconv.Atoi(b[:i])
		if err != nil || n < 0 {
			return 0, errors.New("invalid Arch epoch")
		}
		eb, hasB = n, true
		b = b[i+1:]
	}
	if hasA && hasB && ea != eb {
		return sign(ea - eb), nil
	}
	// The pkgrel (after the last '-') only compares when both sides have one.
	va, relA := splitPacmanPkgrel(a)
	vb, relB := splitPacmanPkgrel(b)
	if c, err := pacmanCmp(va, vb); err != nil {
		return 0, err
	} else if c != 0 {
		return c, nil
	}
	if relA == "" || relB == "" {
		return 0, nil
	}
	return pacmanCmp(relA, relB)
}

// splitPacmanPkgrel splits "pkgver-pkgrel" at the last '-'.
func splitPacmanPkgrel(v string) (string, string) {
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		return v[:i], v[i+1:]
	}
	return v, ""
}

// pacmanCmp compares pacman version parts segment by segment. sepA and sepB
// count the separator characters skipped before the upcoming segment; an
// alpha continuation with no separator sorts below the ended base version.
func pacmanCmp(a, b string) (int, error) {
	i, j := 0, 0
	for {
		sepA := 0
		for i < len(a) && !isAlnum(a[i]) && a[i] != '~' {
			i++
			sepA++
		}
		sepB := 0
		for j < len(b) && !isAlnum(b[j]) && b[j] != '~' {
			j++
			sepB++
		}
		aTilde, bTilde := i < len(a) && a[i] == '~', j < len(b) && b[j] == '~'
		if aTilde || bTilde {
			if !aTilde {
				return 1, nil
			}
			if !bTilde {
				return -1, nil
			}
			i++
			j++
			continue
		}
		switch {
		case i >= len(a) && j >= len(b):
			return 0, nil
		case i >= len(a):
			// One side ended. A separated continuation is greater; an alpha
			// continuation that abuts the previous digit segment sorts below
			// the base version (pacman: 1.0a < 1.0 < 1.0.a).
			if !isDigit(b[j]) && sepB == 0 {
				return 1, nil
			}
			return -1, nil
		case j >= len(b):
			if !isDigit(a[i]) && sepA == 0 {
				return -1, nil
			}
			return 1, nil
		}
		// Both continue. Different separator counts decide first (pacman:
		// 2.0a < 2.0.a).
		if sepA != sepB {
			return sign(sepA - sepB), nil
		}
		si, sj := i, j
		if isDigit(a[i]) {
			for i < len(a) && isDigit(a[i]) {
				i++
			}
		} else {
			for i < len(a) && isAlpha(a[i]) {
				i++
			}
		}
		if isDigit(b[j]) {
			for j < len(b) && isDigit(b[j]) {
				j++
			}
		} else {
			for j < len(b) && isAlpha(b[j]) {
				j++
			}
		}
		aDig, bDig := isDigit(a[si]), isDigit(b[sj])
		switch {
		case aDig && bDig:
			if c := compareNumeric(a[si:i], b[sj:j]); c != 0 {
				return c, nil
			}
		case !aDig && !bDig:
			if c := strings.Compare(a[si:i], b[sj:j]); c != 0 {
				return c, nil
			}
		case aDig:
			return 1, nil
		default:
			return -1, nil
		}
	}
}

// ---------------------------------------------------------------------------
// Alpine (apk)
// ---------------------------------------------------------------------------

// Alpine suffix values follow the apk-tools suffix table exactly:
// alpha=0 < beta=1 < pre=2 < rc=3 < none=4 < cvs=5 < svn=6 < git=7 < hg=8
// < p=9. Suffixes below "none" mark pre-releases and sort below the plain
// version; suffixes above "none" mark post-release states and sort above it.
const (
	alpineInvalid = -1
	alpineAlpha   = 0
	alpineBeta    = 1
	alpinePre     = 2
	alpineRC      = 3
	alpineNone    = 4
	alpineCVS     = 5
	alpineSVN     = 6
	alpineGit     = 7
	alpineHG      = 8
	alpineP       = 9
)

var alpineSuffixes = []struct {
	name  string
	value int
}{
	{"alpha", alpineAlpha},
	{"beta", alpineBeta},
	{"pre", alpinePre},
	{"rc", alpineRC},
	{"cvs", alpineCVS},
	{"svn", alpineSVN},
	{"git", alpineGit},
	{"hg", alpineHG},
	{"p", alpineP},
}

// alpineToken kinds.
const (
	alpineTkDigit = iota
	alpineTkLetter
	alpineTkSuffix
	alpineTkRevision
	alpineTkEnd
)

type alpineToken struct {
	kind   int
	digits string // raw digit run (may carry leading zeros)
	number uint64 // numeric value of digits, suffix number or revision
	letter string // letter token content
	suffix int    // suffix table value
}

// nextAlpineToken parses the next token of an Alpine version string. The
// grammar is digit{.digit}...{letter}{_suf{number}}...{-rnumber}; anything
// else is invalid and the caller must report UNVERIFIED rather than guess.
func nextAlpineToken(s string, pos int, seenRevision bool) (alpineToken, int, bool) {
	if pos >= len(s) {
		return alpineToken{kind: alpineTkEnd}, pos, true
	}
	// '.' separates digit runs inside the main version part and carries no
	// ordering information of its own.
	for pos < len(s) && s[pos] == '.' {
		pos++
	}
	if pos >= len(s) {
		return alpineToken{kind: alpineTkEnd}, pos, true
	}
	c := s[pos]
	switch {
	case isDigit(c):
		start := pos
		for pos < len(s) && isDigit(s[pos]) {
			pos++
		}
		run := s[start:pos]
		n, err := strconv.ParseUint(run, 10, 64)
		if err != nil {
			return alpineToken{}, pos, false
		}
		return alpineToken{kind: alpineTkDigit, digits: run, number: n}, pos, true
	case isAlpha(c):
		start := pos
		for pos < len(s) && isAlpha(s[pos]) {
			pos++
		}
		return alpineToken{kind: alpineTkLetter, letter: s[start:pos]}, pos, true
	case c == '_':
		pos++
		rest := s[pos:]
		for _, suf := range alpineSuffixes {
			if len(rest) >= len(suf.name) && rest[:len(suf.name)] == suf.name {
				pos += len(suf.name)
				num := uint64(0)
				dstart := pos
				for pos < len(s) && isDigit(s[pos]) {
					pos++
				}
				if pos > dstart {
					n, err := strconv.ParseUint(s[dstart:pos], 10, 64)
					if err != nil {
						return alpineToken{}, pos, false
					}
					num = n
				}
				return alpineToken{kind: alpineTkSuffix, suffix: suf.value, number: num}, pos, true
			}
		}
		return alpineToken{}, pos, false
	case c == '-':
		if seenRevision || pos+2 > len(s) || s[pos+1] != 'r' {
			return alpineToken{}, pos, false
		}
		pos += 2
		dstart := pos
		for pos < len(s) && isDigit(s[pos]) {
			pos++
		}
		if pos == dstart {
			return alpineToken{}, pos, false
		}
		n, err := strconv.ParseUint(s[dstart:pos], 10, 64)
		if err != nil {
			return alpineToken{}, pos, false
		}
		return alpineToken{kind: alpineTkRevision, number: n}, pos, true
	}
	return alpineToken{}, pos, false
}

// CompareAlpine compares two Alpine package versions ("6.6.58-r0") with
// apk-tools semantics: digit, letter, suffix and revision tokens; digit runs
// with a leading zero compare as raw strings (Gentoo-style, per apk-tools);
// pre-release suffixes (alpha..rc) sort below the plain version while
// post-release suffixes (cvs, svn, git, hg, p) sort above it; '-rN' is the
// numeric revision and must be last. Syntax outside the documented grammar
// (for example a '~' snapshot marker) returns an error so the caller can
// report UNVERIFIED instead of guessing.
func CompareAlpine(a, b string) (int, error) {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	if a == "" || b == "" {
		return 0, errors.New("empty Alpine version")
	}
	pa, pb := 0, 0
	revA, revB := false, false
	for {
		ta, na, okA := nextAlpineToken(a, pa, revA)
		tb, nb, okB := nextAlpineToken(b, pb, revB)
		if !okA || !okB {
			return 0, errors.New("unsupported Alpine version syntax")
		}
		// Nothing may follow the revision.
		if ta.kind != alpineTkEnd && revA {
			return 0, errors.New("Alpine revision must be last")
		}
		if tb.kind != alpineTkEnd && revB {
			return 0, errors.New("Alpine revision must be last")
		}
		if ta.kind == tb.kind {
			if ta.kind == alpineTkEnd {
				return 0, nil
			}
			if c := alpineTokenCompare(ta, tb); c != 0 {
				return c, nil
			}
			if ta.kind == alpineTkRevision {
				revA, revB = true, true
			}
			pa, pb = na, nb
			continue
		}
		// The token kinds differ. A pre-release suffix (alpha..rc) sorts
		// below whatever the other side has, per the apk-tools comparison
		// rules; otherwise the non-terminating side is greater.
		if ta.kind == alpineTkSuffix && ta.suffix < alpineNone {
			return -1, nil
		}
		if tb.kind == alpineTkSuffix && tb.suffix < alpineNone {
			return 1, nil
		}
		if ta.kind == alpineTkEnd || tb.kind == alpineTkEnd {
			if ta.kind == alpineTkEnd {
				return -1, nil
			}
			return 1, nil
		}
		// Remaining mixed token kinds are not part of the tested subset;
		// refuse to guess.
		return 0, errors.New("unsupported Alpine version token mix")
	}
}

// alpineTokenCompare compares two tokens of the same kind.
func alpineTokenCompare(a, b alpineToken) int {
	switch a.kind {
	case alpineTkDigit:
		// A leading zero selects the raw string order, as apk-tools does
		// ("06" < "6", "0" < "00").
		if strings.HasPrefix(a.digits, "0") || strings.HasPrefix(b.digits, "0") {
			return strings.Compare(a.digits, b.digits)
		}
		return compareNumeric(a.digits, b.digits)
	case alpineTkLetter:
		return strings.Compare(a.letter, b.letter)
	case alpineTkSuffix:
		if a.suffix != b.suffix {
			return sign(a.suffix - b.suffix)
		}
		return sign(int(a.number) - int(b.number))
	case alpineTkRevision:
		return sign(int(a.number) - int(b.number))
	}
	return 0
}
