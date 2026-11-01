package wplocale

import "fmt"

// Status is the verdict for the package-locale assessment.
type Status string

const (
	// StatusVerified means the package locale is established by an
	// authoritative source (explicit override or a reliable marker).
	StatusVerified Status = "VERIFIED"
	// StatusUnverified means the package locale could not be established
	// reliably. This includes missing, empty, dynamic, malformed and
	// conflicting metadata.
	StatusUnverified Status = "UNVERIFIED"
)

// LocaleSource names the authority a locale assessment came from.
type LocaleSource string

const (
	SourceNone     LocaleSource = "none"
	SourceExplicit LocaleSource = "explicit_override" // --wp-locale
	SourcePackage  LocaleSource = "package_marker"    // $wp_local_package
	SourceAssumed  LocaleSource = "assumed_en_US_fallback"
	SourceUnknown  LocaleSource = "unknown"
)

// Confidence qualifies the assessment.
type Confidence string

const (
	ConfHigh   Confidence = "high"
	ConfMedium Confidence = "medium"
	ConfLow    Confidence = "low"
	ConfNone   Confidence = "none"
)

// LocaleAssessment is the outcome of package-locale resolution.
type LocaleAssessment struct {
	// Locale is the established package locale, or "" when unknown. Under
	// the opt-in fallback it may hold "en_US" while Status stays
	// UNVERIFIED.
	Locale string
	Status Status
	Source LocaleSource
	// Confidence: high for verified locales, low for the assumed en_US
	// fallback, none for unverified locale.
	Confidence Confidence
	// Inferred is true when the locale was derived/assumed rather than
	// read from authoritative metadata.
	Inferred bool
	// RuntimeWPLANG mirrors the runtime language from wp-config.php. It
	// is reported separately and never establishes the package locale.
	RuntimeWPLANG      string
	RuntimeWPLANGFound bool
	// Reasons explains the decision, one human-readable line each.
	Reasons []string
}

// Options controls resolution.
type Options struct {
	// ExplicitLocale is the operator-provided --wp-locale value ("" when
	// the flag was not given). It has the highest precedence and is
	// validated; an invalid value is refused rather than silently
	// ignored.
	ExplicitLocale string
	// AllowEnUSFallback enables the legacy behavior of assuming en_US
	// when the package locale cannot be established. The assessment
	// remains UNVERIFIED (Inferred, low confidence) and checksum results
	// must be reported as provisional. Default false: missing metadata is
	// never silently treated as en_US.
	AllowEnUSFallback bool
}

// Assess resolves the package locale from statically parsed metadata,
// applying the documented precedence: explicit override > reliable
// $wp_local_package marker > nothing (WPLANG is runtime language only).
func Assess(vf *VersionFile, wpl WPLANGInfo, opts Options) *LocaleAssessment {
	a := &LocaleAssessment{
		RuntimeWPLANGFound: wpl.Found,
	}
	if wpl.Found {
		a.RuntimeWPLANG = wpl.Value
	}

	switch {
	case opts.ExplicitLocale != "":
		if !validWPLocale(opts.ExplicitLocale) {
			a.Status = StatusUnverified
			a.Source = SourceNone
			a.Confidence = ConfNone
			a.Reasons = append(a.Reasons,
				fmt.Sprintf("explicit --wp-locale value %q is not a well-formed WordPress locale; refusing to apply it", opts.ExplicitLocale))
			a.noteMarkerState(vf)
			a.noteRuntimeWPLANG(wpl)
			return a
		}
		a.Locale = opts.ExplicitLocale
		a.Status = StatusVerified
		a.Source = SourceExplicit
		a.Confidence = ConfHigh
		a.Inferred = false
		a.Reasons = append(a.Reasons,
			fmt.Sprintf("package locale %q established by explicit --wp-locale override (highest precedence)", opts.ExplicitLocale))
		if vf.Marker.State == MarkerPresent {
			a.Reasons = append(a.Reasons,
				fmt.Sprintf("package marker $wp_local_package = %q is present but overridden by --wp-locale", vf.Marker.Value))
		}
		a.noteRuntimeWPLANG(wpl)
		return a

	case vf.Marker.State == MarkerPresent:
		a.Locale = vf.Marker.Value
		a.Status = StatusVerified
		a.Source = SourcePackage
		a.Confidence = ConfHigh
		a.Inferred = false
		a.Reasons = append(a.Reasons,
			fmt.Sprintf("package locale %q established by $wp_local_package marker in wp-includes/version.php", vf.Marker.Value))
		for _, amb := range vf.Marker.Ambiguities {
			a.Reasons = append(a.Reasons, "advisory: "+amb)
		}
		a.noteRuntimeWPLANG(wpl)
		return a
	}

	// No authoritative locale source. The assessment is UNVERIFIED;
	// missing/ambiguous metadata never proves en_US.
	a.Status = StatusUnverified
	a.Locale = ""
	a.Source = SourceNone
	a.Confidence = ConfNone
	a.Inferred = false
	a.noteMarkerState(vf)
	a.noteRuntimeWPLANG(wpl)

	if opts.AllowEnUSFallback {
		a.Locale = "en_US"
		a.Source = SourceAssumed
		a.Confidence = ConfLow
		a.Inferred = true
		a.Reasons = append(a.Reasons,
			"en_US assumed for legacy checksum flow (AllowEnUSFallback); the package locale remains UNVERIFIED and results must be labeled provisional")
	}
	return a
}

func (a *LocaleAssessment) noteMarkerState(vf *VersionFile) {
	m := vf.Marker
	switch m.State {
	case MarkerAbsent:
		a.Reasons = append(a.Reasons,
			"$wp_local_package marker not found in wp-includes/version.php; missing metadata does not establish en_US")
	case MarkerEmpty:
		a.Reasons = append(a.Reasons,
			"$wp_local_package is explicitly empty or null; an empty marker is not a reliable locale signal")
	case MarkerDynamic:
		a.Reasons = append(a.Reasons,
			"$wp_local_package is not a static string literal; static analysis cannot establish the package locale")
	case MarkerInvalid:
		a.Reasons = append(a.Reasons,
			fmt.Sprintf("$wp_local_package value %q is not a well-formed WordPress locale", m.Value))
	case MarkerConflicting:
		a.Reasons = append(a.Reasons,
			"conflicting or mixed $wp_local_package definitions; package locale cannot be established")
	case MarkerPresent:
		a.Reasons = append(a.Reasons,
			fmt.Sprintf("reliable $wp_local_package marker %q is present", m.Value))
	}
	for _, amb := range m.Ambiguities {
		a.Reasons = append(a.Reasons, "advisory: "+amb)
	}
}

func (a *LocaleAssessment) noteRuntimeWPLANG(wpl WPLANGInfo) {
	if !wpl.Found {
		return
	}
	if wpl.Conflicting {
		a.Reasons = append(a.Reasons,
			"runtime WPLANG definitions conflict; runtime language unresolved (recorded separately, never used as package locale)")
		return
	}
	if !wpl.Static {
		a.Reasons = append(a.Reasons,
			"runtime WPLANG is defined with a non-static value; runtime language unresolved (recorded separately, never used as package locale)")
		return
	}
	a.Reasons = append(a.Reasons,
		fmt.Sprintf("runtime WPLANG %q (wp-config.php) recorded separately; it does not affect the package locale", wpl.Value))
}

// ChecksumDecision describes whether checksum verification may proceed and,
// if so, against which locale's checksum set.
type ChecksumDecision struct {
	// Proceed is false when verification must be skipped because no
	// reliable locale is available and the fallback is disabled.
	Proceed bool
	// Locale is the checksum-set locale to use ("" when refusing).
	Locale string
	// Provisional is true for the assumed en_US fallback: any checksum
	// verdict computed on it must be labeled provisional.
	Provisional bool
	// Basis explains where the locale came from.
	Basis string
	// Advisory carries the refusal/provisional notice for reports.
	Advisory string
}

// ChecksumGate decides whether checksum verification may use the assessment.
// It refuses to silently substitute en_US for an unverified package locale.
func ChecksumGate(a *LocaleAssessment, opts Options) *ChecksumDecision {
	d := &ChecksumDecision{}
	if a == nil {
		d.Advisory = "no locale assessment available; checksum verification refused"
		return d
	}
	if a.Status == StatusVerified {
		d.Proceed = true
		d.Locale = a.Locale
		d.Provisional = false
		switch a.Source {
		case SourceExplicit:
			d.Basis = "explicit --wp-locale override"
		case SourcePackage:
			d.Basis = "$wp_local_package package marker"
		default:
			d.Basis = "verified locale"
		}
		return d
	}
	if opts.AllowEnUSFallback && a.Source == SourceAssumed {
		d.Proceed = true
		d.Locale = a.Locale // "en_US"
		d.Provisional = true
		d.Basis = "assumed en_US fallback (package locale UNVERIFIED)"
		d.Advisory = "package locale is UNVERIFIED; en_US checksum set used by explicit fallback; any PASS/FAIL verdict must be reported as provisional"
		return d
	}
	d.Proceed = false
	d.Locale = ""
	d.Advisory = "package locale is UNVERIFIED; refusing to silently compare against the en_US checksum set"
	return d
}
