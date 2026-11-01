package wplocale

import "testing"

var emptyWPLANG = WPLANGInfo{}

func jaAssessment(t *testing.T) (*VersionFile, *LocaleAssessment) {
	t.Helper()
	vf := ParseVersionPHP(mustFixture(t, "version_ja.php"))
	a := Assess(vf, emptyWPLANG, Options{})
	return vf, a
}

// --- Required scenario: known official en_US base package -----------------

func TestKnownEnUSPackageMarker(t *testing.T) {
	vf := ParseVersionPHP([]byte(`<?php $wp_version = '6.4.2'; $wp_local_package = 'en_US';`))
	a := Assess(vf, emptyWPLANG, Options{})
	if a.Status != StatusVerified || a.Locale != "en_US" || a.Source != SourcePackage ||
		a.Confidence != ConfHigh || a.Inferred {
		t.Fatalf("got %+v, want verified en_US package high", a)
	}
}

func TestOfficialEnUSUpstreamHasNoMarkerSoUnverified(t *testing.T) {
	vf := ParseVersionPHP(mustFixture(t, "version_wp_6.4.2_enUS_upstream.php"))
	a := Assess(vf, emptyWPLANG, Options{})
	if a.Status != StatusUnverified {
		t.Fatalf("official en_US upstream (no marker) must be UNVERIFIED without explicit fallback, got %+v", a)
	}
	if a.Locale != "" || a.Inferred {
		t.Fatalf("must not silently report en_US: %+v", a)
	}
	for _, r := range a.Reasons {
		if containsStr(r, "missing metadata does not establish en_US") {
			return
		}
	}
	t.Fatalf("missing explanation for missing marker: %v", a.Reasons)
}

// --- Required scenario: non-English localized package ---------------------

func TestLocalizedPackageJA(t *testing.T) {
	_, a := jaAssessment(t)
	if a.Status != StatusVerified || a.Locale != "ja" || a.Confidence != ConfHigh ||
		a.Source != SourcePackage || a.Inferred {
		t.Fatalf("got %+v, want verified ja package high", a)
	}
}

// --- Required scenario: missing package locale marker ---------------------

func TestMissingMarkerIsUnverifiedNotEnUS(t *testing.T) {
	vf := ParseVersionPHP(mustFixture(t, "version_missing_marker.php"))
	a := Assess(vf, emptyWPLANG, Options{})
	if a.Status != StatusUnverified || a.Locale != "" || a.Source != SourceNone ||
		a.Confidence != ConfNone || a.Inferred {
		t.Fatalf("missing marker must be UNVERIFIED/empty/none, got %+v", a)
	}
}

func TestMissingMarkerWithOptInFallback(t *testing.T) {
	vf := ParseVersionPHP(mustFixture(t, "version_missing_marker.php"))
	a := Assess(vf, emptyWPLANG, Options{AllowEnUSFallback: true})
	if a.Status != StatusUnverified {
		t.Fatalf("fallback must keep Status UNVERIFIED, got %+v", a)
	}
	if a.Locale != "en_US" || a.Source != SourceAssumed || a.Confidence != ConfLow || !a.Inferred {
		t.Fatalf("fallback shape wrong: %+v", a)
	}
}

// --- Required scenario: conflicting WPLANG --------------------------------

func TestRuntimeWPLANGNeverOverridesPackageMarker(t *testing.T) {
	vf := ParseVersionPHP(mustFixture(t, "version_ja.php"))
	wpl := ExtractWPLANG(mustFixture(t, "wpconfig_wplang_de.php"))
	a := Assess(vf, wpl, Options{})
	if a.Status != StatusVerified || a.Locale != "ja" {
		t.Fatalf("package marker must beat runtime WPLANG: %+v", a)
	}
	if a.RuntimeWPLANG != "de_DE" || !a.RuntimeWPLANGFound {
		t.Fatalf("runtime WPLANG must be recorded separately: %+v", a)
	}
	noted := false
	for _, r := range a.Reasons {
		if containsStr(r, "recorded separately") {
			noted = true
		}
	}
	if !noted {
		t.Fatalf("expected separation note, got %v", a.Reasons)
	}
}

func TestWPLANGAloneDoesNotEstablishPackageLocale(t *testing.T) {
	vf := ParseVersionPHP(mustFixture(t, "version_missing_marker.php"))
	wpl := ExtractWPLANG(mustFixture(t, "wpconfig_wplang_de.php"))
	a := Assess(vf, wpl, Options{})
	if a.Status != StatusUnverified || a.Locale != "" {
		t.Fatalf("runtime WPLANG must never prove the package locale: %+v", a)
	}
	if a.RuntimeWPLANG != "de_DE" {
		t.Fatalf("runtime WPLANG should still be reported: %+v", a)
	}
}

func TestConflictingRuntimeWPLANG(t *testing.T) {
	vf := ParseVersionPHP(mustFixture(t, "version_ja.php"))
	wpl := ExtractWPLANG(mustFixture(t, "wpconfig_wplang_conflicting.php"))
	a := Assess(vf, wpl, Options{})
	if a.Status != StatusVerified || a.Locale != "ja" {
		t.Fatalf("conflicting runtime WPLANG must not affect verified package marker: %+v", a)
	}
	noted := false
	for _, r := range a.Reasons {
		if containsStr(r, "runtime WPLANG definitions conflict") {
			noted = true
		}
	}
	if !noted {
		t.Fatalf("expected conflict note for runtime WPLANG: %v", a.Reasons)
	}
}

// --- Required scenario: explicit locale override ---------------------------

func TestExplicitOverrideBeatsMarkerAndWPLANG(t *testing.T) {
	vf := ParseVersionPHP(mustFixture(t, "version_ja.php"))
	wpl := ExtractWPLANG(mustFixture(t, "wpconfig_wplang_de.php"))
	a := Assess(vf, wpl, Options{ExplicitLocale: "fr_FR"})
	if a.Status != StatusVerified || a.Locale != "fr_FR" || a.Source != SourceExplicit ||
		a.Confidence != ConfHigh || a.Inferred {
		t.Fatalf("explicit override must win: %+v", a)
	}
	noted := false
	for _, r := range a.Reasons {
		if containsStr(r, "overridden by --wp-locale") {
			noted = true
		}
	}
	if !noted {
		t.Fatalf("expected override transparency note: %v", a.Reasons)
	}
}

func TestExplicitOverrideWorksWithMissingMarker(t *testing.T) {
	vf := ParseVersionPHP(mustFixture(t, "version_missing_marker.php"))
	a := Assess(vf, emptyWPLANG, Options{ExplicitLocale: "ja"})
	if a.Status != StatusVerified || a.Locale != "ja" || a.Source != SourceExplicit {
		t.Fatalf("explicit override on missing marker must verify: %+v", a)
	}
}

func TestInvalidExplicitOverrideIsRefused(t *testing.T) {
	vf := ParseVersionPHP(mustFixture(t, "version_ja.php"))
	a := Assess(vf, emptyWPLANG, Options{ExplicitLocale: "NOT A LOCALE"})
	if a.Status != StatusUnverified || a.Locale != "" {
		t.Fatalf("invalid explicit override must not verify: %+v", a)
	}
	noted := false
	for _, r := range a.Reasons {
		if containsStr(r, "refusing to apply") {
			noted = true
		}
	}
	if !noted {
		t.Fatalf("expected refusal note: %v", a.Reasons)
	}
}

// --- Required scenario: ambiguous locale metadata --------------------------

func TestAmbiguousMarkersAreUnverified(t *testing.T) {
	cases := []struct {
		name  string
		fixt  string
		synth string
	}{
		{"empty marker", "version_empty_marker.php", ""},
		{"dynamic marker", "version_dynamic.php", ""},
		{"conflicting marker", "version_conflicting.php", ""},
		{"malformed marker", "version_malformed.php", ""},
		{"null marker", "", `<?php $wp_local_package = null;`},
		{"interpolated marker", "", `<?php $pkg='x'; $wp_local_package = "v$pkg";`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var vf *VersionFile
			if tc.fixt != "" {
				vf = ParseVersionPHP(mustFixture(t, tc.fixt))
			} else {
				vf = ParseVersionPHP([]byte(tc.synth))
			}
			a := Assess(vf, emptyWPLANG, Options{})
			if a.Status != StatusUnverified || a.Locale != "" {
				t.Fatalf("ambiguous metadata must be UNVERIFIED: %+v", a)
			}
			// And the opt-in fallback must not be triggered for anything
			// other than a genuinely missing/empty marker state.
			a2 := Assess(vf, emptyWPLANG, Options{AllowEnUSFallback: true})
			if a2.Status != StatusUnverified || a2.Locale != "en_US" || !a2.Inferred ||
				a2.Confidence != ConfLow {
				t.Fatalf("fallback shape wrong: %+v", a2)
			}
		})
	}
}

// --- Checksum gate ----------------------------------------------------------

func TestChecksumGateVerified(t *testing.T) {
	_, a := jaAssessment(t)
	d := ChecksumGate(a, Options{})
	if !d.Proceed || d.Locale != "ja" || d.Provisional || d.Basis != "$wp_local_package package marker" {
		t.Fatalf("gate = %+v, want proceed ja non-provisional", d)
	}
}

func TestChecksumGateRefusesSilentEnUS(t *testing.T) {
	vf := ParseVersionPHP(mustFixture(t, "version_missing_marker.php"))
	a := Assess(vf, emptyWPLANG, Options{})
	d := ChecksumGate(a, Options{})
	if d.Proceed || d.Locale != "" {
		t.Fatalf("gate must refuse to silently use en_US: %+v", d)
	}
	if d.Advisory == "" {
		t.Fatalf("refusal must carry an advisory for reports")
	}
}

func TestChecksumGateProvisionalFallback(t *testing.T) {
	vf := ParseVersionPHP(mustFixture(t, "version_missing_marker.php"))
	a := Assess(vf, emptyWPLANG, Options{AllowEnUSFallback: true})
	d := ChecksumGate(a, Options{AllowEnUSFallback: true})
	if !d.Proceed || d.Locale != "en_US" || !d.Provisional {
		t.Fatalf("gate = %+v, want provisional en_US", d)
	}
	if d.Advisory == "" || !containsStr(d.Advisory, "provisional") {
		t.Fatalf("provisional advisory missing: %q", d.Advisory)
	}
}

// --- Full pipeline over fixture files ---------------------------------------

func TestFullPipeline(t *testing.T) {
	cases := []struct {
		name       string
		versionPHP string
		wpConfig   string
		opts       Options
		wantStatus Status
		wantLocale string
		wantGate   bool
	}{
		{
			name:       "official en_US upstream: unverified, no checksums",
			versionPHP: "version_wp_6.4.2_enUS_upstream.php",
			wantStatus: StatusUnverified,
			wantLocale: "",
			wantGate:   false,
		},
		{
			name:       "official en_US upstream with fallback: provisional en_US",
			versionPHP: "version_wp_6.4.2_enUS_upstream.php",
			opts:       Options{AllowEnUSFallback: true},
			wantStatus: StatusUnverified,
			wantLocale: "en_US",
			wantGate:   true,
		},
		{
			name:       "ja localized dist: verified, checksums proceed",
			versionPHP: "version_ja.php",
			wpConfig:   "wpconfig_wplang_de.php",
			wantStatus: StatusVerified,
			wantLocale: "ja",
			wantGate:   true,
		},
		{
			name:       "missing marker + explicit override: verified",
			versionPHP: "version_missing_marker.php",
			opts:       Options{ExplicitLocale: "de_DE"},
			wantStatus: StatusVerified,
			wantLocale: "de_DE",
			wantGate:   true,
		},
		{
			name:       "conflicting marker: unverified, checksums refused",
			versionPHP: "version_conflicting.php",
			wantStatus: StatusUnverified,
			wantLocale: "",
			wantGate:   false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var ver, cfg []byte
			if tc.versionPHP != "" {
				ver = mustFixture(t, tc.versionPHP)
			}
			if tc.wpConfig != "" {
				cfg = mustFixture(t, tc.wpConfig)
			}
			a, gate, _, _ := Analyze(ver, cfg, tc.opts)
			if a.Status != tc.wantStatus || a.Locale != tc.wantLocale {
				t.Fatalf("assessment = %s/%q (reasons %v), want %s/%q",
					a.Status, a.Locale, a.Reasons, tc.wantStatus, tc.wantLocale)
			}
			if gate.Proceed != tc.wantGate {
				t.Fatalf("gate proceed = %v (%s), want %v", gate.Proceed, gate.Basis, tc.wantGate)
			}
		})
	}
}
