package wplocale

import (
	"os"
	"testing"
)

func mustFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

func TestParseUpstreamEnUS642(t *testing.T) {
	vf := ParseVersionPHP(mustFixture(t, "version_wp_6.4.2_enUS_upstream.php"))
	if !vf.HasWPVersion || vf.WPVersion != "6.4.2" {
		t.Fatalf("wp_version = %q (has=%v), want 6.4.2", vf.WPVersion, vf.HasWPVersion)
	}
	if !vf.HasWPDBVersion || vf.WPDBVersion != "56657" {
		t.Fatalf("wp_db_version = %q (has=%v), want 56657", vf.WPDBVersion, vf.HasWPDBVersion)
	}
	if vf.Marker.State != MarkerAbsent {
		t.Fatalf("marker state = %v, want absent (official en_US has no marker)", vf.Marker.State)
	}
}

func TestParseJAMarker(t *testing.T) {
	vf := ParseVersionPHP(mustFixture(t, "version_ja.php"))
	if vf.Marker.State != MarkerPresent || vf.Marker.Value != "ja" {
		t.Fatalf("marker = %v/%q, want present/ja", vf.Marker.State, vf.Marker.Value)
	}
}

func TestParseMissingMarker(t *testing.T) {
	vf := ParseVersionPHP(mustFixture(t, "version_missing_marker.php"))
	if vf.Marker.State != MarkerAbsent {
		t.Fatalf("marker state = %v, want absent", vf.Marker.State)
	}
}

func TestParseEmptyMarker(t *testing.T) {
	vf := ParseVersionPHP(mustFixture(t, "version_empty_marker.php"))
	if vf.Marker.State != MarkerEmpty {
		t.Fatalf("marker state = %v, want empty", vf.Marker.State)
	}
}

func TestParseCommentedMarker(t *testing.T) {
	vf := ParseVersionPHP(mustFixture(t, "version_commented_marker.php"))
	if vf.Marker.State != MarkerAbsent {
		t.Fatalf("marker state = %v, want absent (comments never establish values)", vf.Marker.State)
	}
	foundAdvisory := false
	for _, a := range vf.Marker.Ambiguities {
		if containsStr(a, "commented-out") {
			foundAdvisory = true
		}
	}
	if !foundAdvisory {
		t.Fatalf("expected commented-out advisory, got %v", vf.Marker.Ambiguities)
	}
}

func TestParseConflictingMarker(t *testing.T) {
	vf := ParseVersionPHP(mustFixture(t, "version_conflicting.php"))
	if vf.Marker.State != MarkerConflicting {
		t.Fatalf("marker state = %v, want conflicting", vf.Marker.State)
	}
	if vf.Marker.Occurrences != 2 {
		t.Fatalf("occurrences = %d, want 2", vf.Marker.Occurrences)
	}
}

func TestParseDynamicMarker(t *testing.T) {
	vf := ParseVersionPHP(mustFixture(t, "version_dynamic.php"))
	if vf.Marker.State != MarkerDynamic {
		t.Fatalf("marker state = %v, want dynamic", vf.Marker.State)
	}
}

func TestParseMalformedMarker(t *testing.T) {
	vf := ParseVersionPHP(mustFixture(t, "version_malformed.php"))
	if vf.Marker.State != MarkerInvalid || vf.Marker.Value != "JA!!!" {
		t.Fatalf("marker = %v/%q, want invalid/JA!!!", vf.Marker.State, vf.Marker.Value)
	}
}

func TestParseMarkerOnlyInStrings(t *testing.T) {
	vf := ParseVersionPHP(mustFixture(t, "version_marker_in_string.php"))
	if vf.Marker.State != MarkerAbsent {
		t.Fatalf("marker state = %v, want absent; string contents must never be assignments", vf.Marker.State)
	}
	if len(vf.Marker.Ambiguities) != 0 {
		t.Fatalf("unexpected advisories: %v", vf.Marker.Ambiguities)
	}
}

func TestParseMarkerOnlyInHeredocNowdoc(t *testing.T) {
	vf := ParseVersionPHP(mustFixture(t, "version_heredoc_marker.php"))
	if vf.Marker.State != MarkerAbsent {
		t.Fatalf("marker state = %v, want absent; heredoc/nowdoc bodies must never be assignments", vf.Marker.State)
	}
}

func TestMarkerStatesSynthetic(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want MarkerState
	}{
		{"null", `<?php $wp_local_package = null;`, MarkerEmpty},
		{"en_us", `<?php $wp_local_package = 'en_US';`, MarkerPresent},
		{"upper", `<?php $wp_local_package = 'JA';`, MarkerInvalid},
		{"single letter", `<?php $wp_local_package = 'j';`, MarkerInvalid},
		{"space", `<?php $wp_local_package = 'ja jp';`, MarkerInvalid},
		{"concat", `<?php $wp_local_package = 'de' . '_DE';`, MarkerPresent},
		{"interpolated", `<?php $wp_local_package = "v$pkg";`, MarkerDynamic},
		{"backtick", `<?php $wp_local_package = ` + "`ja`" + `;`, MarkerDynamic},
		{"comparison not assignment", `<?php $x = ($wp_local_package == 'ja');`, MarkerAbsent},
		{"duplicate identical", "<?php $wp_local_package = 'ja'; $wp_local_package = 'ja';", MarkerPresent},
		{"compound", `<?php $wp_local_package .= 'ja';`, MarkerDynamic},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vf := ParseVersionPHP([]byte(tc.src))
			if vf.Marker.State != tc.want {
				t.Fatalf("state = %v (amb: %v), want %v", vf.Marker.State, vf.Marker.Ambiguities, tc.want)
			}
		})
	}
}

func TestValidWPLocale(t *testing.T) {
	valid := []string{"ja", "en_US", "de_DE", "pt_BR", "zh_CN", "de_DE_informal", "en_GB", "ary"}
	invalid := []string{"", "j", "JA", "japanese", "ja jp", "ja!", "a_b_c_d_e_f_g_h_i_j_k_l_m_n_o_p_q_r_s"}
	for _, s := range valid {
		if !validWPLocale(s) {
			t.Errorf("%q should be valid", s)
		}
	}
	for _, s := range invalid {
		if validWPLocale(s) {
			t.Errorf("%q should be invalid", s)
		}
	}
}

func containsStr(hay, needle string) bool {
	return len(needle) > 0 && len(hay) >= len(needle) && indexOf(hay, needle) >= 0
}

func indexOf(hay, needle string) int {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
