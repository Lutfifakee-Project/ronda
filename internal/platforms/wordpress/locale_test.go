package wordpress

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func versionPHPWithPackage(v, pkg string) string {
	s := "<?php" + nlB + dollar() + "wp_version = '" + v + "';" + nlB
	if pkg != "" {
		s += dollar() + "wp_local_package = '" + pkg + "';" + nlB
	}
	return s
}

func makeLocaleInstall(t *testing.T, v, pkg, wplang string) string {
	t.Helper()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "wp-includes", "version.php"), versionPHPWithPackage(v, pkg))
	writeFile(t, filepath.Join(root, "wp-load.php"), "<?php // load"+nlB)
	if wplang != "" {
		cfg := "<?php" + nlB + "define('WPLANG', '" + wplang + "');" + nlB
		writeFile(t, filepath.Join(root, "wp-config.php"), cfg)
	}
	return root
}

// makeRawInstall builds an install from a raw version.php source and a raw
// wp-config.php source (either may be empty).
func makeRawInstall(t *testing.T, versionSrc, wpConfigSrc string) string {
	t.Helper()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "wp-includes", "version.php"), versionSrc)
	writeFile(t, filepath.Join(root, "wp-load.php"), "<?php // load"+nlB)
	if wpConfigSrc != "" {
		writeFile(t, filepath.Join(root, "wp-config.php"), wpConfigSrc)
	}
	return root
}

// wplangConfig builds a wp-config.php body with the given WPLANG values.
func wplangConfig(values ...string) string {
	s := "<?php" + nlB
	for i := 0; i < len(values); i++ {
		s += "define('WPLANG', '" + values[i] + "');" + nlB
	}
	return s
}

// assertRefused asserts that a marker-based resolution was refused: no locale
// is carried, the resolution is not established, and the confidence is low.
func assertRefused(t *testing.T, loc localeResolution, wantSource string) {
	t.Helper()
	if loc.Established {
		t.Fatalf("locale must not be established: %+v", loc)
	}
	if loc.Locale != "" {
		t.Fatalf("refused resolution must not carry a locale, got %q", loc.Locale)
	}
	if loc.Source != wantSource {
		t.Fatalf("source=%q, want %q", loc.Source, wantSource)
	}
	if loc.Confidence != ConfidenceLow {
		t.Fatalf("confidence=%q, want %q", loc.Confidence, ConfidenceLow)
	}
}

func readTestdata(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestDetectLocalPackage(t *testing.T) {
	root := makeLocaleInstall(t, "6.4.2", "id_ID", "")
	if got := DetectLocalPackage(root); got != "id_ID" {
		t.Fatalf("wp_local_package=%q", got)
	}
	root2 := makeLocaleInstall(t, "6.4.2", "", "")
	if got := DetectLocalPackage(root2); got != "" {
		t.Fatalf("expected empty marker, got %q", got)
	}
}

func TestDetectRuntimeLanguage(t *testing.T) {
	root := makeLocaleInstall(t, "6.4.2", "", "fr_FR")
	if got := DetectRuntimeLanguage(root); got != "fr_FR" {
		t.Fatalf("WPLANG=%q", got)
	}
}

func TestValidLocale(t *testing.T) {
	good := []string{"en_US", "id_ID", "pt_BR", "de_DE_formal", "ja"}
	for i := 0; i < len(good); i++ {
		if !validLocale(good[i]) {
			t.Errorf("valid locale rejected: %q", good[i])
		}
	}
	bad := []string{"", "a", "en-US", "en US", "../../etc", "en_US_x_y"}
	for i := 0; i < len(bad); i++ {
		if validLocale(bad[i]) {
			t.Errorf("invalid locale accepted: %q", bad[i])
		}
	}
}

func TestResolveLocaleOverrideWins(t *testing.T) {
	root := makeLocaleInstall(t, "6.4.2", "id_ID", "fr_FR")
	loc := resolveLocale(root, "de_DE")
	if loc.Locale != "de_DE" || loc.Source != "override" || !loc.Established {
		t.Fatalf("override not honored: %+v", loc)
	}
	if loc.Confidence != ConfidenceHigh {
		t.Fatalf("override confidence=%q", loc.Confidence)
	}
	if loc.RuntimeLanguage != "fr_FR" {
		t.Fatalf("runtime language not recorded: %+v", loc)
	}
}

func TestResolveLocaleFromPackage(t *testing.T) {
	root := makeLocaleInstall(t, "6.4.2", "id_ID", "fr_FR")
	loc := resolveLocale(root, "")
	if loc.Locale != "id_ID" || loc.Source != "wp_local_package" || !loc.Established {
		t.Fatalf("package locale not used: %+v", loc)
	}
	if loc.RuntimeLanguage != "fr_FR" {
		t.Fatalf("runtime language not recorded separately: %+v", loc)
	}
}

// TestResolveLocaleMissingMarkerIsNotEnUS pins the corrected contract: a
// missing $wp_local_package marker never silently resolves to en_US. The
// base en_US package omits the marker, but so does a localized package whose
// metadata was lost, so absence establishes nothing.
func TestResolveLocaleMissingMarkerIsNotEnUS(t *testing.T) {
	root := makeLocaleInstall(t, "6.4.2", "", "")
	loc := resolveLocale(root, "")
	assertRefused(t, loc, "missing_marker")
	if loc.Locale == baseLocale {
		t.Fatal("missing marker must not resolve to en_US")
	}
	if loc.Detail == "" {
		t.Fatal("expected a refusal detail")
	}
}

// TestVerifyRefusesUnverifiedLocale rewrites the stale inferred-locale flow
// test: with no marker and no override the verification must refuse instead
// of silently comparing against en_US checksums, and an explicit override
// must restore the checksum flow.
func TestVerifyRefusesUnverifiedLocale(t *testing.T) {
	loadContent := "<?php // load" + nlB
	root := makeLocaleInstall(t, "6.0", "", "")
	manifest := map[string]string{
		"wp-load.php":             md5hex(loadContent),
		"wp-includes/version.php": md5hex(versionPHP("6.0")),
	}
	srv := manifestServer(t, "6.0", manifest, nil)
	defer srv.Close()

	res := verifyWithBase(context.Background(), root, "", srv.URL)
	if res.Verified {
		t.Fatal("missing marker must not silently verify against en_US checksums")
	}
	if res.Locale != "" {
		t.Fatalf("locale=%q, want empty", res.Locale)
	}
	if res.LocaleSource != "missing_marker" {
		t.Fatalf("locale source=%q", res.LocaleSource)
	}
	if res.Reason == "" {
		t.Fatal("expected a refusal reason")
	}

	res2 := verifyWithBase(context.Background(), root, "en_US", srv.URL)
	if !res2.Verified {
		t.Fatalf("explicit override should re-enable verification: %s", res2.Reason)
	}
	if res2.CleanCount != 2 {
		t.Fatalf("clean=%d, want 2", res2.CleanCount)
	}
}

func TestResolveLocaleInvalidOverride(t *testing.T) {
	root := makeLocaleInstall(t, "6.4.2", "", "")
	loc := resolveLocale(root, "../../evil")
	if loc.Established {
		t.Fatalf("invalid override should not be established: %+v", loc)
	}
	if loc.Source != "override" || loc.Confidence != ConfidenceLow {
		t.Fatalf("invalid override metadata: %+v", loc)
	}
}

func TestResolveLocaleEmptyMarker(t *testing.T) {
	src := "<?php" + nlB + dollar() + "wp_version = '6.4.2';" + nlB +
		dollar() + "wp_local_package = '';" + nlB
	root := makeRawInstall(t, src, "")
	assertRefused(t, resolveLocale(root, ""), "wp_local_package")
	if got := DetectLocalPackage(root); got != "" {
		t.Fatalf("empty marker leaked: %q", got)
	}
}

func TestResolveLocaleMalformedMarker(t *testing.T) {
	src := "<?php" + nlB + dollar() + "wp_version = '6.4.2';" + nlB +
		dollar() + "wp_local_package = 'not a locale!';" + nlB
	root := makeRawInstall(t, src, "")
	assertRefused(t, resolveLocale(root, ""), "wp_local_package")
}

func TestResolveLocaleDynamicMarker(t *testing.T) {
	src := "<?php" + nlB + dollar() + "wp_version = '6.4.2';" + nlB +
		dollar() + "lang = 'ja';" + nlB +
		dollar() + "wp_local_package = " + dollar() + "lang;" + nlB
	root := makeRawInstall(t, src, "")
	assertRefused(t, resolveLocale(root, ""), "wp_local_package")
}

func TestResolveLocaleConflictingMarkers(t *testing.T) {
	src := "<?php" + nlB + dollar() + "wp_version = '6.4.2';" + nlB +
		dollar() + "wp_local_package = 'ja';" + nlB +
		dollar() + "wp_local_package = 'id_ID';" + nlB
	root := makeRawInstall(t, src, "")
	assertRefused(t, resolveLocale(root, ""), "wp_local_package")
}

// TestCommentedOutMarkerIgnored covers commented-out assignments: a marker
// that appears only behind a line comment must never establish a locale.
func TestCommentedOutMarkerIgnored(t *testing.T) {
	cases := map[string]string{
		"slash_slash": "// " + dollar() + "wp_local_package = 'ja';",
		"hash":        "# " + dollar() + "wp_local_package = 'ja';",
	}
	for name, line := range cases {
		t.Run(name, func(t *testing.T) {
			src := "<?php" + nlB + dollar() + "wp_version = '6.4.2';" + nlB + line + nlB
			root := makeRawInstall(t, src, "")
			if got := DetectLocalPackage(root); got != "" {
				t.Fatalf("commented marker leaked: %q", got)
			}
			assertRefused(t, resolveLocale(root, ""), "missing_marker")
		})
	}
}

// TestMarkerInsideBlockCommentIgnored covers block comments, including the
// docblock shape used by the upstream version.php header.
func TestMarkerInsideBlockCommentIgnored(t *testing.T) {
	src := "<?php" + nlB +
		"/* " + dollar() + "wp_local_package = 'ja'; */" + nlB +
		"/**" + nlB +
		" * @global string " + dollar() + "wp_local_package" + nlB +
		" */" + nlB +
		dollar() + "wp_version = '6.4.2';" + nlB
	root := makeRawInstall(t, src, "")
	if got := DetectLocalPackage(root); got != "" {
		t.Fatalf("block-comment marker leaked: %q", got)
	}
	assertRefused(t, resolveLocale(root, ""), "missing_marker")
}

// TestMarkerInsideStringOrHeredocIgnored proves the masked scanning: marker
// text inside string literals or heredoc bodies can never establish a locale.
func TestMarkerInsideStringOrHeredocIgnored(t *testing.T) {
	cases := map[string]string{
		"single_quoted": dollar() + "note = 'wp_local_package = ja inside a string';",
		"double_quoted": dollar() + "note = \"wp_local_package = ja inside a string\";",
		"heredoc": dollar() + "doc = <<<EOT" + nlB +
			dollar() + "wp_local_package = 'ja';" + nlB +
			"EOT;",
	}
	for name, line := range cases {
		t.Run(name, func(t *testing.T) {
			src := "<?php" + nlB + dollar() + "wp_version = '6.4.2';" + nlB + line + nlB
			root := makeRawInstall(t, src, "")
			if got := DetectLocalPackage(root); got != "" {
				t.Fatalf("string/heredoc marker leaked: %q", got)
			}
			assertRefused(t, resolveLocale(root, ""), "missing_marker")
		})
	}
}

// TestMarkerWhitespaceAndSyntaxVariants covers supported assignment syntax:
// spacing, quoting, multi-line assignments, static concatenation and
// trailing comments.
func TestMarkerWhitespaceAndSyntaxVariants(t *testing.T) {
	cases := []struct {
		name   string
		assign string
		want   string
	}{
		{"tight", dollar() + "wp_local_package='ja';", "ja"},
		{"double_quotes", dollar() + "wp_local_package = \"ja\";", "ja"},
		{"tabs", dollar() + "wp_local_package\t=\t'ja';", "ja"},
		{"multiline", dollar() + "wp_local_package =" + nlB + "\t'ja';", "ja"},
		{"concat", dollar() + "wp_local_package = 'id' . '_' . 'ID';", "id_ID"},
		{"trailing_comment", dollar() + "wp_local_package = 'ja'; // active package", "ja"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := "<?php" + nlB + dollar() + "wp_version = '6.4.2';" + nlB + tc.assign + nlB
			root := makeRawInstall(t, src, "")
			loc := resolveLocale(root, "")
			if !loc.Established || loc.Locale != tc.want || loc.Source != "wp_local_package" {
				t.Fatalf("assignment syntax not supported: %+v", loc)
			}
			if loc.Confidence != ConfidenceHigh {
				t.Fatalf("confidence=%q", loc.Confidence)
			}
		})
	}
}

// TestOfficialEnUSPackageUpstreamFixture uses the real upstream en_US 6.4.2
// version.php, which contains no code-level wp_local_package assignment (the
// marker appears only inside docblock comments). The package locale stays
// UNVERIFIED: the official en_US package is not special-cased.
func TestOfficialEnUSPackageUpstreamFixture(t *testing.T) {
	root := makeRawInstall(t, readTestdata(t, "version_wp_6.4.2_enUS_upstream.php"), "")
	if v := DetectVersion(root); v != "6.4.2" {
		t.Fatalf("version=%q, want 6.4.2", v)
	}
	if got := DetectLocalPackage(root); got != "" {
		t.Fatalf("upstream en_US fixture leaked a marker: %q", got)
	}
	loc := resolveLocale(root, "")
	assertRefused(t, loc, "missing_marker")
	if loc.Locale == baseLocale {
		t.Fatal("official en_US package must not be inferred from the missing marker")
	}
}

// TestJapanesePackageFixture uses the localized 6.4.2 fixture: the marker
// establishes the package locale with high confidence.
func TestJapanesePackageFixture(t *testing.T) {
	root := makeRawInstall(t, readTestdata(t, "version_ja.php"), "")
	if got := DetectLocalPackage(root); got != "ja" {
		t.Fatalf("wp_local_package=%q, want ja", got)
	}
	loc := resolveLocale(root, "")
	if !loc.Established || loc.Locale != "ja" || loc.Source != "wp_local_package" {
		t.Fatalf("ja package locale not established: %+v", loc)
	}
	if loc.Confidence != ConfidenceHigh {
		t.Fatalf("confidence=%q", loc.Confidence)
	}
}

// TestConflictingWPLANGRecordedSeparately pins the runtime/package split:
// the package marker selects the checksums, WPLANG is reported separately,
// and conflicting or lone WPLANG values never establish a package locale.
func TestConflictingWPLANGRecordedSeparately(t *testing.T) {
	src := "<?php" + nlB + dollar() + "wp_version = '6.4.2';" + nlB +
		dollar() + "wp_local_package = 'id_ID';" + nlB
	root := makeRawInstall(t, src, wplangConfig("fr_FR", "de_DE"))
	loc := resolveLocale(root, "")
	if !loc.Established || loc.Locale != "id_ID" {
		t.Fatalf("package marker must win over WPLANG: %+v", loc)
	}
	if loc.RuntimeLanguage != "fr_FR" {
		t.Fatalf("runtime language=%q, want the first WPLANG value", loc.RuntimeLanguage)
	}

	srcNoMarker := "<?php" + nlB + dollar() + "wp_version = '6.4.2';" + nlB
	root2 := makeRawInstall(t, srcNoMarker, wplangConfig("fr_FR", "de_DE"))
	assertRefused(t, resolveLocale(root2, ""), "missing_marker")
}

// TestEstablishedLocaleReportsSensitiveDiffAsModified documents the corrected
// downgrade semantics: locale-sensitive diffs are downgraded to UNVERIFIED
// only while the locale is unestablished. Once the marker establishes the
// locale, a differing locale-sensitive file is a plain MODIFIED finding.
func TestEstablishedLocaleReportsSensitiveDiffAsModified(t *testing.T) {
	root := makeLocaleInstall(t, "6.0", "id_ID", "")
	manifest := map[string]string{
		"wp-includes/version.php": md5hex("official id_ID build of version.php"),
		"wp-load.php":             md5hex("<?php // load" + nlB),
	}
	srv := manifestServer(t, "6.0", manifest, nil)
	defer srv.Close()

	res := verifyWithBase(context.Background(), root, "", srv.URL)
	if !res.Verified {
		t.Fatalf("not verified: %s", res.Reason)
	}
	if res.LocaleInferred {
		t.Fatal("marker-established locale must not be flagged inferred")
	}
	found := false
	for i := 0; i < len(res.ModifiedFiles); i++ {
		if res.ModifiedFiles[i].Path == "wp-includes/version.php" {
			found = true
		}
	}
	if !found {
		t.Fatalf("established locale must report the diff as MODIFIED: %+v", res.ModifiedFiles)
	}
	if res.UnverifiedCount != 0 {
		t.Fatalf("unverified=%d, want 0", res.UnverifiedCount)
	}
}

func TestReadOnlyPreservation(t *testing.T) {
	root := makeLocaleInstall(t, "6.0", "id_ID", "")
	before, err := os.Stat(filepath.Join(root, "wp-includes", "version.php"))
	if err != nil {
		t.Fatal(err)
	}
	manifest := map[string]string{"wp-load.php": md5hex("x")}
	srv := manifestServer(t, "6.0", manifest, nil)
	defer srv.Close()
	verifyWithBase(context.Background(), root, "", srv.URL)
	after, err := os.Stat(filepath.Join(root, "wp-includes", "version.php"))
	if err != nil {
		t.Fatal(err)
	}
	if before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("scanned file was modified")
	}
}
