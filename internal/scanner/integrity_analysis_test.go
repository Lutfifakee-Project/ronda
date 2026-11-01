package scanner

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Lutfifakee-Project/ronda/internal/platforms/refcheck"
)

// Integrity and threat analysis are independent security perspectives. These
// tests prove it end to end through the real Scan pipeline: a file that is
// checksum-CLEAN against a reference is still run through the PHP threat
// analyzer, a MODIFIED file is never automatically malicious, and integrity
// findings and PHP findings coexist without duplicates. All fixtures are
// deterministic: WordPress checksums come from a local fake API, Drupal and
// Joomla references from a seeded in-memory manifest store. No fixture PHP is
// ever executed; RONDA only reads bytes.

func md5hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// fakeChecksumAPI serves the WordPress checksum response shape for one
// version: {"checksums": {"6.4.2": {"<path>": "<md5>"}}}.
func fakeChecksumAPI(t *testing.T, checksums map[string]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body, err := json.Marshal(map[string]interface{}{
			"checksums": map[string]interface{}{"6.4.2": checksums},
		})
		if err != nil {
			t.Errorf("marshal: %v", err)
			return
		}
		if _, err := w.Write(body); err != nil {
			t.Errorf("write: %v", err)
		}
	}))
}

func writeWPVersion(t *testing.T, site string) {
	t.Helper()
	// Discovery needs the full WordPress marker set; the version file pins
	// the exact version the fake checksum API answers for.
	buildWordPressInstall(t, site)
	mustWrite(t, filepath.Join(site, "wp-includes", "version.php"),
		"<?php\n$"+"wp_version = '6.4.2';\n")
}

var cleanSuspicious = fxSystemGet // suspicious code that a reference may still checksum-CLEAN

func phpFindingAt(t *testing.T, res Result, path string) bool {
	t.Helper()
	for i := 0; i < len(res.Findings); i++ {
		f := res.Findings[i]
		if f.Platform == "php" && f.Path == path {
			return true
		}
	}
	return false
}

func hasIntegrityFinding(res Result) bool {
	for i := 0; i < len(res.Findings); i++ {
		if res.Findings[i].Platform == "wordpress" {
			return true
		}
	}
	return false
}

// TestChecksumCleanCoreFileStillAnalyzed is the core proof for correction #1:
// a wp-includes file whose MD5 matches the official checksum manifest is
// CLEAN, and the PHP threat analyzer still runs over it and reports the
// backdoor inside it. CLEAN is an integrity statement, never an analysis
// exemption.
func TestChecksumCleanCoreFileStillAnalyzed(t *testing.T) {
	target := t.TempDir()
	site := filepath.Join(target, "site")
	writeWPVersion(t, site)

	sneaky := filepath.Join(site, "wp-includes", "sneaky.php")
	mustWrite(t, sneaky, cleanSuspicious)

	srv := fakeChecksumAPI(t, map[string]string{
		"wp-includes/version.php": md5hex("<?php\n$" + "wp_version = '6.4.2';\n"),
		"wp-includes/sneaky.php":  md5hex(cleanSuspicious),
	})
	defer srv.Close()

	res, err := Scan(context.Background(), Options{
		Target:         target,
		Platforms:      []string{"wordpress"},
		WPLocale:       "en_US",
		WPChecksumBase: srv.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.WordPress) != 1 || !res.WordPress[0].Verified {
		t.Fatalf("wordpress verify failed: %+v", res.WordPress)
	}
	if res.WordPress[0].CleanCount < 2 || len(res.WordPress[0].ModifiedFiles) != 0 {
		t.Fatalf("expected checksum-CLEAN files, got clean=%d modified=%d",
			res.WordPress[0].CleanCount, len(res.WordPress[0].ModifiedFiles))
	}
	if !phpFindingAt(t, res, sneaky) {
		t.Fatalf("CLEAN file must still be analyzed; findings: %+v", res.Findings)
	}
	assertNoDuplicateFindings(t, res)
}

// TestChecksumModifiedCoreFileStillAnalyzed: a checksum mismatch marks the
// file MODIFIED, and the PHP analyzer still runs: the backdoor inside it is
// reported independently of the integrity state.
func TestChecksumModifiedCoreFileStillAnalyzed(t *testing.T) {
	target := t.TempDir()
	site := filepath.Join(target, "site")
	writeWPVersion(t, site)

	hacked := filepath.Join(site, "wp-admin", "hacked.php")
	mustWrite(t, hacked, cleanSuspicious)

	srv := fakeChecksumAPI(t, map[string]string{
		"wp-admin/hacked.php": md5hex("<?php // pristine upstream code"),
	})
	defer srv.Close()

	res, err := Scan(context.Background(), Options{
		Target:         target,
		Platforms:      []string{"wordpress"},
		WPLocale:       "en_US",
		WPChecksumBase: srv.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.WordPress) != 1 || len(res.WordPress[0].ModifiedFiles) != 1 {
		t.Fatalf("expected exactly one MODIFIED file: %+v", res.WordPress)
	}
	if !phpFindingAt(t, res, hacked) {
		t.Fatalf("MODIFIED file must still be analyzed; findings: %+v", res.Findings)
	}
	if !hasIntegrityFinding(res) {
		t.Fatalf("integrity finding must coexist: %+v", res.Findings)
	}
	assertNoDuplicateFindings(t, res)
}

// TestUnverifiedWordPressStillAnalyzesCore: when verification cannot establish
// any reference (offline), core files are UNVERIFIED — and the PHP analyzer
// still runs over them. "We do not know if it matches upstream" never means
// "we did not look at it".
func TestUnverifiedWordPressStillAnalyzesCore(t *testing.T) {
	target := t.TempDir()
	site := filepath.Join(target, "site")
	writeWPVersion(t, site)

	core := filepath.Join(site, "wp-includes", "suspicious.php")
	mustWrite(t, core, cleanSuspicious)

	res, err := Scan(context.Background(), Options{
		Target:    target,
		Platforms: []string{"wordpress"},
		Offline:   true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.WordPress) != 1 || res.WordPress[0].Verified {
		t.Fatalf("offline wordpress must be UNVERIFIED: %+v", res.WordPress)
	}
	if !phpFindingAt(t, res, core) {
		t.Fatalf("UNVERIFIED core file must still be analyzed: %+v", res.Findings)
	}
	if !hasIntegrityFinding(res) {
		t.Fatalf("integrity finding must coexist: %+v", res.Findings)
	}
	assertNoDuplicateFindings(t, res)
}

// seededRefStore returns a store holding one pre-authenticated reference for
// a platform and version, so offline fixture scans exercise genuine CLEAN /
// MODIFIED states without network or global caches.
func seededRefStore(t *testing.T, platform, version string, files map[string]string) *refcheck.Store {
	t.Helper()
	manifest := make(map[string]string, len(files))
	for rel, content := range files {
		manifest[rel] = sha256hex(content)
	}
	store := refcheck.NewStoreAt(t.TempDir())
	store.Put(refcheck.Reference{
		Platform:   platform,
		Version:    version,
		Algorithm:  "sha256",
		Digest:     "fixture-digest",
		ArchiveURL: "https://fixture.invalid/" + platform + "-" + version + ".tar.gz",
		Manifest:   manifest,
	})
	return store
}

func buildDrupalFixtureVersion(t *testing.T, root, version string) {
	t.Helper()
	mustWrite(t, filepath.Join(root, "core", "lib", "Drupal.php"),
		"<?php namespace Drupal; const VERSION = '"+version+"';")
}

// TestDrupalCleanCoreFileStillAnalyzed: a core file that matches the
// authenticated Drupal reference is CLEAN, and the PHP analyzer still
// reports the backdoor inside it.
func TestDrupalCleanCoreFileStillAnalyzed(t *testing.T) {
	target := t.TempDir()
	dr := filepath.Join(target, "drupal")
	buildDrupalFixtureVersion(t, dr, "10.3.5")

	evil := filepath.Join(dr, "core", "modules", "evil", "evil.php")
	mustWrite(t, evil, cleanSuspicious)

	store := seededRefStore(t, "drupal", "10.3.5", map[string]string{
		"core/lib/Drupal.php":        "<?php namespace Drupal; const VERSION = '10.3.5';",
		"core/modules/evil/evil.php": cleanSuspicious,
	})

	res, err := Scan(context.Background(), Options{
		Target:    target,
		Platforms: []string{"drupal"},
		Offline:   true,
		RefStore:  store,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Drupal) != 1 || !res.Drupal[0].Verified {
		t.Fatalf("drupal verify failed: %+v", res.Drupal)
	}
	if res.Drupal[0].CleanCount != 2 || len(res.Drupal[0].Modified) != 0 {
		t.Fatalf("expected 2 CLEAN files: %+v", res.Drupal[0])
	}
	if !phpFindingAt(t, res, evil) {
		t.Fatalf("Drupal CLEAN file must still be analyzed: %+v", res.Findings)
	}
	assertNoDuplicateFindings(t, res)
}

// TestDrupalModifiedCoreFileStillAnalyzed: integrity mismatch and threat
// analysis coexist for the same file.
func TestDrupalModifiedCoreFileStillAnalyzed(t *testing.T) {
	target := t.TempDir()
	dr := filepath.Join(target, "drupal")
	buildDrupalFixtureVersion(t, dr, "10.3.5")

	evil := filepath.Join(dr, "core", "modules", "evil", "evil.php")
	mustWrite(t, evil, cleanSuspicious)

	store := seededRefStore(t, "drupal", "10.3.5", map[string]string{
		"core/lib/Drupal.php":        "<?php namespace Drupal; const VERSION = '10.3.5';",
		"core/modules/evil/evil.php": "<?php // pristine",
	})

	res, err := Scan(context.Background(), Options{
		Target:    target,
		Platforms: []string{"drupal"},
		Offline:   true,
		RefStore:  store,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Drupal) != 1 || len(res.Drupal[0].Modified) != 1 {
		t.Fatalf("expected MODIFIED state: %+v", res.Drupal)
	}
	if !phpFindingAt(t, res, evil) {
		t.Fatalf("MODIFIED Drupal file must still be analyzed: %+v", res.Findings)
	}
	assertNoDuplicateFindings(t, res)
}

func buildJoomlaFixtureVersion(t *testing.T, root string) {
	t.Helper()
	mustWrite(t, filepath.Join(root, "administrator", "manifests", "files", "joomla.xml"),
		"<?xml version=\"1.0\"?><extension><version>5.2.0</version></extension>")
	mustWrite(t, filepath.Join(root, "libraries", "src", "Version.php"),
		"<?php final class Version { public const MAJOR_VERSION = 5; public const MINOR_VERSION = 2; public const PATCH_VERSION = 0; public const EXTRA_VERSION = ''; }")
}

// TestJoomlaCleanCoreAndExtensionFilesStillAnalyzed: a Joomla core extension
// file that matches the reference manifest is CLEAN and still analyzed.
func TestJoomlaCleanCoreAndExtensionFilesStillAnalyzed(t *testing.T) {
	target := t.TempDir()
	root := filepath.Join(target, "joomla")
	buildJoomlaFixtureVersion(t, root)

	evil := filepath.Join(root, "components", "com_content", "evil.php")
	mustWrite(t, evil, cleanSuspicious)

	versionPHP := "<?php final class Version { public const MAJOR_VERSION = 5; public const MINOR_VERSION = 2; public const PATCH_VERSION = 0; public const EXTRA_VERSION = ''; }"
	store := seededRefStore(t, "joomla", "5.2.0", map[string]string{
		"libraries/src/Version.php":       versionPHP,
		"components/com_content/evil.php": cleanSuspicious,
	})

	res, err := Scan(context.Background(), Options{
		Target:    target,
		Platforms: []string{"joomla"},
		Offline:   true,
		RefStore:  store,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Joomla) != 1 || !res.Joomla[0].Verified {
		t.Fatalf("joomla verify failed: %+v", res.Joomla)
	}
	if res.Joomla[0].CleanCount != 2 || len(res.Joomla[0].Modified) != 0 {
		t.Fatalf("expected 2 CLEAN files: %+v", res.Joomla[0])
	}
	if !phpFindingAt(t, res, evil) {
		t.Fatalf("Joomla CLEAN extension file must still be analyzed: %+v", res.Findings)
	}
	assertNoDuplicateFindings(t, res)
}

// TestJoomlaModifiedCoreFileStillAnalyzed: MODIFIED core file, independent
// PHP finding.
func TestJoomlaModifiedCoreFileStillAnalyzed(t *testing.T) {
	target := t.TempDir()
	root := filepath.Join(target, "joomla")
	buildJoomlaFixtureVersion(t, root)

	evil := filepath.Join(root, "components", "com_content", "evil.php")
	mustWrite(t, evil, cleanSuspicious)

	versionPHP := "<?php final class Version { public const MAJOR_VERSION = 5; public const MINOR_VERSION = 2; public const PATCH_VERSION = 0; public const EXTRA_VERSION = ''; }"
	store := seededRefStore(t, "joomla", "5.2.0", map[string]string{
		"libraries/src/Version.php":       versionPHP,
		"components/com_content/evil.php": "<?php // pristine",
	})

	res, err := Scan(context.Background(), Options{
		Target:    target,
		Platforms: []string{"joomla"},
		Offline:   true,
		RefStore:  store,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Joomla) != 1 || len(res.Joomla[0].Modified) != 1 {
		t.Fatalf("expected MODIFIED state: %+v", res.Joomla)
	}
	if !phpFindingAt(t, res, evil) {
		t.Fatalf("MODIFIED Joomla file must still be analyzed: %+v", res.Findings)
	}
	assertNoDuplicateFindings(t, res)
}

// TestDrupalUnverifiedConfigurableFileStillAnalyzed: a mismatched
// site-configurable file yields a per-file UNVERIFIED state (not MODIFIED),
// and the PHP analyzer still runs over the existing file.
func TestDrupalUnverifiedConfigurableFileStillAnalyzed(t *testing.T) {
	target := t.TempDir()
	dr := filepath.Join(target, "drupal")
	buildDrupalFixtureVersion(t, dr, "10.3.5")

	susp := filepath.Join(dr, "sites", "example.settings.local.php")
	mustWrite(t, susp, cleanSuspicious)

	store := seededRefStore(t, "drupal", "10.3.5", map[string]string{
		"core/lib/Drupal.php":              "<?php namespace Drupal; const VERSION = '10.3.5';",
		"sites/example.settings.local.php": "<?php // pristine",
	})

	res, err := Scan(context.Background(), Options{
		Target:    target,
		Platforms: []string{"drupal"},
		Offline:   true,
		RefStore:  store,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Drupal) != 1 || !res.Drupal[0].Verified {
		t.Fatalf("drupal verify failed: %+v", res.Drupal)
	}
	foundUnverified := false
	for _, st := range res.Drupal[0].Unverified {
		if st.Path == "sites/example.settings.local.php" {
			foundUnverified = true
		}
	}
	if !foundUnverified {
		t.Fatalf("expected per-file UNVERIFIED state: %+v", res.Drupal[0].Unverified)
	}
	if !phpFindingAt(t, res, susp) {
		t.Fatalf("UNVERIFIED file must still be analyzed: %+v", res.Findings)
	}
	assertNoDuplicateFindings(t, res)
}

// TestModifiedFileWithoutSuspiciousCodeIsNotMalicious: a MODIFIED file whose
// content shows no dangerous behaviour produces NO PHP finding — a checksum
// mismatch is never interpreted as malware.
func TestModifiedFileWithoutSuspiciousCodeIsNotMalicious(t *testing.T) {
	target := t.TempDir()
	site := filepath.Join(target, "site")
	writeWPVersion(t, site)

	edited := filepath.Join(site, "wp-includes", "localized.php")
	mustWrite(t, edited, "<?php echo 'legitimately customized';\n")

	srv := fakeChecksumAPI(t, map[string]string{
		"wp-includes/localized.php": md5hex("<?php // pristine upstream"),
	})
	defer srv.Close()

	res, err := Scan(context.Background(), Options{
		Target:         target,
		Platforms:      []string{"wordpress"},
		WPLocale:       "en_US",
		WPChecksumBase: srv.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.WordPress) != 1 || len(res.WordPress[0].ModifiedFiles) != 1 {
		t.Fatalf("expected exactly one MODIFIED file: %+v", res.WordPress)
	}
	if phpFindingAt(t, res, edited) {
		t.Fatalf("MODIFIED must never imply malicious: %+v", res.Findings)
	}
	if !hasIntegrityFinding(res) {
		t.Fatalf("integrity finding must stand alone: %+v", res.Findings)
	}
}

// TestCleanFilesAcrossAllPlatformsAreAnalyzed: one scan over an --all target
// with WordPress, Drupal and Joomla installations, each holding a
// checksum-CLEAN backdoor. Every platform's CLEAN file is analyzed in the
// same run, and no duplicate findings appear.
func TestCleanFilesAcrossAllPlatformsAreAnalyzed(t *testing.T) {
	target := t.TempDir()

	wpSite := filepath.Join(target, "wp")
	writeWPVersion(t, wpSite)
	wpEvil := filepath.Join(wpSite, "wp-includes", "evil.php")
	mustWrite(t, wpEvil, cleanSuspicious)

	dr := filepath.Join(target, "dr")
	buildDrupalFixtureVersion(t, dr, "10.3.5")
	drEvil := filepath.Join(dr, "core", "modules", "evil", "evil.php")
	mustWrite(t, drEvil, cleanSuspicious)

	jo := filepath.Join(target, "jo")
	buildJoomlaFixtureVersion(t, jo)
	joEvil := filepath.Join(jo, "components", "com_content", "evil.php")
	mustWrite(t, joEvil, cleanSuspicious)

	srv := fakeChecksumAPI(t, map[string]string{
		"wp-includes/evil.php": md5hex(cleanSuspicious),
	})
	defer srv.Close()

	versionPHP := "<?php final class Version { public const MAJOR_VERSION = 5; public const MINOR_VERSION = 2; public const PATCH_VERSION = 0; public const EXTRA_VERSION = ''; }"
	store := seededRefStore(t, "drupal", "10.3.5", map[string]string{
		"core/lib/Drupal.php":        "<?php namespace Drupal; const VERSION = '10.3.5';",
		"core/modules/evil/evil.php": cleanSuspicious,
	})
	store.Put(refcheck.Reference{
		Platform:   "joomla",
		Version:    "5.2.0",
		Algorithm:  "sha256",
		Digest:     "fixture-digest",
		ArchiveURL: "https://fixture.invalid/joomla-5.2.0.tar.gz",
		Manifest: map[string]string{
			"libraries/src/Version.php":       sha256hex(versionPHP),
			"components/com_content/evil.php": sha256hex(cleanSuspicious),
		},
	})

	// Fully offline: the WordPress reference stays UNVERIFIED (the clean-file
	// proof for WordPress lives in TestChecksumCleanCoreFileStillAnalyzed),
	// while the seeded Drupal and Joomla references yield genuine CLEAN
	// states. The point of this scan is that all three platforms' files are
	// analyzed in one deterministic run regardless of integrity state.
	res, err := Scan(context.Background(), Options{
		Target:   target,
		All:      true,
		Offline:  true,
		RefStore: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, evil := range []string{wpEvil, drEvil, joEvil} {
		if !phpFindingAt(t, res, evil) {
			t.Fatalf("CLEAN file %s must be analyzed; findings: %+v", evil, res.Findings)
		}
	}
	if len(res.WordPress) != 1 || len(res.Drupal) != 1 || !res.Drupal[0].Verified ||
		len(res.Joomla) != 1 || !res.Joomla[0].Verified {
		t.Fatalf("seeded platforms must verify: wp=%d dr=%+v jo=%+v", len(res.WordPress), res.Drupal, res.Joomla)
	}
	// The seeded Drupal and Joomla files are CLEAN; the WordPress files stay
	// unverified because offline mode cannot reach a checksum reference.
	if res.Drupal[0].CleanCount != 2 || res.Joomla[0].CleanCount != 2 {
		t.Fatalf("seeded references must be CLEAN: dr=%d jo=%d", res.Drupal[0].CleanCount, res.Joomla[0].CleanCount)
	}
	assertNoDuplicateFindings(t, res)
}

// TestOldAnalyzerRegressionFixturesStillRun: the analyzer regression fixtures
// keep flowing through Scan after the suppression machinery was removed — the
// generic PHP platform scan still surfaces every legacy fixture finding.
func TestOldAnalyzerRegressionFixturesStillRun(t *testing.T) {
	target := t.TempDir()
	loose := filepath.Join(target, "fixtures")
	mustWrite(t, filepath.Join(loose, "a.php"), fxBacktick)
	mustWrite(t, filepath.Join(loose, "b.php"), fxSystemGet)
	mustWrite(t, filepath.Join(loose, "c.php"), fxEvalB64Post)
	mustWrite(t, filepath.Join(loose, "d.php"), fxShortEchoSys)

	res, err := Scan(context.Background(), Options{Target: target})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{
		filepath.Join(loose, "a.php"),
		filepath.Join(loose, "b.php"),
		filepath.Join(loose, "c.php"),
		filepath.Join(loose, "d.php"),
	} {
		if !phpFindingAt(t, res, p) {
			t.Fatalf("fixture %s lost after independence change: %+v", p, res.Findings)
		}
	}
	assertNoDuplicateFindings(t, res)
	_ = os.Getpid // keep os import honest if fixtures change
}
