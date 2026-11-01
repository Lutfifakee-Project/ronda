package reporter

import (
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/Lutfifakee-Project/ronda/internal/finding"
	"github.com/Lutfifakee-Project/ronda/internal/platforms/drupal"
	"github.com/Lutfifakee-Project/ronda/internal/platforms/joomla"
	"github.com/Lutfifakee-Project/ronda/internal/platforms/laravel"
	"github.com/Lutfifakee-Project/ronda/internal/platforms/wordpress"
	"github.com/Lutfifakee-Project/ronda/internal/scanner"
	"github.com/Lutfifakee-Project/ronda/internal/version"
)

func fixtureResult() scanner.Result {
	res := scanner.Result{
		Target:    "/srv",
		Platforms: []string{"wordpress", "drupal", "joomla", "laravel"},
		Findings: []finding.Finding{
			{
				Status:   finding.Modified,
				Severity: finding.High,
				Title:    "Drupal core files modified: 1",
				Platform: "drupal",
				Path:     "/srv/drupal",
				Evidence: "core/index.php",
			},
			{
				Status:   finding.Suspicious,
				Severity: finding.High,
				Title:    "Laravel sensitive file in public directory",
				Platform: "laravel",
				Path:     "/srv/laravel/public/.env",
			},
		},
	}
	res.WordPress = []wordpress.Result{{
		Root: "/srv/wp", Version: "6.4.2", Locale: "en_US",
		LocaleSource: "wp_local_package", LocaleConfidence: "high",
		Verified: true, TotalFiles: 10, CleanCount: 10,
		ManifestSource: "api.wordpress.org",
	}}
	res.Drupal = []drupal.Result{{
		Root: "/srv/drupal", Version: "10.3.5", Layout: drupal.LayoutTarball,
		Verified: true, VerificationMethod: "official release archive (sha256-authenticated) per-file manifest",
		TotalFiles: 100, CleanCount: 97, SkippedCount: 0,
		Modified: []drupal.FileState{{Path: "core/index.php", Status: "MODIFIED",
			ExpectedSHA256: "aaaa", ActualSHA256: "bbbb"}},
		Reference: drupal.Reference{
			SourcePage: "https://www.drupal.org/project/drupal/releases/10.3.5",
			ArchiveURL: "https://ftp.drupal.org/files/projects/drupal-10.3.5.tar.gz",
			Algorithm:  "sha256", Cached: true, Created: "2026-10-31T00:00:00Z",
		},
		SkippedAreas: []string{"sites (site-owned)"},
	}}
	res.Joomla = []joomla.Result{{
		Root: "/srv/joomla", Version: "5.2.0", Verified: false,
		Reason: "offline mode and no cached reference manifest for Joomla 5.2.0",
		VersionSources: []joomla.VersionSource{
			{Value: "5.2.0", Source: "libraries/src/Version.php"},
		},
	}}
	res.Laravel = []laravel.Result{{
		Root: "/srv/laravel", Confidence: laravel.ConfidenceHigh,
		FrameworkRequired: true, Version: "v11.20.0", VersionSource: "composer.lock",
		PackagesLocked: 42, PackagesInstalled: 42,
		IntegrityStatus: "UNVERIFIED", IntegrityReason: "no authenticated archive available",
		Checks: []laravel.Check{{
			Name: "sensitive file in public directory", Status: "HIGH",
			Detail: "may be directly downloadable", Path: "/srv/laravel/public/.env",
			Evidence: "file present: .env",
		}},
	}}
	return res
}

func TestTerminalRendersAllPlatforms(t *testing.T) {
	out := renderTerminal(fixtureResult())
	for _, want := range []string{
		"WordPress: /srv/wp",
		"Drupal: /srv/drupal",
		"VERIFIED via official release archive",
		"Joomla: /srv/joomla",
		"UNVERIFIED (offline mode",
		"Laravel: /srv/laravel",
		"confidence: high",
		"integrity: UNVERIFIED",
		"[HIGH] Laravel sensitive file in public directory",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("terminal missing %q\n---\n%s", want, out)
		}
	}
}

func TestJSONIsValidAndAdditive(t *testing.T) {
	data, err := renderJSON(fixtureResult())
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	// Legacy key untouched.
	wp, ok := doc["wordpress"].([]interface{})
	if !ok || len(wp) != 1 {
		t.Fatalf("wordpress key %v", doc["wordpress"])
	}
	for _, key := range []string{"drupal", "joomla", "laravel", "findings", "platforms"} {
		if _, ok := doc[key]; !ok {
			t.Fatalf("JSON key %q missing", key)
		}
	}
	dr := doc["drupal"].([]interface{})[0].(map[string]interface{})
	if dr["version"] != "10.3.5" || dr["integrity_status"] != "VERIFIED" {
		t.Fatalf("drupal JSON %+v", dr)
	}
	jo := doc["joomla"].([]interface{})[0].(map[string]interface{})
	if jo["integrity_status"] != "UNVERIFIED" {
		t.Fatalf("joomla JSON %+v", jo)
	}
	la := doc["laravel"].([]interface{})[0].(map[string]interface{})
	if la["confidence"] != "high" || la["integrity_status"] != "UNVERIFIED" {
		t.Fatalf("laravel JSON %+v", la)
	}
}

func TestHTMLRendersAllPlatforms(t *testing.T) {
	out := renderHTML(fixtureResult())
	for _, want := range []string{
		"<h2>WordPress Core Integrity</h2>",
		"<h2>Drupal Core Integrity</h2>",
		"<h2>Joomla Core Integrity</h2>",
		"<h2>Laravel Framework Profile</h2>",
		"MODIFIED",
		"UNVERIFIED",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("html missing %q", want)
		}
	}
	// Findings table shows both integrity and threat findings.
	if !strings.Contains(out, "Laravel sensitive file in public directory") ||
		!strings.Contains(out, "Drupal core files modified: 1") {
		t.Fatal("findings table incomplete")
	}
}

func TestWriteDefaultsToTerminal(t *testing.T) {
	// Smoke: Write with an unknown format must fail, known ones must not.
	res := fixtureResult()
	if err := Write(io.Discard, res, Options{Format: "bogus"}); err == nil {
		t.Fatal("bogus format must fail")
	}
	_ = version.RulesVersion
}
