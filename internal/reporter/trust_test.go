package reporter

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Lutfifakee-Project/ronda/internal/platforms/drupal"
	"github.com/Lutfifakee-Project/ronda/internal/platforms/joomla"
	"github.com/Lutfifakee-Project/ronda/internal/platforms/laravel"
	"github.com/Lutfifakee-Project/ronda/internal/platforms/refcheck"
	"github.com/Lutfifakee-Project/ronda/internal/platforms/wordpress"
	"github.com/Lutfifakee-Project/ronda/internal/scanner"
)

// The trust model must be visible in every report format: how strongly the
// reference archive was authenticated is reported explicitly and separately
// from the integrity status and from any threat findings.

func trustFixture(res *scanner.Result) {
	res.WordPress = []wordpress.Result{{
		Root: "/srv/wp", Version: "6.4.2", Locale: "en_US",
		LocaleSource: "wp_local_package", LocaleConfidence: "high",
		Verified: true, TotalFiles: 10, CleanCount: 10,
		ManifestSource: "api.wordpress.org",
	}}
	res.Drupal = []drupal.Result{{
		Root: "/srv/drupal", Version: "10.3.5", Layout: drupal.LayoutTarball,
		Verified: true, TotalFiles: 100, CleanCount: 100,
		Reference: drupal.Reference{
			SourcePage: "https://www.drupal.org/project/drupal/releases/10.3.5",
			Algorithm:  "sha256",
			Trust: refcheck.Trust{
				Category:             refcheck.StrengthSHA256Authenticated,
				DigestAlgorithm:      "sha256",
				AuthenticationMethod: "release page SHA-256",
				Confidence:           "strong evidence",
			},
		},
	}}
	res.Joomla = []joomla.Result{{
		Root: "/srv/joomla", Version: "5.2.0", Verified: true,
		Reference: joomla.Reference{
			SourcePage: "https://downloads.joomla.org/cms/joomla5/5-2-0",
			Algorithm:  "md5+sha1",
			Trust: refcheck.Trust{
				Category:             refcheck.StrengthSHA256Authenticated,
				DigestAlgorithm:      "sha256",
				AuthenticationMethod: "downloads-page MD5+SHA-1 plus GitHub SHA-256",
				ArchiveSHA256:        "abc",
				Confidence:           "strong evidence",
			},
		},
	}}
	res.Laravel = []laravel.Result{{
		Root: "/srv/laravel", Confidence: laravel.ConfidenceHigh,
		IntegrityStatus: "UNVERIFIED", IntegrityReason: "no authenticated archive available",
	}}
}

func TestReferenceTrustFieldsInJSON(t *testing.T) {
	res := fixtureResult()
	trustFixture(&res)

	data, err := renderJSON(res)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}

	// WordPress: per-file MD5 is honest legacy evidence.
	wp := doc["wordpress"].([]interface{})[0].(map[string]interface{})
	if wp["reference_strength"] != refcheck.StrengthLegacyDigestMatch {
		t.Fatalf("wordpress reference_strength %v", wp["reference_strength"])
	}
	if wp["reference_digest_algorithm"] != "md5" || wp["verification_confidence"] == "" {
		t.Fatalf("wordpress trust metadata incomplete: %v %v", wp["reference_digest_algorithm"], wp["verification_confidence"])
	}

	// Drupal: SHA-256 authenticated, all seven display fields present.
	dr := doc["drupal"].([]interface{})[0].(map[string]interface{})
	ref := dr["reference"].(map[string]interface{})
	for _, key := range []string{
		"reference_source", "archive_format", "reference_digest_algorithm",
		"reference_authentication_method", "reference_strength",
		"reference_verified", "verification_confidence",
	} {
		if _, ok := ref[key]; !ok {
			t.Fatalf("drupal reference field %q missing", key)
		}
	}
	if ref["reference_strength"] != refcheck.StrengthSHA256Authenticated || ref["reference_verified"] != true ||
		ref["archive_format"] != "tar.gz" {
		t.Fatalf("drupal reference trust wrong: %v", ref)
	}

	// Joomla: strong path carries no warnings.
	jo := doc["joomla"].([]interface{})[0].(map[string]interface{})
	jref := jo["reference"].(map[string]interface{})
	if jref["reference_strength"] != refcheck.StrengthSHA256Authenticated {
		t.Fatalf("joomla reference_strength %v", jref["reference_strength"])
	}
	if _, ok := jo["reference_warnings"]; ok {
		t.Fatal("strong joomla reference must carry no warnings")
	}

	// Laravel: no reference exists, so the strength is UNVERIFIED by design.
	la := doc["laravel"].([]interface{})[0].(map[string]interface{})
	if la["reference_strength"] != refcheck.StrengthUnverified || la["verification_confidence"] == "" {
		t.Fatalf("laravel trust %v / %v", la["reference_strength"], la["verification_confidence"])
	}
}

func TestLegacyDigestWarningInAllFormats(t *testing.T) {
	res := fixtureResult()
	trustFixture(&res)
	res.Joomla[0].Reference.Trust.Category = refcheck.StrengthLegacyDigestMatch
	res.Joomla[0].Reference.Trust.DigestAlgorithm = "md5+sha1"
	res.Joomla[0].Reference.Trust.ArchiveSHA256 = ""
	res.Joomla[0].Warnings = []string{
		"reference strength: LEGACY_DIGEST_MATCH — Joomla publishes only MD5 and SHA-1 for this package and the GitHub release SHA-256 was unavailable (context); treat the reference as legacy-digest evidence, not strong authentication",
	}

	// JSON: the warning list and the honest category travel together.
	data, err := renderJSON(res)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	jo := doc["joomla"].([]interface{})[0].(map[string]interface{})
	jref := jo["reference"].(map[string]interface{})
	if jref["reference_strength"] != refcheck.StrengthLegacyDigestMatch {
		t.Fatalf("legacy trust must be labelled honestly: %v", jref["reference_strength"])
	}
	warnings, ok := jo["reference_warnings"].([]interface{})
	if !ok || len(warnings) != 1 {
		t.Fatalf("reference_warnings missing: %v", jo["reference_warnings"])
	}

	// Terminal: the warning is printed, never swallowed.
	term := renderTerminal(res)
	if !strings.Contains(term, "reference strength: LEGACY_DIGEST_MATCH") {
		t.Fatalf("terminal must show the legacy category:\n%s", term)
	}
	if !strings.Contains(term, "warning: reference strength: LEGACY_DIGEST_MATCH") {
		t.Fatalf("terminal must show the weak-digest warning:\n%s", term)
	}

	// HTML: same honesty.
	page := renderHTML(res)
	if !strings.Contains(page, "Reference strength: LEGACY_DIGEST_MATCH") ||
		!strings.Contains(page, "Warning: reference strength: LEGACY_DIGEST_MATCH") {
		t.Fatalf("html must surface the legacy category and warning")
	}
}

func TestUnverifiedInstallsGetUnverifiedStrength(t *testing.T) {
	res := fixtureResult()
	trustFixture(&res)
	res.Drupal[0] = drupal.Result{Root: "/srv/drupal", Verified: false, Reason: "official release page unavailable: context"}
	res.Joomla[0] = joomla.Result{Root: "/srv/joomla", Verified: false, Reason: "offline mode"}
	res.WordPress[0].Verified = false
	res.WordPress[0].Reason = "offline mode"

	data, err := renderJSON(res)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"wordpress", "drupal", "joomla"} {
		inst := doc[key].([]interface{})[0].(map[string]interface{})
		if inst["reference_strength"] != refcheck.StrengthUnverified {
			t.Fatalf("%s unverified install must report reference_strength UNVERIFIED, got %v", key, inst["reference_strength"])
		}
	}
	// WordPress, Drupal and Joomla each show the unverified strength; the
	// Laravel line is always UNVERIFIED by design, for four occurrences.
	term := renderTerminal(res)
	if strings.Count(term, "reference strength: UNVERIFIED") != 4 {
		t.Fatalf("terminal must show UNVERIFIED strength for wp/dr/jo + laravel:\n%s", term)
	}
	page := renderHTML(res)
	if strings.Count(page, "Reference strength: UNVERIFIED") != 4 {
		t.Fatalf("html must show UNVERIFIED strength for wp/dr/jo + laravel")
	}
}

func TestLaravelStrengthAlwaysUnverified(t *testing.T) {
	res := fixtureResult()
	trustFixture(&res)
	term := renderTerminal(res)
	if !strings.Contains(term, "reference strength: UNVERIFIED (no official per-file reference exists for framework applications)") {
		t.Fatalf("laravel terminal trust line missing:\n%s", term)
	}
	page := renderHTML(res)
	if !strings.Contains(page, "Reference strength: UNVERIFIED (no official per-file reference exists for framework applications)") {
		t.Fatalf("laravel html trust line missing")
	}
}
