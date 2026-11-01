package joomla

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Lutfifakee-Project/ronda/internal/platforms/refcheck"
)

// The tests in this file cover the Phase 3.1 corrections: explicit reference
// trust categories backed by the GitHub-release SHA-256 cross-check, and the
// ownership-aware unexpected scan over shared extension areas.

// extensionArchive is a minimal official package that spans the shared
// extension areas (an official component, module, plugin and its language
// files) so ownership behaviour can be tested end to end through Verify.
func extensionArchive() map[string]string {
	return map[string]string{
		"libraries/src/Version.php":                       "<?php final class Version { public const MAJOR_VERSION = 5; public const MINOR_VERSION = 2; public const PATCH_VERSION = 0; public const EXTRA_VERSION = ''; }",
		"administrator/manifests/files/joomla.xml":        "<?xml version=\"1.0\"?><extension><name>files_joomla</name><version>5.2.0</version></extension>",
		"components/com_content/content.php":              "<?php core article",
		"components/com_content/tmpl/article/default.php": "<?php core view",
		"modules/mod_stats/stats.php":                     "<?php core stats",
		"plugins/content/pagebreak/pagebreak.php":         "<?php core pagebreak",
		"language/en-GB/en-GB.com_content.ini":            "COM_CONTENT=\"Article\"",
	}
}

// TestVerifyTrustStrongPath: the downloads-page MD5+SHA-1 pair matches and
// the GitHub release publishes a matching SHA-256 for the same package, so
// the reference must be SHA256_AUTHENTICATED with no warnings.
func TestVerifyTrustStrongPath(t *testing.T) {
	fs := newFakeServer(t, baseArchive())
	fs.overrideBases(t)
	root := installFrom(t, baseArchive())
	store := refcheck.NewStoreAt(filepath.Join(t.TempDir(), "refs"))

	res := Verify(context.Background(), root, testOpts(fs, store))
	if !res.Verified {
		t.Fatalf("not verified: %s", res.Reason)
	}
	if res.Reference.Trust.Category != refcheck.StrengthSHA256Authenticated {
		t.Fatalf("trust %q, want SHA256_AUTHENTICATED: %+v", res.Reference.Trust.Category, res.Reference.Trust)
	}
	if res.Reference.Trust.DigestAlgorithm != "sha256" || res.Reference.Trust.ArchiveSHA256 == "" ||
		res.Reference.Trust.AuthenticationMethod == "" || res.Reference.Trust.Confidence == "" {
		t.Fatalf("trust metadata incomplete: %+v", res.Reference.Trust)
	}
	if len(res.Warnings) != 0 {
		t.Fatalf("strong path must carry no warnings: %v", res.Warnings)
	}
	if !strings.Contains(res.VerificationMethod, "SHA-256") {
		t.Fatalf("method must name the strongest evidence: %q", res.VerificationMethod)
	}

	// Cached offline run keeps the recorded trust level; trust travels with
	// the reference, it is never re-derived from weaker evidence.
	off := Verify(context.Background(), root, VerifyOptions{Offline: true, Store: store, Client: fs.client})
	if !off.Verified || !off.Reference.Cached {
		t.Fatalf("offline cached run failed: %+v", off)
	}
	if off.Reference.Trust.Category != refcheck.StrengthSHA256Authenticated {
		t.Fatalf("cached trust must stay strong: %q", off.Reference.Trust.Category)
	}
}

// TestVerifyTrustLegacyPath: the strong digest is unavailable, so the
// reference is honestly LEGACY_DIGEST_MATCH and every warning the caller
// needs to see is attached to the result.
func TestVerifyTrustLegacyPath(t *testing.T) {
	fs := newFakeServer(t, baseArchive())
	fs.overrideBases(t)
	fs.githubSHA256 = "" // GitHub endpoint answers 404
	root := installFrom(t, baseArchive())

	res := Verify(context.Background(), root, testOpts(fs, refcheck.NewStoreAt(filepath.Join(t.TempDir(), "refs"))))
	if !res.Verified {
		t.Fatalf("legacy-digest verification must still succeed: %s", res.Reason)
	}
	if res.Reference.Trust.Category != refcheck.StrengthLegacyDigestMatch {
		t.Fatalf("trust %q, want LEGACY_DIGEST_MATCH", res.Reference.Trust.Category)
	}
	if len(res.Warnings) == 0 {
		t.Fatal("weak-digest warning missing")
	}
	found := false
	for _, w := range res.Warnings {
		if strings.Contains(w, "LEGACY_DIGEST_MATCH") {
			found = true
		}
	}
	if !found {
		t.Fatalf("warning must name the legacy category: %v", res.Warnings)
	}
	if strings.Contains(res.VerificationMethod, "SHA-256") {
		t.Fatalf("method must not claim strong authentication: %q", res.VerificationMethod)
	}
}

// TestVerifyTrustMismatchRefused: when the GitHub release SHA-256 does not
// match the downloaded archive, the official sources disagree and no manifest
// may be derived — the refusal is a hard failure, never a downgrade.
func TestVerifyTrustMismatchRefused(t *testing.T) {
	fs := newFakeServer(t, baseArchive())
	fs.overrideBases(t)
	fs.githubSHA256 = strings.Repeat("ab", 32) // a valid-looking but wrong digest
	root := installFrom(t, baseArchive())

	res := Verify(context.Background(), root, testOpts(fs, refcheck.NewStoreAt(filepath.Join(t.TempDir(), "refs"))))
	if res.Verified {
		t.Fatal("mismatching official sources must refuse verification")
	}
	if !strings.Contains(res.Reason, "official sources disagree") {
		t.Fatalf("reason must explain the refusal: %q", res.Reason)
	}
}

// TestParseGitHubReleaseSHA256Shape pins the strict parser to the real
// release body shape, including the exclusion of the update-package table.
func TestParseGitHubReleaseSHA256Shape(t *testing.T) {
	fs := newFakeServer(t, baseArchive())
	fs.overrideBases(t)
	body := fs.githubReleaseBody()

	got, err := parseGitHubReleaseSHA256([]byte(body), testVersion)
	if err != nil {
		t.Fatal(err)
	}
	if got != fs.githubSHA256 {
		t.Fatalf("parsed %q, want the full-package digest %q", got, fs.githubSHA256)
	}
	if got == "3333333333333333333333333333333333333333333333333333333333333333" {
		t.Fatal("the update-package digest must never be picked for the full package")
	}

	// A body without the New Installations section must fail, not guess.
	if _, err := parseGitHubReleaseSHA256([]byte("no table here"), testVersion); err == nil {
		t.Fatal("missing section must error")
	}
	// A row for a different asset must not match.
	trimmed := strings.Replace(body, "Joomla_5.2.0-Stable-Full_Package.tar.gz", "Joomla_5.1.9-Stable-Full_Package.tar.gz", 1)
	if _, err := parseGitHubReleaseSHA256([]byte(trimmed), testVersion); err == nil {
		t.Fatal("a different version's row must not satisfy this version")
	}
}

// TestVerifyOwnershipFixtures walks the Joomla adapter end to end: core
// extension areas are now inside the unexpected-file scan, while third-party
// extensions and language overrides stay conservatively unreported, and
// modified/missing official extension files are still per-file states.
func TestVerifyOwnershipFixtures(t *testing.T) {
	fs := newFakeServer(t, extensionArchive())
	fs.overrideBases(t)
	files := extensionArchive()
	root := installFrom(t, files)

	// Extra file inside an official Core extension directory: reported.
	if err := os.MkdirAll(filepath.Join(root, "components", "com_content", "tmpl", "article"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "components", "com_content", "rogue.php"), []byte("<?php rogue"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Third-party extension directory: never reported.
	if err := os.MkdirAll(filepath.Join(root, "components", "com_3rdparty"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "components", "com_3rdparty", "x.php"), []byte("<?php 3p"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Language override for an unknown (third-party) token: never reported.
	if err := os.WriteFile(filepath.Join(root, "language", "en-GB", "en-GB.com_3rdparty.ini"), []byte("X=\"Y\""), 0o644); err != nil {
		t.Fatal(err)
	}
	// Modified official Core extension file: MODIFIED state.
	if err := os.WriteFile(filepath.Join(root, "components", "com_content", "content.php"), []byte("<?php tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Deleted official Core extension file: MISSING state.
	if err := os.Remove(filepath.Join(root, "modules", "mod_stats", "stats.php")); err != nil {
		t.Fatal(err)
	}

	res := Verify(context.Background(), root, testOpts(fs, refcheck.NewStoreAt(filepath.Join(t.TempDir(), "refs"))))
	if !res.Verified {
		t.Fatalf("not verified: %s", res.Reason)
	}
	if len(res.Unexpected) != 1 || res.Unexpected[0] != "components/com_content/rogue.php" {
		t.Fatalf("unexpected %v, want exactly the owned-dir extra", res.Unexpected)
	}
	st, ok := findState(res, "components/com_content/content.php")
	if !ok || st.Status != "MODIFIED" {
		t.Fatalf("core extension file must be MODIFIED, got %+v", st)
	}
	st, ok = findState(res, "modules/mod_stats/stats.php")
	if !ok || st.Status != "MISSING" {
		t.Fatalf("core extension file must be MISSING, got %+v", st)
	}

	// The skipped-areas description must match the real policy: it no longer
	// claims shared areas are wholly excluded.
	joined := strings.Join(res.SkippedAreas, " ")
	if strings.Contains(joined, "not reported)") {
		t.Fatalf("stale exclusion text: %v", res.SkippedAreas)
	}
	if !strings.Contains(joined, "does not demonstrably own") {
		t.Fatalf("policy description must be honest: %v", res.SkippedAreas)
	}
}

// TestVerifyCachedLegacyWarningSurvivesCache: the weak-digest warning must
// also appear on runs that hit the cache — honesty survives the cache.
func TestVerifyCachedLegacyWarningSurvivesCache(t *testing.T) {
	fs := newFakeServer(t, baseArchive())
	fs.overrideBases(t)
	fs.githubSHA256 = "" // strong digest unavailable at build time
	root := installFrom(t, baseArchive())
	store := refcheck.NewStoreAt(filepath.Join(t.TempDir(), "refs"))

	first := Verify(context.Background(), root, testOpts(fs, store))
	if !first.Verified || first.Reference.Trust.Category != refcheck.StrengthLegacyDigestMatch {
		t.Fatalf("legacy build failed: %+v", first)
	}

	// Online cached run and offline cached run both re-attach the warning.
	for _, mode := range []string{"online", "offline"} {
		var res Result
		if mode == "online" {
			res = Verify(context.Background(), root, testOpts(fs, store))
		} else {
			res = Verify(context.Background(), root, VerifyOptions{Offline: true, Store: store, Client: fs.client})
		}
		if !res.Verified || !res.Reference.Cached {
			t.Fatalf("%s cached run failed: %+v", mode, res)
		}
		if len(res.Warnings) == 0 {
			t.Fatalf("%s cached run lost the weak-digest warning", mode)
		}
		if !strings.Contains(res.Warnings[0], "LEGACY_DIGEST_MATCH") {
			t.Fatalf("%s cached warning must name the category: %v", mode, res.Warnings)
		}
	}
}
