package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Fixture installs are marker-only: verification without network references
// yields UNVERIFIED findings, which is exactly the plumbing these tests
// exercise (discovery, trigger, finding conversion, scope filtering).

func buildDrupalFixture(t *testing.T, root string) {
	t.Helper()
	mustWrite(t, filepath.Join(root, "core", "lib", "Drupal.php"),
		"<?php namespace Drupal; const VERSION = '9.5.10';")
}

func buildJoomlaFixture(t *testing.T, root string) {
	t.Helper()
	mustWrite(t, filepath.Join(root, "administrator", "manifests", "files", "joomla.xml"),
		"<?xml version=\"1.0\"?><extension><version>5.2.0</version></extension>")
	mustWrite(t, filepath.Join(root, "libraries", "src", "Version.php"),
		"<?php final class Version { public const MAJOR_VERSION = 5; public const MINOR_VERSION = 2; public const PATCH_VERSION = 0; public const EXTRA_VERSION = ''; }")
}

func buildLaravelFixture(t *testing.T, root string) {
	t.Helper()
	mustWrite(t, filepath.Join(root, "artisan"), "<?php")
	mustWrite(t, filepath.Join(root, "bootstrap", "app.php"), "<?php")
	mustWrite(t, filepath.Join(root, "composer.json"),
		`{"require":{"laravel/framework":"^11.0"}}`)
	mustWrite(t, filepath.Join(root, "composer.lock"),
		`{"packages":[{"name":"laravel/framework","version":"v11.20.0"}]}`)
}

func platformIn(list []string, name string) bool {
	for _, p := range list {
		if p == name {
			return true
		}
	}
	return false
}

func TestDiscoverMultipleInstallations(t *testing.T) {
	base := t.TempDir()
	buildWordPressInstall(t, filepath.Join(base, "site1"))
	buildDrupalFixture(t, filepath.Join(base, "site2"))
	buildJoomlaFixture(t, filepath.Join(base, "site3"))
	buildLaravelFixture(t, filepath.Join(base, "app1"))
	buildDrupalFixture(t, filepath.Join(base, "site2b")) // second drupal

	d := discoverInstallations(base)
	if len(d.WordPress) != 1 || len(d.Drupal) != 2 || len(d.Joomla) != 1 || len(d.Laravel) != 1 {
		t.Fatalf("discovery: %+v", d)
	}
	if got := d.names(); !platformIn(got, "wordpress") || !platformIn(got, "drupal") ||
		!platformIn(got, "joomla") || !platformIn(got, "laravel") {
		t.Fatalf("names %v", got)
	}
}

func TestDiscoverySkipsVendor(t *testing.T) {
	base := t.TempDir()
	// vendor/drupal/core contains a core marker and must never be treated
	// as a Drupal installation.
	buildDrupalFixture(t, filepath.Join(base, "site", "vendor", "drupal", "core"))
	buildDrupalFixture(t, filepath.Join(base, "site"))

	d := discoverInstallations(base)
	if len(d.Drupal) != 1 {
		t.Fatalf("vendor tree must be skipped: %+v", d.Drupal)
	}
}

func TestPlatformModesAreOptIn(t *testing.T) {
	base := t.TempDir()
	buildDrupalFixture(t, filepath.Join(base, "drupal"))
	buildLaravelFixture(t, filepath.Join(base, "laravel"))

	// Default scan: platforms detected, but no Drupal/Laravel verification
	// results and no platform findings.
	res, err := Scan(context.Background(), Options{Target: base, Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	if !platformIn(res.Platforms, "drupal") || !platformIn(res.Platforms, "laravel") {
		t.Fatalf("platforms %v", res.Platforms)
	}
	if len(res.Drupal) != 0 || len(res.Laravel) != 0 {
		t.Fatalf("default scan must not verify new platforms: %+v", res.Drupal)
	}

	// --drupal: verification runs (offline -> UNVERIFIED with reason).
	res, err = Scan(context.Background(), Options{Target: base, Platforms: []string{"drupal"}, Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Drupal) != 1 {
		t.Fatalf("drupal results %d", len(res.Drupal))
	}
	if res.Drupal[0].Verified || res.Drupal[0].Reason == "" {
		t.Fatalf("offline drupal verify must be UNVERIFIED: %+v", res.Drupal[0])
	}
	if len(res.Laravel) != 0 {
		t.Fatalf("laravel must stay unverified when not requested")
	}

	// --all: everything runs.
	res, err = Scan(context.Background(), Options{Target: base, All: true, Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Drupal) != 1 || len(res.Laravel) != 1 {
		t.Fatalf("--all must run both: drupal=%d laravel=%d", len(res.Drupal), len(res.Laravel))
	}
}

func TestPlatformModeKeepsPHPFindingsInsideInstall(t *testing.T) {
	base := t.TempDir()
	dr := filepath.Join(base, "drupal")
	buildDrupalFixture(t, dr)
	// A backdoored contributed module inside the Drupal installation and a
	// suspicious file elsewhere on the server.
	mustWrite(t, filepath.Join(dr, "modules", "contrib", "evil", "shell.php"),
		"<?php "+dollar()+"c = "+dollar()+"_GET['c']; system("+dollar()+"c);")
	mustWrite(t, filepath.Join(base, "loose.php"),
		"<?php "+dollar()+"c = "+dollar()+"_GET['c']; system("+dollar()+"c);")

	res, err := Scan(context.Background(), Options{Target: base, Platforms: []string{"drupal"}, Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	suspicious := 0
	looseReported := false
	for i := 0; i < len(res.Findings); i++ {
		f := res.Findings[i]
		if f.Platform != "php" {
			continue
		}
		suspicious++
		if f.Path == filepath.Join(base, "loose.php") {
			looseReported = true
		}
	}
	// Phase 4: the in-install fixture yields the aggregate signal finding
	// plus the established request-to-shell correlation finding.
	if suspicious != 2 {
		t.Fatalf("expected aggregate + correlation PHP findings, got %d: %+v", suspicious, res.Findings)
	}
	if looseReported {
		t.Fatal("unrelated PHP must not leak into --drupal output")
	}
	// The unverified Drupal integrity finding coexists with the PHP finding.
	hasDrupal := false
	for i := 0; i < len(res.Findings); i++ {
		if res.Findings[i].Platform == "drupal" {
			hasDrupal = true
		}
	}
	if !hasDrupal {
		t.Fatal("drupal integrity finding missing")
	}
}

func TestLaravelModeReportsStructuralChecksAndPHP(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "app")
	buildLaravelFixture(t, root)
	// .env with debug enabled, plus a suspicious file in public/.
	envPath := filepath.Join(root, ".env")
	mustWrite(t, envPath, "APP_KEY=base64:realkey\nAPP_DEBUG=true\n")
	if err := os.Chmod(envPath, 0o644); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(root, "public", ".env"), "APP_KEY=base64:realkey")
	mustWrite(t, filepath.Join(root, "public", "shell.php"),
		"<?php system("+dollar()+"_GET['c']);")

	res, err := Scan(context.Background(), Options{Target: base, Platforms: []string{"laravel"}, Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Laravel) != 1 {
		t.Fatalf("laravel results %d", len(res.Laravel))
	}
	titles := map[string]bool{}
	for i := 0; i < len(res.Findings); i++ {
		f := res.Findings[i]
		if f.Platform == "laravel" {
			titles[f.Title] = true
		}
	}
	if !titles["Laravel sensitive file in public directory"] {
		t.Fatalf("public .env finding missing: %v", titles)
	}
	if !titles["Laravel debug mode enabled"] {
		t.Fatalf("debug finding missing: %v", titles)
	}
	if !titles["Laravel package integrity not verifiable"] {
		t.Fatalf("integrity trust finding missing: %v", titles)
	}
	// PHP analysis still runs on application code.
	phpSeen := false
	for i := 0; i < len(res.Findings); i++ {
		if res.Findings[i].Platform == "php" && filepath.Base(filepath.Dir(res.Findings[i].Path)) == "public" {
			phpSeen = true
		}
	}
	if !phpSeen {
		t.Fatal("PHP analyzer must cover Laravel application code")
	}
}

func TestRequestedRoots(t *testing.T) {
	base := t.TempDir()
	buildDrupalFixture(t, filepath.Join(base, "d1"))
	buildDrupalFixture(t, filepath.Join(base, "d2"))
	buildJoomlaFixture(t, filepath.Join(base, "j1"))
	d := discoverInstallations(base)

	opts := Options{Platforms: []string{"drupal"}}
	roots := requestedRoots(opts, d)
	if len(roots) != 2 {
		t.Fatalf("drupal roots %v", roots)
	}
	opts = Options{Platforms: []string{"joomla"}}
	roots = requestedRoots(opts, d)
	if len(roots) != 1 || filepath.Base(roots[0]) != "j1" {
		t.Fatalf("joomla roots %v", roots)
	}
	opts = Options{All: true}
	roots = requestedRoots(opts, d)
	if len(roots) != 3 {
		t.Fatalf("--all roots %v", roots)
	}
	opts = Options{}
	if roots := requestedRoots(opts, d); len(roots) != 0 {
		t.Fatalf("default scan has no requested roots: %v", roots)
	}
}

func TestSiblingDirectoryTrapWithPlatforms(t *testing.T) {
	base := t.TempDir()
	dr := filepath.Join(base, "site")
	buildDrupalFixture(t, dr)
	// A sibling whose name shares the prefix must not swallow findings.
	mustWrite(t, filepath.Join(base, "site-backup", "evil.php"),
		"<?php system("+dollar()+"_GET['c']);")

	res, err := Scan(context.Background(), Options{Target: base, Platforms: []string{"drupal"}, Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(res.Findings); i++ {
		f := res.Findings[i]
		if f.Platform == "php" && contains(f.Path, "site-backup") {
			t.Fatalf("sibling directory leaked into platform mode: %+v", f)
		}
	}
}

func TestDuplicatePlatformFindingsNotCreated(t *testing.T) {
	base := t.TempDir()
	buildDrupalFixture(t, filepath.Join(base, "site"))
	res, err := Scan(context.Background(), Options{Target: base, Platforms: []string{"drupal"}, Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for i := 0; i < len(res.Findings); i++ {
		f := res.Findings[i]
		key := f.Platform + "|" + f.Title + "|" + f.Path
		seen[key]++
		if seen[key] > 1 {
			t.Fatalf("duplicate finding: %+v", f)
		}
	}
}

// contains is a small helper matching substring semantics used above.
func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
