package laravel

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// standardProject builds a typical Laravel project skeleton.
func standardProject(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "artisan"), "<?php // artisan entrypoint")
	writeFile(t, filepath.Join(root, "bootstrap", "app.php"), "<?php")
	writeFile(t, filepath.Join(root, "composer.json"),
		`{"require":{"php":"^8.2","laravel/framework":"^11.0"}}`)
	writeFile(t, filepath.Join(root, "composer.lock"),
		`{"packages":[{"name":"laravel/framework","version":"v11.20.0","source":{"reference":"abc123def456"},"dist":{"url":"https://example.invalid/laravel.zip","shasum":"deadbeef"}},{"name":"symfony/console","version":"v7.0.0"}],"packages-dev":[{"name":"phpunit/phpunit","version":"11.1.0"}]}`)
	writeFile(t, filepath.Join(root, "vendor", "composer", "installed.json"),
		`{"packages":[{"name":"laravel/framework","version":"v11.20.0"},{"name":"symfony/console","version":"v7.0.0"}]}`)
	writeFile(t, filepath.Join(root, "vendor", "laravel", "framework", "composer.json"), "{}")
	writeFile(t, filepath.Join(root, "public", "index.php"), "<?php")
	return root
}

func findCheck(checks []Check, name string) (Check, bool) {
	for _, c := range checks {
		if c.Name == name {
			return c, true
		}
	}
	return Check{}, false
}

func TestDetectStandardProject(t *testing.T) {
	root := standardProject(t)
	if !IsLaravel(root) {
		t.Fatal("laravel project not detected")
	}
	if IsLaravel(t.TempDir()) {
		t.Fatal("empty dir detected as laravel")
	}
	// A single marker is not enough.
	only := t.TempDir()
	writeFile(t, filepath.Join(only, "artisan"), "<?php")
	if IsLaravel(only) {
		t.Fatal("single marker must not detect laravel")
	}
}

func TestInventoryAndConfidence(t *testing.T) {
	root := standardProject(t)
	res := Verify(context.Background(), root)

	if res.Confidence != ConfidenceHigh {
		t.Fatalf("confidence %q", res.Confidence)
	}
	if !res.FrameworkRequired {
		t.Fatal("framework required not detected")
	}
	if res.Version != "v11.20.0" || res.VersionSource != "composer.lock" {
		t.Fatalf("version %q source %q", res.Version, res.VersionSource)
	}
	if res.SourceRef != "abc123def456" {
		t.Fatalf("source ref %q", res.SourceRef)
	}
	if res.PackagesLocked != 3 || res.PackagesInstalled != 2 {
		t.Fatalf("locked=%d installed=%d", res.PackagesLocked, res.PackagesInstalled)
	}
	if res.IntegrityStatus != "UNVERIFIED" || res.IntegrityReason == "" {
		t.Fatalf("integrity %+v", res)
	}
	if len(res.VersionConflicts) != 0 {
		t.Fatalf("unexpected conflicts %v", res.VersionConflicts)
	}
	found := false
	for _, p := range res.Require {
		if p.Name == "laravel/framework" {
			found = true
		}
	}
	if !found {
		t.Fatal("require list missing laravel/framework")
	}
}

func TestInstalledVersionMismatchIsReported(t *testing.T) {
	root := standardProject(t)
	writeFile(t, filepath.Join(root, "vendor", "composer", "installed.json"),
		`{"packages":[{"name":"laravel/framework","version":"v11.0.2"}]}`)
	res := Verify(context.Background(), root)
	if len(res.VersionConflicts) == 0 {
		t.Fatalf("conflicts must be reported: %+v", res)
	}
}

func TestLockMissingStaysUnverified(t *testing.T) {
	root := standardProject(t)
	if err := os.Remove(filepath.Join(root, "composer.lock")); err != nil {
		t.Fatal(err)
	}
	res := Verify(context.Background(), root)
	if res.IntegrityStatus != "UNVERIFIED" {
		t.Fatalf("status %q", res.IntegrityStatus)
	}
	if res.Version == "" || res.VersionSource != "vendor/composer/installed.json" {
		t.Fatalf("version %q from %q", res.Version, res.VersionSource)
	}
	noted := false
	for _, n := range res.Notes {
		if contains(n, "composer.lock is missing") {
			noted = true
		}
	}
	if !noted {
		t.Fatalf("missing-lock note absent: %v", res.Notes)
	}
}

func TestSensitiveFileUnderPublic(t *testing.T) {
	root := standardProject(t)
	writeFile(t, filepath.Join(root, "public", ".env"), "APP_KEY=base64:secret")
	writeFile(t, filepath.Join(root, "public", "composer.lock"), "{}")
	res := Verify(context.Background(), root)
	c, ok := findCheck(res.Checks, "sensitive file in public directory")
	if !ok || c.Status != "HIGH" {
		t.Fatalf("check %+v ok=%v", c, ok)
	}
	if contains(c.Evidence, "secret") || contains(c.Evidence, "APP_KEY=") {
		t.Fatalf("evidence must not carry values: %q", c.Evidence)
	}
}

func TestEnvWorldReadable(t *testing.T) {
	root := standardProject(t)
	envPath := filepath.Join(root, ".env")
	writeFile(t, envPath, "APP_KEY=base64:secret\nAPP_DEBUG=true\nDB_PASSWORD=hunter2\n")
	if err := os.Chmod(envPath, 0o644); err != nil {
		t.Fatal(err)
	}
	res := Verify(context.Background(), root)
	c, ok := findCheck(res.Checks, "environment file world-readable")
	if !ok || c.Status != "MEDIUM" {
		t.Fatalf("check %+v ok=%v", c, ok)
	}
	c, ok = findCheck(res.Checks, "debug mode enabled")
	if !ok || c.Status != "LOW" || c.Line != 2 {
		t.Fatalf("debug check %+v ok=%v", c, ok)
	}
	// No secret value may leak into any check.
	for _, ch := range res.Checks {
		if contains(ch.Evidence, "hunter2") || contains(ch.Evidence, "secret") || contains(ch.Detail, "hunter2") {
			t.Fatalf("secret leaked: %+v", ch)
		}
	}
}

func TestEnvDebugDisabled(t *testing.T) {
	root := standardProject(t)
	writeFile(t, filepath.Join(root, ".env"), "APP_DEBUG=false\n")
	res := Verify(context.Background(), root)
	if _, ok := findCheck(res.Checks, "debug mode enabled"); ok {
		t.Fatal("debug check must not fire when disabled")
	}
}

func TestWorldWritableStorage(t *testing.T) {
	root := standardProject(t)
	storage := filepath.Join(root, "storage")
	if err := os.MkdirAll(storage, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(storage, 0o777); err != nil {
		t.Fatal(err)
	}
	res := Verify(context.Background(), root)
	c, ok := findCheck(res.Checks, "world-writable directory")
	if !ok || c.Status != "LOW" {
		t.Fatalf("check %+v ok=%v", c, ok)
	}
}

func TestNoPublicDirNotJudged(t *testing.T) {
	root := standardProject(t)
	if err := os.RemoveAll(filepath.Join(root, "public")); err != nil {
		t.Fatal(err)
	}
	res := Verify(context.Background(), root)
	c, ok := findCheck(res.Checks, "public directory")
	if !ok || c.Status != "INFO" {
		t.Fatalf("custom layouts must not be judged insecure: %+v ok=%v", c, ok)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
