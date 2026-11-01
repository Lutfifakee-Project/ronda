package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDetectWordPress(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "wp-load.php"), "<?php")
	mustWrite(t, filepath.Join(root, "wp-includes", "version.php"), "<?php")
	mustWrite(t, filepath.Join(root, "index.php"), "<?php echo 1;")

	res, err := Scan(context.Background(), Options{Target: root, Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for i := 0; i < len(res.Platforms); i++ {
		if res.Platforms[i] == "wordpress" {
			found = true
		}
	}
	if !found {
		t.Fatalf("wordpress not detected: %v", res.Platforms)
	}
	if res.FilesScanned != 3 {
		t.Fatalf("files scanned=%d want 3", res.FilesScanned)
	}
}

func TestScanRejectsNonDir(t *testing.T) {
	f := filepath.Join(t.TempDir(), "x")
	mustWrite(t, f, "hi")
	if _, err := Scan(context.Background(), Options{Target: f}); err == nil {
		t.Fatal("expected error scanning a file, not a directory")
	}
}

func TestNormalizePathStable(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.php")
	if normalizePath(p) != normalizePath(p) {
		t.Fatal("normalizePath not stable")
	}
}

// The former cleanCorePaths/verifiedCleanFiles suppression machinery and its
// unit tests were removed in Phase 3.1: behavioral proof that checksum-CLEAN,
// MODIFIED and UNVERIFIED files are all analyzed lives in
// analyzer_coverage_test.go.
