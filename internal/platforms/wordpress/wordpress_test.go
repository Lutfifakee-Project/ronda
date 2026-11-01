package wordpress

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

var nlB = string([]byte{10})

func dollar() string { return string([]byte{36}) }

func versionPHP(v string) string {
	return "<?php" + nlB + dollar() + "wp_version = '" + v + "';" + nlB
}

func md5hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func makeInstall(t *testing.T, version string, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "wp-includes", "version.php"), versionPHP(version))
	writeFile(t, filepath.Join(root, "wp-load.php"), "<?php // load"+nlB)
	for rel, content := range files {
		writeFile(t, filepath.Join(root, filepath.FromSlash(rel)), content)
	}
	return root
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func manifestServer(t *testing.T, version string, manifest map[string]string, hits *int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			atomic.AddInt32(hits, 1)
		}
		w.Header().Set("Content-Type", "application/json")
		body, err := json.Marshal(map[string]interface{}{
			"checksums": map[string]interface{}{version: manifest},
		})
		if err != nil {
			t.Errorf("marshal: %v", err)
			return
		}
		w.Write(body)
	}))
}

func TestDetectVersion(t *testing.T) {
	root := makeInstall(t, "6.4.2", nil)
	if v := DetectVersion(root); v != "6.4.2" {
		t.Fatalf("version=%q", v)
	}
}

func TestIsMD5Hex(t *testing.T) {
	if !isMD5Hex("d41d8cd98f00b204e9800998ecf8427e") {
		t.Fatal("valid md5 rejected")
	}
	if isMD5Hex("xyz") || isMD5Hex("d41d8cd98f00b204e9800998ecf8427") {
		t.Fatal("invalid md5 accepted")
	}
}

func TestSafeJoinRejectsTraversal(t *testing.T) {
	root := t.TempDir()
	if _, err := safeJoin(root, "../evil.php"); err == nil {
		t.Fatal("expected traversal rejection")
	}
	if _, err := safeJoin(root, "/etc/passwd"); err == nil {
		t.Fatal("expected absolute path rejection")
	}
}

func TestVerifyClean(t *testing.T) {
	loadContent := "<?php // load" + nlB
	root := makeInstall(t, "6.0", map[string]string{"wp-load.php": loadContent})
	manifest := map[string]string{
		"wp-load.php":             md5hex(loadContent),
		"wp-includes/version.php": md5hex(versionPHP("6.0")),
	}
	srv := manifestServer(t, "6.0", manifest, nil)
	defer srv.Close()

	res := verifyIsolated(t, context.Background(), root, "en_US", srv.URL)
	if !res.Verified {
		t.Fatalf("not verified: %s", res.Reason)
	}
	if res.CleanCount != 2 || len(res.ModifiedFiles) != 0 || len(res.MissingFiles) != 0 {
		t.Fatalf("clean=%d modified=%d missing=%d", res.CleanCount, len(res.ModifiedFiles), len(res.MissingFiles))
	}
}

func TestVerifyModifiedAndMissing(t *testing.T) {
	loadContent := "<?php // load" + nlB
	root := makeInstall(t, "6.0", map[string]string{"wp-load.php": "tampered"})
	manifest := map[string]string{
		"wp-load.php":             md5hex(loadContent),
		"wp-includes/version.php": md5hex(versionPHP("6.0")),
		"wp-admin/admin.php":      md5hex("absent"),
	}
	srv := manifestServer(t, "6.0", manifest, nil)
	defer srv.Close()

	res := verifyIsolated(t, context.Background(), root, "en_US", srv.URL)
	if !res.Verified {
		t.Fatalf("not verified: %s", res.Reason)
	}
	if len(res.ModifiedFiles) != 1 || res.ModifiedFiles[0].Path != "wp-load.php" {
		t.Fatalf("modified=%v", res.ModifiedFiles)
	}
	if len(res.MissingFiles) != 1 || res.MissingFiles[0].Path != "wp-admin/admin.php" {
		t.Fatalf("missing=%v", res.MissingFiles)
	}
}

func TestVerifyUnavailableAPI(t *testing.T) {
	root := makeInstall(t, "6.0", nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	res := verifyIsolated(t, context.Background(), root, "en_US", srv.URL)
	if res.Verified {
		t.Fatal("should not be verified when API fails")
	}
	if res.Reason == "" {
		t.Fatal("expected a reason")
	}
}

// verifyIsolated runs verifyWithBase with a per-test persistent-cache
// location. Ephemeral httptest ports can be recycled across runs, and a
// leftover disk-cache entry keyed by a recycled base URL would make
// manifest-fetch tests nondeterministic (observed as an intermittent
// TestVerifyInvalidJSON flake).
func verifyIsolated(t *testing.T, ctx context.Context, root, localeOverride, base string) Result {
	t.Helper()
	t.Setenv("RONDA_CACHE_DIR", t.TempDir())
	return verifyFull(ctx, root, localeOverride, base, false)
}

func TestVerifyInvalidJSON(t *testing.T) {
	root := makeInstall(t, "6.0", nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	}))
	defer srv.Close()

	res := verifyIsolated(t, context.Background(), root, "en_US", srv.URL)
	if res.Verified {
		t.Fatal("should not verify on invalid JSON")
	}
}

func TestVerifyNoVersion(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "wp-load.php"), "x")
	res := verifyIsolated(t, context.Background(), root, "", "http://invalid")
	if res.Verified {
		t.Fatal("should not verify without version")
	}
}

func TestVerifyExtraFile(t *testing.T) {
	loadContent := "<?php // load" + nlB
	root := makeInstall(t, "6.0", map[string]string{
		"wp-load.php":           loadContent,
		"wp-includes/rogue.php": "<?php evil();" + nlB,
	})
	manifest := map[string]string{
		"wp-load.php":             md5hex(loadContent),
		"wp-includes/version.php": md5hex(versionPHP("6.0")),
	}
	srv := manifestServer(t, "6.0", manifest, nil)
	defer srv.Close()

	res := verifyIsolated(t, context.Background(), root, "en_US", srv.URL)
	found := false
	for _, f := range res.ExtraFiles {
		if f == "wp-includes/rogue.php" {
			found = true
		}
	}
	if !found {
		t.Fatalf("rogue file not reported as extra: %v", res.ExtraFiles)
	}
}

func TestParseManifestRejectsBadChecksum(t *testing.T) {
	body, err := json.Marshal(map[string]interface{}{
		"checksums": map[string]interface{}{
			"6.0": map[string]string{"a.php": "notamd5"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseManifest(body, "6.0"); err == nil {
		t.Fatal("expected error for invalid checksum")
	}
}

func TestDetectVersionIgnoresCommentedVersion(t *testing.T) {
	root := t.TempDir()
	src := "<?php" + nlB +
		"// " + dollar() + "wp_version = '9.9';" + nlB +
		"/* " + dollar() + "wp_version = '8.8'; */" + nlB +
		dollar() + "wp_version = '6.0';" + nlB
	writeFile(t, filepath.Join(root, "wp-includes", "version.php"), src)
	if v := DetectVersion(root); v != "6.0" {
		t.Fatalf("version=%q, want 6.0 with commented assignments ignored", v)
	}
}

func TestCacheAvoidsSecondRequest(t *testing.T) {
	loadContent := "<?php // load" + nlB
	root := makeInstall(t, "6.0", map[string]string{"wp-load.php": loadContent})
	manifest := map[string]string{
		"wp-load.php":             md5hex(loadContent),
		"wp-includes/version.php": md5hex(versionPHP("6.0")),
	}
	var hits int32
	srv := manifestServer(t, "6.0", manifest, &hits)
	defer srv.Close()

	verifyWithBase(context.Background(), root, "en_US", srv.URL)
	verifyWithBase(context.Background(), root, "en_US", srv.URL)
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("expected 1 API hit, got %d", hits)
	}
}
