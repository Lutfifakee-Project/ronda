package refcheck

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/Lutfifakee-Project/ronda/internal/official"
)

// newTestClient returns an official client pointed at a local TLS test
// server. Only the transport changes; every allowlist and safety rule of the
// official client stays active, and TLS verification remains enabled.
func newTestClient(t *testing.T, srv *httptest.Server) *official.Client {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	c := official.NewClient([]official.Host{{Host: u.Host}}, official.DefaultMaxResponseBytes)
	base := srv.Client().Transport.(*http.Transport)
	c.SetTestTransport(&http.Transport{TLSClientConfig: base.TLSClientConfig})
	return c
}

func manifestFrom(t *testing.T, root string, files map[string]string) map[string]string {
	t.Helper()
	out := make(map[string]string, len(files))
	for rel, content := range files {
		sum := sha256.Sum256([]byte(content))
		out[rel] = hex.EncodeToString(sum[:])
	}
	_ = root
	return out
}

func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, content := range files {
		abs := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(abs, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func stateOf(res Result, path string) (FileState, bool) {
	all := append(append(append([]FileState{}, res.Modified...), res.Missing...), res.Unverified...)
	for _, s := range all {
		if s.Path == path {
			return s, true
		}
	}
	return FileState{}, false
}

func TestCompareCleanInstall(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"core/a.php": "<?php",
		"core/b.php": "<?php",
		"index.php":  "root",
	}
	writeTree(t, root, files)
	manifest := manifestFrom(t, root, files)

	res, err := Compare(context.Background(), root, manifest, Policy{StrictDirs: []string{"core"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.TotalFiles != 3 || res.CleanCount != 3 || len(res.Modified) != 0 || len(res.Missing) != 0 {
		t.Fatalf("res %+v", res)
	}
	if len(res.CleanFiles) != 3 {
		t.Fatalf("CleanFiles %v", res.CleanFiles)
	}
}

func TestCompareModifiedAndConfigurable(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"core/a.php": "original",
		".htaccess":  "original",
	}
	writeTree(t, root, files)
	manifest := manifestFrom(t, root, map[string]string{
		"core/a.php": "original",
		".htaccess":  "original",
	})
	// Local edits after the reference snapshot.
	writeTree(t, root, map[string]string{
		"core/a.php": "tampered",
		".htaccess":  "RewEngine on",
	})

	policy := Policy{ConfigurableFiles: map[string]bool{".htaccess": true}}
	res, err := Compare(context.Background(), root, manifest, policy)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := stateOf(res, "core/a.php")
	if !ok || st.Status != StatusModified {
		t.Fatalf("core/a.php %+v", st)
	}
	if st.ActualSHA256 == "" || st.ActualSHA256 == st.ExpectedSHA256 {
		t.Fatalf("digests not recorded: %+v", st)
	}
	st, ok = stateOf(res, ".htaccess")
	if !ok || st.Status != StatusUnverified {
		t.Fatalf(".htaccess must downgrade to UNVERIFIED, got %+v", st)
	}
}

func TestCompareMissingAndOptional(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"core/a.php":             "a",
		"installation/setup.php": "setup",
	}
	writeTree(t, root, files)
	manifest := manifestFrom(t, root, files)
	if err := os.Remove(filepath.Join(root, "installation", "setup.php")); err != nil {
		t.Fatal(err)
	}
	// core/a.php is missing too.
	if err := os.Remove(filepath.Join(root, "core", "a.php")); err != nil {
		t.Fatal(err)
	}

	policy := Policy{OptionalPrefixes: []string{"installation"}}
	res, err := Compare(context.Background(), root, manifest, policy)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := stateOf(res, "installation/setup.php")
	if !ok || st.Status != StatusUnverified {
		t.Fatalf("installation/setup.php should be UNVERIFIED, got %+v", st)
	}
	st, ok = stateOf(res, "core/a.php")
	if !ok || st.Status != StatusMissing {
		t.Fatalf("core/a.php should be MISSING, got %+v", st)
	}
}

func TestCompareUnexpectedFiles(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{"core/a.php": "a"}
	writeTree(t, root, files)
	manifest := manifestFrom(t, root, files)
	writeTree(t, root, map[string]string{
		"core/rogue.php":        "rogue",
		"core/vendor/cache.txt": "cache",
		"modules/custom/x.php":  "contrib", // outside strict dirs: not flagged
	})

	policy := Policy{
		StrictDirs:        []string{"core"},
		IgnoreNames:       map[string]bool{"cache.txt": true},
		RootExtra:         true,
		RootExtraExcluded: map[string]bool{"configuration.php": true},
	}
	res, err := Compare(context.Background(), root, manifest, policy)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Unexpected) != 1 || res.Unexpected[0] != "core/rogue.php" {
		t.Fatalf("Unexpected %v", res.Unexpected)
	}
	// Root extra: "stray.txt" reported, "configuration.php" excluded.
	writeTree(t, root, map[string]string{"stray.txt": "s", "configuration.php": "c"})
	res, err = Compare(context.Background(), root, manifest, policy)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range res.Unexpected {
		if p == "stray.txt" {
			found = true
		}
		if p == "configuration.php" {
			t.Fatal("root extra exclusion failed")
		}
	}
	if !found {
		t.Fatalf("stray.txt not reported: %v", res.Unexpected)
	}
}

func TestCompareRejectsUnsafeManifestPath(t *testing.T) {
	root := t.TempDir()
	manifest := map[string]string{"../escape.php": "deadbeef"}
	res, err := Compare(context.Background(), root, manifest, Policy{})
	if err != nil {
		t.Fatal(err)
	}
	st, ok := stateOf(res, "../escape.php")
	if !ok || st.Status != StatusUnverified || st.Reason == "" {
		t.Fatalf("unsafe path must be UNVERIFIED with reason, got %+v ok=%v", st, ok)
	}
}

func TestCompareSymlinkEscapeIsUnverified(t *testing.T) {
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(root, "core")); err != nil {
		t.Skip("symlinks unavailable")
	}
	manifest := map[string]string{"core/data.php": "deadbeef"}
	res, err := Compare(context.Background(), root, manifest, Policy{})
	if err != nil {
		t.Fatal(err)
	}
	st, ok := stateOf(res, "core/data.php")
	if !ok || st.Status != StatusUnverified {
		t.Fatalf("symlink escape must be UNVERIFIED, got %+v ok=%v", st, ok)
	}
}

func TestStoreRoundTripAndCorruption(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "refs")
	store := NewStoreAt(dir)
	ref := Reference{
		Platform:   "drupal",
		Version:    "10.3.5",
		Algorithm:  "sha256",
		Digest:     "abcdef",
		ArchiveURL: "https://ftp.drupal.org/files/projects/drupal-10.3.5.tar.gz",
		Manifest:   Manifest{"core/a.php": shaOfContent("a")},
	}
	store.Put(ref)

	got, ok := store.Get("drupal", "10.3.5", ref.ArchiveURL, "abcdef")
	if !ok || len(got.Manifest) != 1 {
		t.Fatalf("cache hit failed: ok=%v got=%+v", ok, got)
	}
	if _, ok := store.Get("drupal", "10.3.6", ref.ArchiveURL, "abcdef"); ok {
		t.Fatal("wrong version must miss")
	}
	if _, ok := store.Get("drupal", "10.3.5", ref.ArchiveURL, "ffffff"); ok {
		t.Fatal("wrong digest must miss")
	}

	// Corruption: flip bytes inside the cached file.
	key := CacheKey(ref.Platform, ref.Version, ref.ArchiveURL, ref.Digest)
	path := filepath.Join(dir, key+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, []byte("garbage")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Get("drupal", "10.3.5", ref.ArchiveURL, "abcdef"); ok {
		t.Fatal("corrupted cache entry must miss")
	}

	// Tampered manifest path inside a well-formed entry must miss too.
	tampered := ref
	tampered.Digest = "ffffff"
	tampered.Manifest = Manifest{"../evil.php": shaOfContent("a")}
	store.Put(tampered)
	key2 := CacheKey(tampered.Platform, tampered.Version, tampered.ArchiveURL, tampered.Digest)
	if key2 == key {
		t.Fatal("digest differs so keys must differ")
	}
	if _, ok := store.Get("drupal", "10.3.5", tampered.ArchiveURL, "ffffff"); ok {
		t.Fatal("unsafe cached manifest path must miss")
	}
	// The original entry, rewritten after its corruption above, must load.
	store.Put(ref)
	if _, ok := store.Get("drupal", "10.3.5", ref.ArchiveURL, "abcdef"); !ok {
		t.Fatal("rewritten original entry lost")
	}
}

func TestFetchArchiveVerifiesDigests(t *testing.T) {
	content := "official archive bytes"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte(content)); err != nil {
			t.Errorf("write: %v", err)
		}
	}))
	defer srv.Close()

	client := newTestClient(t, srv)
	arch, err := FetchArchive(context.Background(), client, srv.URL+"/drupal.tar.gz", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer arch.Cleanup()
	if arch.Size != int64(len(content)) {
		t.Fatalf("size %d", arch.Size)
	}
	sum := sha256.Sum256([]byte(content))
	shaHex := hex.EncodeToString(sum[:])

	if err := arch.VerifyDigests([]Digest{{Algorithm: "sha256", Hex: shaHex}}); err != nil {
		t.Fatalf("digest should match: %v", err)
	}
	if err := arch.VerifyDigests([]Digest{{Algorithm: "sha256", Hex: "0000"}}); err == nil {
		t.Fatal("mismatched digest must fail")
	}
	if err := arch.VerifyDigests(nil); err == nil {
		t.Fatal("empty digest list must fail closed")
	}
	if _, err := os.Stat(arch.Path); err == nil {
		arch.Cleanup()
	} else {
		t.Fatal("temp archive missing before cleanup")
	}
}

func shaOfContent(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}
