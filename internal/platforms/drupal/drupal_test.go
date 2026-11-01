package drupal

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/Lutfifakee-Project/ronda/internal/official"
	"github.com/Lutfifakee-Project/ronda/internal/platforms/refcheck"
)

const testVersion = "9.5.10"

// fakeServer serves a release page and a tar.gz archive for testVersion.
// The archive contents are supplied by the test through the returned handle.
type fakeServer struct {
	srv    *httptest.Server
	client *official.Client
	files  map[string]string // archive content (paths inside drupal-<ver>/)
	sha    string
}

func newFakeServer(t *testing.T, files map[string]string, pageHTML string) *fakeServer {
	t.Helper()

	// Build the archive.
	dir := t.TempDir()
	archPath := filepath.Join(dir, "drupal-"+testVersion+".tar.gz")
	f, err := os.Create(archPath)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "drupal-" + testVersion + "/", Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sortStrings(names)
	for _, n := range names {
		body := files[n]
		if err := tw.WriteHeader(&tar.Header{Name: "drupal-" + testVersion + "/" + n, Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	archiveBytes, err := os.ReadFile(archPath)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(archiveBytes)
	shaHex := hex.EncodeToString(sum[:])

	fs := &fakeServer{files: files, sha: shaHex}

	_ = pageHTML // custom pages are injected via releasePage handling

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/project/drupal/releases/"+testVersion:
			// The page is rendered lazily so its links carry the real host.
			if _, err := w.Write([]byte(fs.releasePage(r.Host))); err != nil {
				t.Errorf("write: %v", err)
			}
		case r.URL.Path == "/files/projects/drupal-"+testVersion+".tar.gz":
			if _, err := w.Write(archiveBytes); err != nil {
				t.Errorf("write: %v", err)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := official.NewClient([]official.Host{{Host: u.Host}}, official.DefaultMaxResponseBytes)
	base := srv.Client().Transport.(*http.Transport)
	client.SetTestTransport(&http.Transport{TLSClientConfig: base.TLSClientConfig})

	fs.srv = srv
	fs.client = client
	return fs
}

func (fs *fakeServer) releasePage(host string) string {
	const tpl = `<div class="views-row views-row-1">
<span><a href="%s/files/projects/drupal-%s.tar.gz" class="download">Download</a></span>
<span class="field-content">1.2 MB</span>
<div class="views-field views-field-field-release-file-sha256"><span class="views-label">SHA-256: </span><span class="field-content hash">%s</span></div>
</div>
<div class="views-row views-row-2">
<span><a href="%s/files/projects/drupal-%s.zip" class="download">Download zip</a></span>
<div class="views-field views-field-field-release-file-sha256"><span class="views-label">SHA-256: </span><span class="field-content hash">%s</span></div>
</div>`
	u := "https://" + host
	return fmt.Sprintf(tpl, u, testVersion, fs.sha, u, testVersion, anotherHash)
}

const anotherHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func (fs *fakeServer) overrideBases(t *testing.T) {
	t.Helper()
	origPage, origArch := releasePageBase, archiveBase
	releasePageBase = fs.srv.URL + "/project/drupal/releases/"
	archiveBase = fs.srv.URL + "/files/projects/"
	t.Cleanup(func() {
		releasePageBase, archiveBase = origPage, origArch
	})
}

func sortStrings(s []string) {
	for i := 0; i < len(s); i++ {
		for j := i + 1; j < len(s); j++ {
			if s[j] < s[i] {
				s[i], s[j] = s[j], s[i]
			}
		}
	}
}

// baseArchive is the minimal official archive used by the fixture tests.
func baseArchive() map[string]string {
	return map[string]string{
		"core/lib/Drupal.php":                "<?php namespace Drupal; const VERSION = '" + testVersion + "';",
		"core/index.php":                     "<?php",
		"core/misc/a.txt":                    "a",
		"vendor/pkg/pkg.php":                 "<?php",
		"sites/default/default.settings.php": "<?php",
		"index.php":                          "<?php",
		"autoload.php":                       "<?php",
		".htaccess":                          "default",
	}
}

// installFrom writes the archive files into a document root.
func installFrom(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		abs := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(abs, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func testOpts(fs *fakeServer, store *refcheck.Store) VerifyOptions {
	return VerifyOptions{Store: store, Client: fs.client}
}

func findState(res Result, path string) (FileState, bool) {
	all := append(append(append([]FileState{}, res.Modified...), res.Missing...), res.Unverified...)
	for _, s := range all {
		if s.Path == path {
			return s, true
		}
	}
	return FileState{}, false
}

func TestVerifyCleanTarballInstall(t *testing.T) {
	fs := newFakeServer(t, baseArchive(), "")
	fs.overrideBases(t)
	root := installFrom(t, baseArchive())
	store := refcheck.NewStoreAt(filepath.Join(t.TempDir(), "refs"))

	res := Verify(context.Background(), root, testOpts(fs, store))
	if !res.Verified {
		t.Fatalf("not verified: %s (sources %+v)", res.Reason, res.VersionSources)
	}
	if res.Version != testVersion || res.Layout != LayoutTarball {
		t.Fatalf("res %+v", res)
	}
	if res.TotalFiles != 8 || res.CleanCount != 8 {
		t.Fatalf("counts: total=%d clean=%d", res.TotalFiles, res.CleanCount)
	}
	if len(res.Modified)+len(res.Missing)+len(res.Unverified)+len(res.Unexpected) != 0 {
		t.Fatalf("unexpected findings: %+v", res)
	}
	if res.Reference.Cached {
		t.Fatal("first fetch must not be reported as cached")
	}
	if res.Reference.Digest != fs.sha {
		t.Fatalf("reference digest %q", res.Reference.Digest)
	}

	// Second verify: served from the persistent cache and still clean.
	res2 := Verify(context.Background(), root, testOpts(fs, store))
	if !res2.Verified || !res2.Reference.Cached {
		t.Fatalf("second run must hit the cache: %+v", res2)
	}
	if res2.TotalFiles != 8 || res2.CleanCount != 8 {
		t.Fatalf("cached counts: total=%d clean=%d", res2.TotalFiles, res2.CleanCount)
	}
}

func TestVerifyModifiedMissingUnexpected(t *testing.T) {
	fs := newFakeServer(t, baseArchive(), "")
	fs.overrideBases(t)
	files := baseArchive()
	root := installFrom(t, files)

	// Modify a core file, delete a core file, add an unexpected file,
	// edit a configurable file.
	if err := os.WriteFile(filepath.Join(root, "core", "index.php"), []byte("backdoor"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "core", "misc", "a.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "core", "rogue.php"), []byte("rogue"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".htaccess"), []byte("RewriteEngine On"), 0o644); err != nil {
		t.Fatal(err)
	}

	res := Verify(context.Background(), root, testOpts(fs, refcheck.NewStoreAt(filepath.Join(t.TempDir(), "refs"))))
	if !res.Verified {
		t.Fatalf("not verified: %s", res.Reason)
	}
	st, ok := findState(res, "core/index.php")
	if !ok || st.Status != "MODIFIED" {
		t.Fatalf("core/index.php %+v ok=%v", st, ok)
	}
	st, ok = findState(res, "core/misc/a.txt")
	if !ok || st.Status != "MISSING" {
		t.Fatalf("core/misc/a.txt %+v ok=%v", st, ok)
	}
	st, ok = findState(res, ".htaccess")
	if !ok || st.Status != "UNVERIFIED" {
		t.Fatalf(".htaccess must be UNVERIFIED, got %+v", st)
	}
	if len(res.Unexpected) != 1 || res.Unexpected[0] != "core/rogue.php" {
		t.Fatalf("unexpected %v", res.Unexpected)
	}
	if res.CleanCount != 5 {
		t.Fatalf("clean=%d want 5 (8 files: 1 modified, 1 missing, 1 configurable)", res.CleanCount)
	}
}

func TestVerifyComposerLayoutSkipsVendor(t *testing.T) {
	files := baseArchive()
	fs := newFakeServer(t, files, "")
	fs.overrideBases(t)

	// Composer project: docroot under web/, composer.lock one level up.
	project := t.TempDir()
	docroot := filepath.Join(project, "web")
	if err := os.MkdirAll(docroot, 0o755); err != nil {
		t.Fatal(err)
	}
	for rel, content := range files {
		abs := filepath.Join(docroot, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(abs, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	lock := `{"packages":[{"name":"drupal/core-recommended","version":"` + testVersion + `"},{"name":"symfony/http-foundation","version":"v6.4.0"}]}`
	if err := os.WriteFile(filepath.Join(project, "composer.lock"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	// A composer-managed vendor file that differs from the archive must
	// NOT be reported as modified core.
	if err := os.WriteFile(filepath.Join(docroot, "vendor", "pkg", "pkg.php"), []byte("<?php different"), 0o644); err != nil {
		t.Fatal(err)
	}

	store := refcheck.NewStoreAt(filepath.Join(t.TempDir(), "refs"))
	res := Verify(context.Background(), docroot, testOpts(fs, store))
	if !res.Verified {
		t.Fatalf("not verified: %s", res.Reason)
	}
	if res.Layout != LayoutComposer || res.ProjectRoot != project {
		t.Fatalf("layout=%q project=%q", res.Layout, res.ProjectRoot)
	}
	if len(res.Modified) != 0 {
		t.Fatalf("composer vendor must not be compared: %+v", res.Modified)
	}
	if res.CleanCount != 3 || res.SkippedCount != 5 {
		t.Fatalf("clean=%d skipped=%d (core-only compare)", res.CleanCount, res.SkippedCount)
	}
	found := false
	for _, s := range res.SkippedAreas {
		if contains(s, "vendor") {
			found = true
		}
	}
	if !found {
		t.Fatalf("vendor skip not documented: %v", res.SkippedAreas)
	}
}

func TestVerifyVersionConflictUnverified(t *testing.T) {
	fs := newFakeServer(t, baseArchive(), "")
	fs.overrideBases(t)
	files := baseArchive()
	root := installFrom(t, files)
	// A conflicting composer.lock one level up.
	lock := `{"packages":[{"name":"drupal/core","version":"10.2.1"}]}`
	if err := os.WriteFile(filepath.Join(filepath.Dir(root), "composer.lock"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}

	res := Verify(context.Background(), root, testOpts(fs, refcheck.NewStoreAt(filepath.Join(t.TempDir(), "refs"))))
	if res.Verified {
		t.Fatal("conflicting version signals must not verify")
	}
	if !contains(res.Reason, "conflicting") {
		t.Fatalf("reason %q", res.Reason)
	}
	if len(res.VersionSources) < 2 {
		t.Fatalf("conflicting sources must be kept separate: %+v", res.VersionSources)
	}
}

func TestVerifyPreReleaseRefused(t *testing.T) {
	fs := newFakeServer(t, baseArchive(), "")
	fs.overrideBases(t)
	files := baseArchive()
	files["core/lib/Drupal.php"] = "<?php const VERSION = '11.0.0-beta1';"
	root := installFrom(t, files)

	res := Verify(context.Background(), root, testOpts(fs, refcheck.NewStoreAt(filepath.Join(t.TempDir(), "refs"))))
	if res.Verified || !contains(res.Reason, "not a stable release") {
		t.Fatalf("pre-release must be refused: %+v", res)
	}
}

func TestVerifyMissingArchiveUnverified(t *testing.T) {
	fs := newFakeServer(t, baseArchive(), "")
	fs.overrideBases(t)
	// Replace the archive route with a 404 by pointing archiveBase deeper.
	origArch := archiveBase
	archiveBase = fs.srv.URL + "/files/projects/missing/"
	t.Cleanup(func() { archiveBase = origArch })

	root := installFrom(t, baseArchive())
	res := Verify(context.Background(), root, testOpts(fs, refcheck.NewStoreAt(filepath.Join(t.TempDir(), "refs"))))
	if res.Verified || !contains(res.Reason, "unavailable") {
		t.Fatalf("missing archive must yield UNVERIFIED: %+v", res)
	}
}

func TestVerifyDigestMismatchRefused(t *testing.T) {
	// The server serves the real archive bytes but publishes a wrong hash
	// on its release page; the manifest must never be derived.
	files := baseArchive()
	fs2 := newFakeServerWithHash(t, files, "bbbb"+"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	fs2.overrideBases(t)

	root := installFrom(t, files)
	res := Verify(context.Background(), root, testOpts(fs2, refcheck.NewStoreAt(filepath.Join(t.TempDir(), "refs"))))
	if res.Verified || !contains(res.Reason, "authentication failed") {
		t.Fatalf("digest mismatch must refuse the manifest: %+v", res)
	}
}

func newFakeServerWithHash(t *testing.T, files map[string]string, publishedSHA string) *fakeServer {
	fs := newFakeServer(t, files, "")
	fs.sha = publishedSHA
	return fs
}

func TestVerifyOfflineCacheHitAndMiss(t *testing.T) {
	fs := newFakeServer(t, baseArchive(), "")
	fs.overrideBases(t)
	root := installFrom(t, baseArchive())
	store := refcheck.NewStoreAt(filepath.Join(t.TempDir(), "refs"))

	// Offline with an empty store: UNVERIFIED.
	res := Verify(context.Background(), root, VerifyOptions{Offline: true, Store: store, Client: fs.client})
	if res.Verified || !contains(res.Reason, "offline") {
		t.Fatalf("offline miss must be UNVERIFIED: %+v", res)
	}

	// Populate the cache online, then go offline again.
	res = Verify(context.Background(), root, testOpts(fs, store))
	if !res.Verified {
		t.Fatalf("online verify failed: %s", res.Reason)
	}
	res = Verify(context.Background(), root, VerifyOptions{Offline: true, Store: store, Client: fs.client})
	if !res.Verified || !res.Reference.Cached {
		t.Fatalf("offline cache hit must verify: %+v", res)
	}
}

func TestParseReleasePage(t *testing.T) {
	fs := newFakeServer(t, baseArchive(), "")
	page := []byte(fs.releasePage("127.0.0.1:1"))
	digest, err := parseReleasePage(page, testVersion)
	if err != nil {
		t.Fatal(err)
	}
	if digest != fs.sha {
		t.Fatalf("digest %q want %q", digest, fs.sha)
	}
	if _, err := parseReleasePage([]byte("<html>no files here</html>"), testVersion); err == nil {
		t.Fatal("empty page must fail")
	}
}

func TestDetectVersion(t *testing.T) {
	root := installFrom(t, baseArchive())
	sources := DetectVersion(root, "")
	if len(sources) != 1 || sources[0].Value != testVersion || sources[0].Source != "core/lib/Drupal.php" {
		t.Fatalf("sources %+v", sources)
	}
	v, why := EstablishVersion(sources)
	if v != testVersion || why != "" {
		t.Fatalf("v=%q why=%q", v, why)
	}
}

func TestIsDrupal(t *testing.T) {
	root := installFrom(t, baseArchive())
	if !IsDrupal(root) {
		t.Fatal("drupal root not detected")
	}
	if IsDrupal(t.TempDir()) {
		t.Fatal("empty dir detected as drupal")
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOfSub(s, sub) >= 0)
}

func indexOfSub(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
