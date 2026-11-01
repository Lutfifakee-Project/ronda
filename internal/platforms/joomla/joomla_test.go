package joomla

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Lutfifakee-Project/ronda/internal/official"
	"github.com/Lutfifakee-Project/ronda/internal/platforms/refcheck"
)

const testVersion = "5.2.0"

// fakeServer serves a downloads page, a flat tar.gz archive and the GitHub
// release metadata endpoint.
type fakeServer struct {
	srv    *httptest.Server
	client *official.Client
	md5    string
	sha1   string
	// publishedMD5/publishedSHA1 override the page values (tamper tests).
	publishedMD5  string
	publishedSHA1 string
	// githubSHA256 is the SHA-256 the fake GitHub release publishes for the
	// full-package tar.gz ("" makes the endpoint unavailable). githubBody
	// replaces the generated release body when set.
	githubSHA256 string
	githubBody   string
}

func newFakeServer(t *testing.T, files map[string]string) *fakeServer {
	t.Helper()

	dir := t.TempDir()
	archPath := filepath.Join(dir, "Joomla_5-2-0-Stable-Full_Package.tar.gz")
	f, err := os.Create(archPath)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sortStrings(names)
	for _, n := range names {
		body := files[n]
		if err := tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(body))}); err != nil {
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
	md5Sum := md5.Sum(archiveBytes)
	sha1Sum := sha1.Sum(archiveBytes)
	sha256Sum := sha256.Sum256(archiveBytes)

	fs := &fakeServer{
		md5:           hex.EncodeToString(md5Sum[:]),
		sha1:          hex.EncodeToString(sha1Sum[:]),
		publishedMD5:  hex.EncodeToString(md5Sum[:]),
		publishedSHA1: hex.EncodeToString(sha1Sum[:]),
		githubSHA256:  hex.EncodeToString(sha256Sum[:]),
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/cms/joomla5/5-2-0":
			if _, err := w.Write([]byte(fs.downloadsPage(r.Host))); err != nil {
				t.Errorf("write: %v", err)
			}
		case r.URL.Path == "/cms/joomla5/5-2-0/Joomla_5-2-0-Stable-Full_Package.tar.gz":
			// Mirror the official 303 redirect behaviour to the S3 bucket.
			target := "https://s3-us-west-2.amazonaws.com/joomla-official-downloads/joomladownloads/joomla5/Joomla_5.2.0-Stable-Full_Package.tar.gz"
			http.Redirect(w, r, target, http.StatusFound)
		case r.URL.Path == "/joomla-official-downloads/joomladownloads/joomla5/Joomla_5.2.0-Stable-Full_Package.tar.gz":
			// After the transport reroute the Host header is the test
			// server; the bucket path identifies the mirrored object.
			if _, err := w.Write(archiveBytes); err != nil {
				t.Errorf("write: %v", err)
			}
		case r.URL.Path == "/repos/joomla/joomla-cms/releases/tags/5.2.0":
			if fs.githubSHA256 == "" && fs.githubBody == "" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			body := fs.githubBody
			if body == "" {
				body = fs.githubReleaseBody()
			}
			payload, err := json.Marshal(struct {
				TagName string `json:"tag_name"`
				Body    string `json:"body"`
			}{TagName: testVersion, Body: body})
			if err != nil {
				t.Errorf("marshal: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			if _, err := w.Write(payload); err != nil {
				t.Errorf("write: %v", err)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)

	// Route both hostnames to the same test server by rewriting the
	// allowlist and pinning the S3 host in the client's DialTLS via the
	// test transport of the primary server.
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := official.NewClient([]official.Host{
		{Host: u.Host},
		{Host: "s3-us-west-2.amazonaws.com", PathPrefix: "/joomla-official-downloads/"},
	}, official.DefaultMaxResponseBytes)
	client.SetTestTransport(&s3RerouteTransport{base: srv.Client().Transport.(*http.Transport), testHost: u.Host})

	fs.srv = srv
	fs.client = client
	return fs
}

// s3RerouteTransport sends requests for the official S3 mirror host to the
// local test server instead, keeping the allowlist semantics intact.
type s3RerouteTransport struct {
	base     *http.Transport
	testHost string
}

func (s *s3RerouteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host == "s3-us-west-2.amazonaws.com" {
		req = req.Clone(req.Context())
		req.URL.Host = s.testHost
	}
	return s.base.RoundTrip(req)
}

func (fs *fakeServer) downloadsPage(host string) string {
	const tpl = `<div class="ars-item-8778 well"><div class="page-header"><h3 dir="ltr"> Joomla! %s Full Package (.zip) </h3></div>
<div class="ars-item-description" dir="ltr"><p>zip package</p></div>
<dl><dt>MD5 Signature</dt><dd>%s</dd><dt>SHA1 Signature</dt><dd>%s</dd></dl>
<p class="readmore"><a href="/cms/joomla5/5-2-0/Joomla_5-2-0-Stable-Full_Package.zip" class="btn">Download now</a></p></div>
<div class="ars-item-8779 well"><div class="page-header"><h3 dir="ltr"> Joomla! %s Full Package (.tar.gz) </h3></div>
<div class="ars-item-description" dir="ltr"><p>This is the full download package for Joomla! %s</p></div>
<dl><dt>MD5 Signature</dt><dd>%s</dd><dt>SHA1 Signature</dt><dd>%s</dd></dl>
<div><p class="readmore"><a href="/cms/joomla5/5-2-0/Joomla_5-2-0-Stable-Full_Package.tar.gz?format=gz" class="btn btn-primary"> Download now </a></p></div></div>`
	return fmt.Sprintf(tpl, testVersion, "00000000000000000000000000000000", "1111111111111111111111111111111111111111",
		testVersion, testVersion, fs.publishedMD5, fs.publishedSHA1)
}

func (fs *fakeServer) overrideBases(t *testing.T) {
	t.Helper()
	origDownloads := downloadsBase
	origGitHub := githubAPIBase
	downloadsBase = fs.srv.URL
	githubAPIBase = fs.srv.URL
	t.Cleanup(func() {
		downloadsBase = origDownloads
		githubAPIBase = origGitHub
	})
}

// githubReleaseBody mirrors the real joomla/joomla-cms release body shape:
// a New Installations SHA-256 table followed by an update-package table that
// must never leak into the full-package parse.
func (fs *fakeServer) githubReleaseBody() string {
	const fakeZip = "1111111111111111111111111111111111111111111111111111111111111111"
	const fakeZst = "2222222222222222222222222222222222222222222222222222222222222222"
	const fakeUpdate = "3333333333333333333333333333333333333333333333333333333333333333"
	return "Release notes\n\n" +
		"| | New Joomla! Installations | SHA-256 Checksums |\n" +
		"|---|---|---|\n" +
		"| | [ZIP Archive (.zip)](https://github.com/joomla/joomla-cms/releases/download/5.2.0/Joomla_5.2.0-Stable-Full_Package.zip) | `" + fakeZip + "` |\n" +
		"| | [GNU Zip Archive (.tar.gz)](https://github.com/joomla/joomla-cms/releases/download/5.2.0/Joomla_5.2.0-Stable-Full_Package.tar.gz) | `" + fs.githubSHA256 + "` |\n" +
		"| | [Zstandard Archive (.tar.zst)](https://github.com/joomla/joomla-cms/releases/download/5.2.0/Joomla_5.2.0-Stable-Full_Package.tar.zst) | `" + fakeZst + "` |\n" +
		"\n| | Update from a previous version | SHA-256 Checksums |\n" +
		"|---|---|---|\n" +
		"| | [GNU Zip Archive (.tar.gz)](https://github.com/joomla/joomla-cms/releases/download/5.2.0/Joomla_5.2.0-Stable-Update_Package.tar.gz) | `" + fakeUpdate + "` |\n"
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

// baseArchive is a minimal flat Joomla archive.
func baseArchive() map[string]string {
	return map[string]string{
		"libraries/src/Version.php":                "<?php final class Version { public const MAJOR_VERSION = 5; public const MINOR_VERSION = 2; public const PATCH_VERSION = 0; public const EXTRA_VERSION = ''; }",
		"administrator/manifests/files/joomla.xml": "<?xml version=\"1.0\"?><extension><name>files_joomla</name><version>5.2.0</version></extension>",
		"libraries/joomla/factory.php":             "<?php",
		"includes/defines.php":                     "<?php",
		"index.php":                                "<?php",
		"installation/index.php":                   "<?php",
		"cache/index.html":                         "<!DOCTYPE html>",
		"htaccess.txt":                             "default",
	}
}

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

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestVerifyCleanInstall(t *testing.T) {
	fs := newFakeServer(t, baseArchive())
	fs.overrideBases(t)
	root := installFrom(t, baseArchive())
	store := refcheck.NewStoreAt(filepath.Join(t.TempDir(), "refs"))

	res := Verify(context.Background(), root, testOpts(fs, store))
	if !res.Verified {
		t.Fatalf("not verified: %s (sources %+v)", res.Reason, res.VersionSources)
	}
	if res.Version != testVersion {
		t.Fatalf("version %q", res.Version)
	}
	if res.TotalFiles != 8 || res.CleanCount != 8 {
		t.Fatalf("total=%d clean=%d", res.TotalFiles, res.CleanCount)
	}
	if res.Reference.Cached {
		t.Fatal("first fetch must not be cached")
	}
	if !contains(res.Reference.Algorithm, "md5") || !contains(res.Reference.Algorithm, "sha1") {
		t.Fatalf("algorithm %q", res.Reference.Algorithm)
	}

	// Cached second run.
	res2 := Verify(context.Background(), root, testOpts(fs, store))
	if !res2.Verified || !res2.Reference.Cached {
		t.Fatalf("cached run: %+v", res2)
	}
	if res2.TotalFiles != 8 || res2.CleanCount != 8 {
		t.Fatalf("cached counts total=%d clean=%d", res2.TotalFiles, res2.CleanCount)
	}
}

func TestVerifyModifiedMissingOptionalUnexpected(t *testing.T) {
	fs := newFakeServer(t, baseArchive())
	fs.overrideBases(t)
	files := baseArchive()
	root := installFrom(t, files)

	if err := os.WriteFile(filepath.Join(root, "libraries", "joomla", "factory.php"), []byte("<?php hacked"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "includes", "defines.php")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "installation", "index.php")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "libraries", "rogue.php"), []byte("rogue"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Extension areas: extra files are conservatively not reported.
	if err := os.MkdirAll(filepath.Join(root, "components", "com_custom"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "components", "com_custom", "x.php"), []byte("third-party"), 0o644); err != nil {
		t.Fatal(err)
	}

	res := Verify(context.Background(), root, testOpts(fs, refcheck.NewStoreAt(filepath.Join(t.TempDir(), "refs"))))
	if !res.Verified {
		t.Fatalf("not verified: %s", res.Reason)
	}
	st, ok := findState(res, "libraries/joomla/factory.php")
	if !ok || st.Status != "MODIFIED" {
		t.Fatalf("factory.php %+v", st)
	}
	st, ok = findState(res, "includes/defines.php")
	if !ok || st.Status != "MISSING" {
		t.Fatalf("defines.php should be MISSING, got %+v", st)
	}
	st, ok = findState(res, "installation/index.php")
	if !ok || st.Status != "UNVERIFIED" {
		t.Fatalf("installation/index.php should be UNVERIFIED (optional), got %+v", st)
	}
	if len(res.Unexpected) != 1 || res.Unexpected[0] != "libraries/rogue.php" {
		t.Fatalf("unexpected %v", res.Unexpected)
	}
}

func TestVerifyVersionConflict(t *testing.T) {
	fs := newFakeServer(t, baseArchive())
	fs.overrideBases(t)
	files := baseArchive()
	// Manifest disagrees with Version.php.
	files["administrator/manifests/files/joomla.xml"] = "<?xml version=\"1.0\"?><extension><version>5.1.4</version></extension>"
	root := installFrom(t, files)

	res := Verify(context.Background(), root, testOpts(fs, refcheck.NewStoreAt(filepath.Join(t.TempDir(), "refs"))))
	if res.Verified || !contains(res.Reason, "conflicting") {
		t.Fatalf("conflict must refuse: %+v", res)
	}
	if len(res.VersionSources) < 2 {
		t.Fatalf("sources kept separate: %+v", res.VersionSources)
	}
}

func TestVerifyMissingVersionMarker(t *testing.T) {
	fs := newFakeServer(t, baseArchive())
	fs.overrideBases(t)
	files := baseArchive()
	// Version.php present but unparseable; manifest without a version.
	files["libraries/src/Version.php"] = "<?php final class Version { }"
	files["administrator/manifests/files/joomla.xml"] = "<?xml version=\"1.0\"?><extension><name>files_joomla</name></extension>"
	root := installFrom(t, files)

	res := Verify(context.Background(), root, testOpts(fs, refcheck.NewStoreAt(filepath.Join(t.TempDir(), "refs"))))
	if res.Verified || !contains(res.Reason, "could not read the Joomla version") {
		t.Fatalf("unparseable markers must refuse: %+v", res)
	}
}

func TestVerifyDevBuildRefused(t *testing.T) {
	fs := newFakeServer(t, baseArchive())
	fs.overrideBases(t)
	files := baseArchive()
	files["libraries/src/Version.php"] = "<?php final class Version { public const MAJOR_VERSION = 5; public const MINOR_VERSION = 3; public const PATCH_VERSION = 0; public const EXTRA_VERSION = '-dev'; }"
	files["administrator/manifests/files/joomla.xml"] = "<?xml version=\"1.0\"?><extension><version>5.3.0-dev</version></extension>"
	root := installFrom(t, files)

	res := Verify(context.Background(), root, testOpts(fs, refcheck.NewStoreAt(filepath.Join(t.TempDir(), "refs"))))
	if res.Verified || !contains(res.Reason, "not a stable release") {
		t.Fatalf("dev build must refuse: %+v", res)
	}
}

func TestVerifyLegacyVersionPHP(t *testing.T) {
	fs := newFakeServer(t, baseArchive())
	fs.overrideBases(t)
	files := baseArchive()
	delete(files, "libraries/src/Version.php")
	files["libraries/cms/version/version.php"] = "<?php class JVersion { public $RELEASE = '3.10'; public $DEV_LEVEL = '12'; public $DEV_STATUS = 'Stable'; }"
	files["administrator/manifests/files/joomla.xml"] = "<?xml version=\"1.0\"?><extension><version>3.10.12</version></extension>"
	// The fake server only serves 5.2.0 pages, so verification will fail
	// on the page fetch; version detection itself is what we assert here.
	root := installFrom(t, files)
	sources := DetectVersion(root)
	if len(sources) != 2 || sources[0].Value != "3.10.12" {
		t.Fatalf("legacy detection: %+v", sources)
	}
	v, why := EstablishVersion(sources)
	if v != "3.10.12" || why != "" {
		t.Fatalf("v=%q why=%q", v, why)
	}
}

func TestVerifyDigestTamperRefused(t *testing.T) {
	fs := newFakeServer(t, baseArchive())
	fs.overrideBases(t)
	// Publish a wrong MD5 on the page.
	fs.publishedMD5 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	root := installFrom(t, baseArchive())

	res := Verify(context.Background(), root, testOpts(fs, refcheck.NewStoreAt(filepath.Join(t.TempDir(), "refs"))))
	if res.Verified || !contains(res.Reason, "authentication failed") {
		t.Fatalf("tampered digest must refuse: %+v", res)
	}
}

func TestVerifyOfflineHitAndMiss(t *testing.T) {
	fs := newFakeServer(t, baseArchive())
	fs.overrideBases(t)
	root := installFrom(t, baseArchive())
	store := refcheck.NewStoreAt(filepath.Join(t.TempDir(), "refs"))

	res := Verify(context.Background(), root, VerifyOptions{Offline: true, Store: store, Client: fs.client})
	if res.Verified || !contains(res.Reason, "offline") {
		t.Fatalf("offline miss must be UNVERIFIED: %+v", res)
	}
	res = Verify(context.Background(), root, testOpts(fs, store))
	if !res.Verified {
		t.Fatalf("online failed: %s", res.Reason)
	}
	res = Verify(context.Background(), root, VerifyOptions{Offline: true, Store: store, Client: fs.client})
	if !res.Verified || !res.Reference.Cached {
		t.Fatalf("offline cache hit must verify: %+v", res)
	}
}

func TestParseDownloadsPageRealShape(t *testing.T) {
	fs := newFakeServer(t, baseArchive())
	fs.overrideBases(t)
	pub, err := parseDownloadsPage([]byte(fs.downloadsPage("127.0.0.1:1")), testVersion)
	if err != nil {
		t.Fatal(err)
	}
	if pub.MD5 != fs.publishedMD5 || pub.SHA1 != fs.publishedSHA1 {
		t.Fatalf("pub %+v", pub)
	}
	if !strings.HasPrefix(pub.ArchiveURL, fs.srv.URL+"/cms/joomla5/5-2-0/") ||
		!strings.HasSuffix(pub.ArchiveURL, "Joomla_5-2-0-Stable-Full_Package.tar.gz") {
		t.Fatalf("url %q", pub.ArchiveURL)
	}
}

func TestIsJoomla(t *testing.T) {
	root := installFrom(t, baseArchive())
	if !IsJoomla(root) {
		t.Fatal("joomla root not detected")
	}
	if IsJoomla(t.TempDir()) {
		t.Fatal("empty dir detected as joomla")
	}
}
