package kernelintel

import (
	"bufio"
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Lutfifakee-Project/ronda/internal/kernel"
	"github.com/Lutfifakee-Project/ronda/internal/official"
)

// testFeedServer serves one fixture body over TLS with an allowlisted client
// whose transport trusts the httptest certificate.
func testFeedServer(t *testing.T, body string, requests *int) (*httptest.Server, *FeedClient) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*requests++
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	fc := NewFeedClient(NewCacheAt(t.TempDir()), false)
	fc.HTTP = trustedClient(t, srv)
	return srv, fc
}

// trustedClient builds an official.Client allowlisted to the test server and
// trusting its certificate. TLS verification itself stays enabled.
func trustedClient(t *testing.T, srv *httptest.Server) *official.Client {
	t.Helper()
	c := official.NewClient([]official.Host{{Host: hostOf(t, srv.URL)}}, 1<<20)
	rootCAs := srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	c.SetTestTransport(&http.Transport{TLSClientConfig: &tls.Config{RootCAs: rootCAs}})
	return c
}

func hostOf(t *testing.T, rawURL string) string {
	t.Helper()
	// httptest servers use http(s)://127.0.0.1:port; the official client
	// matches host:port exactly.
	u := strings.TrimPrefix(strings.TrimPrefix(rawURL, "https://"), "http://")
	return u
}

func TestLoadFeedFreshThenCacheHit(t *testing.T) {
	requests := 0
	srv, fc := testFeedServer(t, debianFixture, &requests)
	src := FeedSource{
		Provider: ProviderDebian, Distro: "debian", Release: "bookworm",
		URL: srv.URL + "/tracker/data/json", MaxBytes: 1 << 20,
		Freshness: time.Hour, Format: "debian-tracker",
	}
	ctx := context.Background()
	res, err := fc.LoadFeed(ctx, src)
	if err != nil {
		t.Fatal(err)
	}
	if res.State != TrustFresh || requests != 1 {
		t.Errorf("first load must fetch: state %s requests %d", res.State, requests)
	}
	if len(res.Entry.Advisories) == 0 {
		t.Fatal("parsed advisories missing")
	}

	// Second load inside the freshness window must hit the cache.
	res2, err := fc.LoadFeed(ctx, src)
	if err != nil {
		t.Fatal(err)
	}
	if requests != 1 {
		t.Errorf("second load must not hit the network (requests=%d)", requests)
	}
	if res2.State != TrustFresh || len(res2.Entry.Advisories) != len(res.Entry.Advisories) {
		t.Errorf("cache hit mismatch: %s %d", res2.State, len(res2.Entry.Advisories))
	}

	// Refresh forces a re-download.
	fc.Refresh = true
	if _, err := fc.LoadFeed(ctx, src); err != nil {
		t.Fatal(err)
	}
	if requests != 2 {
		t.Errorf("refresh must re-download (requests=%d)", requests)
	}
}

func TestLoadFeedOfflineMissIsUnverified(t *testing.T) {
	_, fc := testFeedServer(t, debianFixture, new(int))
	fc.Offline = true
	src := FeedSource{
		Provider: ProviderDebian, Distro: "debian", Release: "bookworm",
		URL:      "https://security-tracker.debian.org/tracker/data/json",
		MaxBytes: 1 << 20, Freshness: time.Hour, Format: "debian-tracker",
	}
	res, err := fc.LoadFeed(context.Background(), src)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Miss || res.State != TrustNone {
		t.Errorf("offline miss must be a miss with TrustNone: %+v", res)
	}
	if !strings.Contains(res.Note, "UNVERIFIED") {
		t.Errorf("offline miss must disclose UNVERIFIED: %s", res.Note)
	}
}

func TestLoadFeedOfflineCacheHit(t *testing.T) {
	requests := 0
	srv, fc := testFeedServer(t, debianFixture, &requests)
	src := FeedSource{
		Provider: ProviderDebian, Distro: "debian", Release: "bookworm",
		URL: srv.URL + "/tracker/data/json", MaxBytes: 1 << 20,
		Freshness: time.Hour, Format: "debian-tracker",
	}
	if _, err := fc.LoadFeed(context.Background(), src); err != nil {
		t.Fatal(err)
	}
	fc.Offline = true
	fc.Refresh = false
	res, err := fc.LoadFeed(context.Background(), src)
	if err != nil {
		t.Fatal(err)
	}
	if res.Miss || res.State != TrustOffline || requests != 1 {
		t.Errorf("offline cache hit: %+v requests=%d", res, requests)
	}
}

func TestLoadFeedHTTPFailureFallsBackToCache(t *testing.T) {
	requests := 0
	srv, fc := testFeedServer(t, debianFixture, &requests)
	src := FeedSource{
		Provider: ProviderDebian, Distro: "debian", Release: "bookworm",
		URL: srv.URL + "/tracker/data/json", MaxBytes: 1 << 20,
		Freshness: time.Hour, Format: "debian-tracker",
	}
	ctx := context.Background()
	if _, err := fc.LoadFeed(ctx, src); err != nil {
		t.Fatal(err)
	}
	// Make the cached copy stale so a refresh is attempted, then break the
	// server: the refresh fails and the cached copy is used with an explicit
	// note, never silently.
	origStale := staleAfter
	staleAfter = 0
	t.Cleanup(func() { staleAfter = origStale })
	src.Freshness = 0 // force TrustStale so a refresh is attempted
	srv.Close()
	res, err := fc.LoadFeed(ctx, src)
	if err != nil {
		t.Fatal(err)
	}
	if res.Miss {
		t.Fatalf("cached copy must be used when refresh fails: %+v", res)
	}
	if !strings.Contains(res.Note, "refresh failed") || !strings.Contains(res.Note, "stale") {
		t.Errorf("fallback must disclose the failure and staleness: %s", res.Note)
	}
}

func TestLoadFeedInvalidJSONIsMiss(t *testing.T) {
	requests := 0
	srv, fc := testFeedServer(t, "{not json", &requests)
	src := FeedSource{
		Provider: ProviderDebian, Distro: "debian", Release: "bookworm",
		URL: srv.URL + "/tracker/data/json", MaxBytes: 1 << 20,
		Freshness: time.Hour, Format: "debian-tracker",
	}
	res, err := fc.LoadFeed(context.Background(), src)
	if err == nil {
		t.Fatal("invalid feed JSON must error")
	}
	if !res.Miss || !strings.Contains(res.Note, "UNVERIFIED") {
		t.Errorf("invalid feed must yield UNVERIFIED miss: %+v", res)
	}
}

func TestLoadFeedRejectsNonAllowlistedHost(t *testing.T) {
	evil := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("pwned"))
	}))
	t.Cleanup(evil.Close)
	fc := NewFeedClient(NewCacheAt(t.TempDir()), false)
	src := FeedSource{
		Provider: ProviderDebian, Distro: "debian", Release: "bookworm",
		URL: evil.URL + "/data.json", MaxBytes: 1 << 20,
		Freshness: time.Hour, Format: "debian-tracker",
	}
	res, err := fc.LoadFeed(context.Background(), src)
	if err == nil {
		t.Fatal("non-allowlisted host must be refused")
	}
	if !res.Miss {
		t.Errorf("refused host must be a miss: %+v", res)
	}
}

func TestLoadFeedEnforcesSizeCap(t *testing.T) {
	requests := 0
	srv, fc := testFeedServer(t, strings.Repeat("a", 4096), &requests)
	src := FeedSource{
		Provider: ProviderDebian, Distro: "debian", Release: "bookworm",
		URL: srv.URL + "/big.json", MaxBytes: 1024,
		Freshness: time.Hour, Format: "debian-tracker",
	}
	res, err := fc.LoadFeed(context.Background(), src)
	if err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("oversized response must be refused: %v", err)
	}
	if !res.Miss {
		t.Errorf("oversized response must be a miss: %+v", res)
	}
}

// ---------------------------------------------------------------------------
// End-to-end assessment on a synthetic Debian root
// ---------------------------------------------------------------------------

func debianRoot(t *testing.T, status string) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"/etc/os-release":      "ID=debian\nVERSION_ID=12\nVERSION_CODENAME=bookworm\nNAME=\"Debian GNU/Linux\"\n",
		"/var/lib/dpkg/status": status,
	}
	for path, content := range files {
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

const debianStatusFixture = `Package: linux-image-6.1.0-18-amd64
Source: linux
Version: 6.1.94-1
Architecture: amd64
Status: install ok installed

Package: linux-image-amd64
Version: 6.1.94-1
Architecture: amd64
Status: install ok installed
`

func TestAssessDebianEndToEnd(t *testing.T) {
	requests := 0
	srv, _ := testFeedServer(t, debianFixture, &requests)
	root := debianRoot(t, debianStatusFixture)

	fc := NewFeedClient(NewCacheAt(t.TempDir()), false)
	fc.HTTP = official.NewClient([]official.Host{{Host: hostOf(t, srv.URL)}}, 1<<20)

	// The assessment builds its own client; to point it at the test server
	// we monkey-patch through the package-level constructor hook.
	origNewCache := newCacheHook
	origNewFeed := newFeedClientHook
	defer func() { newCacheHook, newFeedClientHook = origNewCache, origNewFeed }()
	newCacheHook = func() *Cache { return NewCacheAt(t.TempDir()) }
	origURL := debianTrackerURL
	debianTrackerURL = srv.URL + "/tracker/data/json"
	newFeedClientHook = func(cache *Cache, offline bool) *FeedClient {
		c := NewFeedClient(cache, offline)
		c.HTTP = trustedClient(t, srv)
		return c
	}
	t.Cleanup(func() { debianTrackerURL = origURL })

	assessment, err := Assess(context.Background(), Options{Root: root, Timeout: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if assessment.Identity.OSRelease.ID != "debian" || assessment.Identity.OSRelease.Codename != "bookworm" {
		t.Errorf("identity mismatch: %+v", assessment.Identity.OSRelease)
	}
	if assessment.Identity.Mode != "offline-rootfs" {
		t.Errorf("root %q must be offline mode", root)
	}
	if assessment.Identity.Running.Available {
		t.Error("offline target must not report a running kernel")
	}
	byCVE := map[string]Finding{}
	for _, f := range assessment.Findings {
		byCVE[f.CVE] = f
	}
	// Installed 6.1.94-1: CVE-2024-1086 fixed in 6.1.94-1 -> FIXED;
	// CVE-2024-26759 fixed in 6.1.82-1 -> FIXED; ignored -> NOT_AFFECTED;
	// undetermined -> UNDER_INVESTIGATION.
	if f := byCVE["CVE-2024-1086"]; f.State != StateFixed {
		t.Errorf("CVE-2024-1086 = %s (%s)", f.State, f.Explanation)
	}
	if f := byCVE["CVE-2024-26759"]; f.State != StateFixed {
		t.Errorf("CVE-2024-26759 = %s", f.State)
	}
	if f := byCVE["CVE-2023-52617"]; f.State != StateNotAffected {
		t.Errorf("CVE-2023-52617 = %s", f.State)
	}
	if f := byCVE["CVE-2024-26816"]; f.State != StateUnderInvestigation {
		t.Errorf("CVE-2024-26816 = %s", f.State)
	}
	if len(assessment.Feeds) == 0 {
		t.Error("feed summary missing")
	}
	if assessment.Counts.Affected != 0 {
		t.Errorf("unexpected affected count: %+v", assessment.Counts)
	}
	if assessment.Counts.Fixed != 2 || assessment.Counts.NotAffected != 1 || assessment.Counts.UnderInvestigation != 1 {
		t.Errorf("counts wrong: %+v", assessment.Counts)
	}
	// Dedup: linux-signed duplicate of CVE-2024-1086 must collapse.
	count := 0
	for _, f := range assessment.Findings {
		if f.CVE == "CVE-2024-1086" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("CVE-2024-1086 must appear once after dedup, got %d", count)
	}
}

func TestAssessDebianAffectedAndExit(t *testing.T) {
	requests := 0
	vulnFixture := strings.Replace(debianFixture, `"fixed_version": "6.1.94-1"`, `"fixed_version": "6.1.200-1"`, 1)
	srv, _ := testFeedServer(t, vulnFixture, &requests)
	root := debianRoot(t, debianStatusFixture)

	origNewCache := newCacheHook
	origNewFeed := newFeedClientHook
	defer func() { newCacheHook, newFeedClientHook = origNewCache, origNewFeed }()
	newCacheHook = func() *Cache { return NewCacheAt(t.TempDir()) }
	origURL := debianTrackerURL
	debianTrackerURL = srv.URL + "/tracker/data/json"
	newFeedClientHook = func(cache *Cache, offline bool) *FeedClient {
		c := NewFeedClient(cache, offline)
		c.HTTP = trustedClient(t, srv)
		return c
	}
	t.Cleanup(func() { debianTrackerURL = origURL })

	assessment, err := Assess(context.Background(), Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if !assessment.HasAffected() {
		t.Fatalf("installed 6.1.94-1 with fix 6.1.200-1 must be affected: %+v", assessment.Counts)
	}
	affected := 0
	for _, f := range assessment.Findings {
		if f.State == StateAffected {
			affected++
			if f.CVE != "CVE-2024-1086" {
				t.Errorf("unexpected affected CVE: %+v", f)
			}
			if f.InstalledVersion != "6.1.94-1" || f.FixedVersion != "6.1.200-1" {
				t.Errorf("affected finding fields wrong: %+v", f)
			}
			if f.MatchingMethod != MatchVendorStatus || f.Confidence != "confirmed" {
				t.Errorf("matching method/confidence wrong: %+v", f)
			}
			if len(f.References) == 0 || !strings.HasPrefix(f.References[0], "https://") {
				t.Errorf("reference URL must be preserved: %+v", f.References)
			}
		}
	}
	if affected != 1 {
		t.Errorf("expected exactly 1 affected finding (CVE-2024-1086), got %d: %+v", affected, assessment.Findings)
	}
}

func TestAssessOfflineWithoutCacheIsUnverified(t *testing.T) {
	// Isolate the cache so the user-level cache (populated by live runs)
	// cannot turn this offline-miss test into a cache hit.
	origCache := newCacheHook
	newCacheHook = func() *Cache { return NewCacheAt(t.TempDir()) }
	defer func() { newCacheHook = origCache }()
	root := debianRoot(t, debianStatusFixture)
	assessment, err := Assess(context.Background(), Options{Root: root, Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(assessment.Feeds) == 0 {
		t.Fatal("offline miss must still record the feed consultation")
	}
	joined := strings.Join(assessment.Notes, "; ")
	if !strings.Contains(joined, "UNVERIFIED") {
		t.Errorf("offline without cache must be UNVERIFIED, notes: %v", assessment.Notes)
	}
	if assessment.HasAffected() {
		t.Error("offline miss must never produce affected verdicts")
	}
}

func TestAssessUnknownDistroIsUnverified(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "/etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "/etc/os-release"),
		[]byte("ID=mysteryos\nVERSION_ID=1.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	assessment, err := Assess(context.Background(), Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if assessment.HasAffected() {
		t.Error("unknown distro must never produce affected verdicts")
	}
	found := false
	for _, n := range assessment.Notes {
		if strings.Contains(n, "UNVERIFIED") || strings.Contains(n, "unverified") {
			found = true
		}
	}
	if !found {
		t.Errorf("unknown distro must disclose UNVERIFIED: %v", assessment.Notes)
	}
}

func TestAssessUnknownSyntaxIsUnverified(t *testing.T) {
	// A Debian root whose installed version does not parse under dpkg rules.
	requests := 0
	srv, _ := testFeedServer(t, debianFixture, &requests)
	root := debianRoot(t, "Package: linux-image-x\nSource: linux\nVersion: broken:\nArchitecture: amd64\nStatus: install ok installed\n")
	origNewCache := newCacheHook
	origNewFeed := newFeedClientHook
	defer func() { newCacheHook, newFeedClientHook = origNewCache, origNewFeed }()
	newCacheHook = func() *Cache { return NewCacheAt(t.TempDir()) }
	origURL := debianTrackerURL
	debianTrackerURL = srv.URL + "/tracker/data/json"
	newFeedClientHook = func(cache *Cache, offline bool) *FeedClient {
		c := NewFeedClient(cache, offline)
		c.HTTP = trustedClient(t, srv)
		return c
	}
	t.Cleanup(func() { debianTrackerURL = origURL })
	assessment, err := Assess(context.Background(), Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if assessment.HasAffected() {
		t.Error("unparseable versions must never yield affected verdicts")
	}
	for _, f := range assessment.Findings {
		if f.State != StateUnverified && f.State != StateNotAffected && f.State != StateUnderInvestigation {
			t.Errorf("expected unverified-class state, got %s (%s)", f.State, f.Explanation)
		}
	}
}

func TestUpstreamQueryIsContextOnly(t *testing.T) {
	requests := 0
	upstreamFixture := `{
	 "resultsPerPage": 2, "totalResults": 2,
	 "vulnerabilities": [
	  {"cve": {"id": "CVE-2024-99901", "published": "2024-06-01T00:00:00.000", "lastModified": "2024-06-02T00:00:00.000",
	    "vulnStatus": "Analyzed",
	    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.8, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]}}},
	  {"cve": {"id": "CVE-2024-99902", "published": "2024-05-01T00:00:00.000", "lastModified": "2024-05-02T00:00:00.000",
	    "vulnStatus": "Rejected"}}
	 ]}`
	srv, fc := testFeedServer(t, upstreamFixture, &requests)
	origURL := nvdCVEURL
	nvdCVEURL = srv.URL + "/rest/json/cves/2.0"
	defer func() { nvdCVEURL = origURL }()
	hits, res, err := fc.QueryUpstream(context.Background(), "6.6.58")
	if err != nil {
		t.Fatal(err)
	}
	if res.Miss || len(hits) != 1 {
		t.Fatalf("upstream query failed: %d hits, miss=%v, err=%v", len(hits), res.Miss, err)
	}
	if hits[0].CVE != "CVE-2024-99901" {
		t.Errorf("upstream hit mismatch: %+v", hits[0])
	}
	if hits[0].Source != ProviderNVD || hits[0].Severity != "" && hits[0].Summary != "Analyzed" {
		t.Logf("upstream hit fields: %+v", hits[0])
	}
	if !strings.Contains(hits[0].Note, "never a distribution-confirmed vulnerability") {
		t.Errorf("upstream hit must carry the non-applicability note: %s", hits[0].Note)
	}
	// The upstream hit must NOT appear as a finding when wired through the
	// assessment path: verify the mapping helper keeps them separate.
	assessment := &Assessment{}
	assessment.Upstream = hits
	assessment.finalize(time.Now())
	if assessment.Counts.Affected != 0 {
		t.Errorf("upstream records must never count as affected: %+v", assessment.Counts)
	}
	if assessment.Counts.UpstreamOnly != 1 {
		t.Errorf("upstream-only count wrong: %+v", assessment.Counts)
	}
}

// TestFlavorMismatchNeverAffects pins the flavor separation: an advisory
// record for one flavor must not mark a different flavor affected. Debian
// tracker keys on source packages (flavor-independent), so the pin lives in
// the pending-reboot rules instead; here we pin the Alpine/Arch behavior via
// exact package name matching.
func TestFlavorMismatchNeverAffects(t *testing.T) {
	advisories, _, err := loadAlpineSecdb(bufio.NewReader(strings.NewReader(alpineFixture)))
	if err != nil {
		t.Fatal(err)
	}
	// linux-virt installed; secfixes only for linux-lts -> no findings.
	packages := []kernel.KernelPackage{
		{Name: "linux-virt", Version: "6.6.50-r0", Flavor: "virt",
			KernelRelease: "6.6.50-0-virt", Ecosystem: kernel.EcosystemAPK, Provenance: kernel.ProvenancePackageDB},
	}
	findings := MatchSecdb("v3.20", packages, advisories, TrustFresh)
	if len(findings) != 0 {
		t.Errorf("records for another flavor must not apply: %+v", findings)
	}
}

// TestDedupKeepsAffectedAndRecordsSources pins the dedup semantics: the
// affected verdict from one feed wins over a fixed verdict from another and
// both sources stay visible.
func TestDedupKeepsAffectedAndRecordsSources(t *testing.T) {
	a := &Assessment{Findings: []Finding{
		{CVE: "CVE-2024-1", Package: "linux", State: StateFixed, Provider: ProviderDebian},
		{CVE: "CVE-2024-1", Package: "linux", State: StateAffected, Provider: ProviderUbuntuOSV},
	}}
	a.dedupFindings()
	if len(a.Findings) != 1 {
		t.Fatalf("dedup failed: %+v", a.Findings)
	}
	if a.Findings[0].State != StateAffected {
		t.Errorf("affected verdict must win: %+v", a.Findings[0])
	}
	if len(a.Findings[0].Sources) == 0 || a.Findings[0].Sources[0].Provider != ProviderDebian {
		t.Errorf("losing source must be retained as evidence: %+v", a.Findings[0].Sources)
	}
}
