package kernelintel

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Lutfifakee-Project/ronda/internal/kernel"
)

// ---------------------------------------------------------------------------
// Cache
// ---------------------------------------------------------------------------

func TestCacheRoundTripAndIdentity(t *testing.T) {
	dir := t.TempDir()
	c := NewCacheAt(dir)
	entry := CacheEntry{
		Provider: ProviderDebian, Distro: "debian", Release: "bookworm",
		URL: "https://security-tracker.debian.org/tracker/data/json",
		Advisories: []Advisory{
			{Provider: ProviderDebian, DistroID: "debian", Release: "bookworm",
				CVE: "CVE-2024-1234", Package: "linux", FixedVersion: "6.1.112-1",
				Normalized: "resolved", SourceURL: debianTrackerURL},
		},
	}
	c.Put(entry)
	got, ok := c.Get(ProviderDebian, "debian", "bookworm", "https://security-tracker.debian.org/tracker/data/json")
	if !ok {
		t.Fatal("cache round trip failed")
	}
	if len(got.Advisories) != 1 || got.Advisories[0].CVE != "CVE-2024-1234" {
		t.Errorf("advisory mismatch: %+v", got.Advisories)
	}

	// Wrong identity fields must miss.
	if _, ok := c.Get(ProviderDebian, "debian", "trixie", "https://security-tracker.debian.org/tracker/data/json"); ok {
		t.Error("wrong release must miss")
	}
	if _, ok := c.Get(ProviderUbuntuOSV, "debian", "bookworm", "https://security-tracker.debian.org/tracker/data/json"); ok {
		t.Error("wrong provider must miss")
	}

	// Tampered content must miss, never trust.
	key := CacheKey(ProviderDebian, "debian", "bookworm", "https://security-tracker.debian.org/tracker/data/json")
	path := filepath.Join(dir, key+".json")
	data, _ := os.ReadFile(path)
	bad := strings.Replace(string(data), "CVE-2024-1234", "CVE-2024-9999", 1)
	if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Get(ProviderDebian, "debian", "bookworm", "https://security-tracker.debian.org/tracker/data/json"); ok {
		t.Error("corrupted cache entry must be treated as a miss")
	}

	// Cache file permissions are 0600.
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := fi.Mode().Perm(); mode != 0o600 {
		t.Errorf("cache file mode = %o, want 600", mode)
	}
}

func TestCacheKeyStable(t *testing.T) {
	a := CacheKey("p", "d", "r", "https://HOST/x")
	b := CacheKey("p", "d", "r", "https://host/x")
	if a != b {
		t.Error("cache key must normalize URL case")
	}
	if CacheKey("p", "d", "r", "u1") == CacheKey("p", "d", "r", "u2") {
		t.Error("different URLs must produce different keys")
	}
}

// ---------------------------------------------------------------------------
// Debian tracker parser
// ---------------------------------------------------------------------------

const debianFixture = `{
 "linux": {
  "CVE-2024-1086": {
   "description": "use-after-free in netfilter",
   "releases": {
    "bookworm": {"status": "resolved", "fixed_version": "6.1.94-1", "urgency": "high"},
    "buster": {"status": "vulnerable", "fixed_version": null, "urgency": "high"}
   }
  },
  "CVE-2024-26759": {
   "releases": {
    "bookworm": {"status": "resolved", "fixed_version": "6.1.82-1", "urgency": "medium"}
   }
  },
  "CVE-2023-52617": {
   "releases": {
    "bookworm": {"status": "ignored", "urgency": "unimportant"}
   }
  },
  "CVE-2024-26816": {
   "releases": {
    "bookworm": {"status": "undetermined", "urgency": "not yet assigned"}
   }
  },
  "DSA-5678-1": {
   "releases": {"bookworm": {"status": "resolved", "fixed_version": "6.1.90-1"}}
  },
  "TEMP-0000000-AAAAAA": {
   "releases": {"bookworm": {"status": "vulnerable"}}
  }
 },
 "openssh": {
  "CVE-2024-6387": {
   "releases": {"bookworm": {"status": "resolved", "fixed_version": "9.2p1-1"}}
  }
 },
 "linux-signed": {
  "CVE-2024-1086": {
   "releases": {"bookworm": {"status": "resolved", "fixed_version": "6.1.94-1", "urgency": "high"}}
  }
 }
}`

func TestLoadDebianTracker(t *testing.T) {
	advisories, feedUpdated, err := loadDebianTracker(bufio.NewReader(strings.NewReader(debianFixture)))
	if err != nil {
		t.Fatal(err)
	}
	if feedUpdated != "" {
		t.Errorf("tracker declares no feed timestamp; got %q", feedUpdated)
	}
	// kernel sources only: openssh excluded; DSA- and TEMP-keyed entries
	// carry no CVE id and are excluded from advisories.
	counts := map[string]int{}
	for _, a := range advisories {
		counts[a.Package+"|"+a.Release+"|"+a.Normalized]++
	}
	if counts["linux|bookworm|resolved"] != 2 {
		t.Errorf("expected 2 resolved bookworm linux records, got %v", counts)
	}
	if counts["linux|buster|affected"] != 1 {
		t.Errorf("expected 1 vulnerable buster record, got %v", counts)
	}
	if counts["linux|bookworm|not-affected"] != 1 {
		t.Errorf("ignored status must map to not-affected, got %v", counts)
	}
	if counts["linux|bookworm|under-investigation"] != 1 {
		t.Errorf("undetermined must map to under-investigation, got %v", counts)
	}
	if counts["openssh|bookworm|resolved"] != 0 {
		t.Errorf("non-kernel package leaked: %v", counts)
	}
	if counts["linux-signed|bookworm|resolved"] != 1 {
		t.Errorf("linux-signed source missing: %v", counts)
	}
	for _, a := range advisories {
		if a.CVE == "" {
			t.Errorf("advisory without CVE id leaked into the set: %+v", a)
		}
		if a.Provider != ProviderDebian || a.DistroID != "debian" {
			t.Errorf("provider identity missing: %+v", a)
		}
	}
}

// ---------------------------------------------------------------------------
// Debian matching
// ---------------------------------------------------------------------------

// debianOrderFixture builds a tracker payload with n linux CVEs, each with
// three release records, so that map iteration order (randomized per run by
// the Go runtime) has observable consequences if a parse ever walks it
// unordered.
func debianOrderFixture(n int) string {
	var b strings.Builder
	b.WriteString(`{"linux": {`)
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(fmt.Sprintf(
			`"CVE-2020-%05d": {"releases": {"bookworm": {"status": "resolved", "fixed_version": "6.1.%d-1"}, "sid": {"status": "vulnerable", "fixed_version": null}, "trixie": {"status": "resolved", "fixed_version": "6.1.%d-1"}}}`,
			i, i, i))
	}
	b.WriteString(`}}`)
	return b.String()
}

// TestLoadDebianTrackerDeterministicEmission pins byte-identical advisory
// output for identical input. Go map iteration order is randomized per run;
// the unordered walk that used to feed the advisory bound retained a random
// CVE subset on every run (observed during Phase 6 acceptance: two parses of
// the byte-identical tracker response kept disjoint ~5000-CVE subsets).
func TestLoadDebianTrackerDeterministicEmission(t *testing.T) {
	fixture := debianOrderFixture(40)
	var prev []Advisory
	for run := 0; run < 3; run++ {
		out, _, err := loadDebianTracker(bufio.NewReader(strings.NewReader(fixture)))
		if err != nil {
			t.Fatal(err)
		}
		if len(out) != 40*3 {
			t.Fatalf("run %d: expected %d advisories, got %d", run, 40*3, len(out))
		}
		if prev != nil && !reflect.DeepEqual(prev, out) {
			t.Fatalf("run %d: advisory emission is not deterministic", run)
		}
		prev = out
	}
}

// TestLoadDebianTrackerBoundedTruncationDeterministic pins the contract that
// the advisory bound, when it ever engages, truncates deterministically: the
// smallest CVE keys are retained, in sorted order, identically across parses.
func TestLoadDebianTrackerBoundedTruncationDeterministic(t *testing.T) {
	old := maxAdvisoriesPerFeed
	maxAdvisoriesPerFeed = 9
	defer func() { maxAdvisoriesPerFeed = old }()
	fixture := debianOrderFixture(40)
	first, _, err := loadDebianTracker(bufio.NewReader(strings.NewReader(fixture)))
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := loadDebianTracker(bufio.NewReader(strings.NewReader(fixture)))
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 9 || len(second) != 9 {
		t.Fatalf("expected the bound to retain 9 advisories, got %d and %d", len(first), len(second))
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("bounded truncation is not deterministic")
	}
	for _, a := range first {
		if a.CVE > "CVE-2020-00002" {
			t.Fatalf("truncation retained %s beyond the smallest CVE keys", a.CVE)
		}
	}
}

func TestMatchDebianStates(t *testing.T) {
	advisories, _, err := loadDebianTracker(bufio.NewReader(strings.NewReader(debianFixture)))
	if err != nil {
		t.Fatal(err)
	}
	packages := []kernel.KernelPackage{
		{Name: "linux-image-6.1.0-18-amd64", Version: "6.1.112-1", SourcePackage: "linux",
			KernelRelease: "6.1.0-18-amd64", Ecosystem: kernel.EcosystemDPKG, Provenance: kernel.ProvenancePackageDB},
	}
	findings := MatchDebian("bookworm", packages, advisories, TrustFresh)
	byCVE := map[string]Finding{}
	for _, f := range findings {
		byCVE[f.CVE] = f
	}
	// CVE-2024-1086 fixed in 6.1.94-1; installed 6.1.112-1 is newer -> FIXED.
	if f := byCVE["CVE-2024-1086"]; f.State != StateFixed {
		t.Errorf("CVE-2024-1086 = %s (%s), want FIXED", f.State, f.Explanation)
	}
	// CVE-2024-26759 fixed in 6.1.82-1; installed is newer -> FIXED.
	if f := byCVE["CVE-2024-26759"]; f.State != StateFixed {
		t.Errorf("CVE-2024-26759 = %s, want FIXED", f.State)
	}
	// CVE-2023-52617 ignored by Debian -> NOT_AFFECTED with vendor wording.
	if f := byCVE["CVE-2023-52617"]; f.State != StateNotAffected {
		t.Errorf("CVE-2023-52617 = %s, want NOT_AFFECTED", f.State)
	}
	// CVE-2024-26816 undetermined -> UNDER_INVESTIGATION.
	if f := byCVE["CVE-2024-26816"]; f.State != StateUnderInvestigation {
		t.Errorf("CVE-2024-26816 = %s, want UNDER_INVESTIGATION", f.State)
	}

	// An older installed package must be AFFECTED, with the backport-aware
	// explanation.
	old := []kernel.KernelPackage{
		{Name: "linux-image-6.1.0-18-amd64", Version: "6.1.80-1", SourcePackage: "linux",
			Ecosystem: kernel.EcosystemDPKG, Provenance: kernel.ProvenancePackageDB},
	}
	findings = MatchDebian("bookworm", old, advisories, TrustFresh)
	byCVE = map[string]Finding{}
	for _, f := range findings {
		byCVE[f.CVE] = f
	}
	if f := byCVE["CVE-2024-26759"]; f.State != StateAffected {
		t.Errorf("older package must be AFFECTED, got %s (%s)", f.State, f.Explanation)
	} else if !strings.Contains(f.Explanation, "backport") {
		t.Errorf("explanation must disclose the backport semantics: %s", f.Explanation)
	}

	// Wrong release records must not apply.
	findings = MatchDebian("trixie", packages, advisories, TrustFresh)
	if len(findings) != 0 {
		t.Errorf("records from another release must not apply: %v", findings)
	}
}

// TestMatchDebianBackportFalsePositive pins the core false-positive
// protection: a Debian backport fix (tilde revision, upstream version LOWER
// than the vulnerable upstream release) still fixes the package. Upstream
// version ranges never decide the verdict.
func TestMatchDebianBackportFalsePositive(t *testing.T) {
	advisories := []Advisory{
		{Provider: ProviderDebian, DistroID: "debian", Release: "bookworm",
			CVE: "CVE-2024-1234", Package: "linux", FixedVersion: "6.6.58-1",
			Normalized: "resolved", Status: "resolved"},
	}
	// Installed 6.6.58-1 is at the backported fix; upstream kernels below
	// 6.6.59 might carry the bug, but Debian's own fix decides: FIXED.
	packages := []kernel.KernelPackage{
		{Name: "linux-image-6.6.58-1", Version: "6.6.58-1", SourcePackage: "linux",
			Ecosystem: kernel.EcosystemDPKG, Provenance: kernel.ProvenancePackageDB},
	}
	findings := MatchDebian("bookworm", packages, advisories, TrustFresh)
	if len(findings) != 1 || findings[0].State != StateFixed {
		t.Fatalf("backported fix must yield FIXED: %+v", findings)
	}
	// Installed below the backported fix -> AFFECTED.
	packages[0].Version = "6.6.57-1"
	findings = MatchDebian("bookworm", packages, advisories, TrustFresh)
	if len(findings) != 1 || findings[0].State != StateAffected {
		t.Fatalf("below backported fix must yield AFFECTED: %+v", findings)
	}
}

// TestMatchDebianWithoutSourceMapping pins honesty: a binary package with no
// source mapping and a name that is not a tracker key cannot be matched.
func TestMatchDebianWithoutSourceMapping(t *testing.T) {
	advisories := []Advisory{
		{Provider: ProviderDebian, DistroID: "debian", Release: "bookworm",
			CVE: "CVE-2024-1234", Package: "linux", FixedVersion: "6.1.94-1",
			Normalized: "resolved"},
	}
	packages := []kernel.KernelPackage{
		{Name: "linux-image-6.1.0-18-amd64", Version: "6.1.112-1", SourcePackage: "",
			Ecosystem: kernel.EcosystemDPKG},
	}
	findings := MatchDebian("bookworm", packages, advisories, TrustFresh)
	for _, f := range findings {
		if f.CVE == "CVE-2024-1234" && f.State == StateFixed && f.Confidence == "confirmed" {
			t.Errorf("binary-only match must not claim confirmed confidence: %+v", f)
		}
	}
}

// ---------------------------------------------------------------------------
// Alpine secdb
// ---------------------------------------------------------------------------

const alpineFixture = `{
 "distroversion": "v3.20",
 "url": "https://security.alpinelinux.org",
 "packages": [
  {"pkg": {"name": "linux-lts", "secfixes": {
     "6.6.58-r0": ["CVE-2024-44986 CVE-2024-44987"],
     "6.6.59-r0": ["CVE-2024-50001"]
  }}},
  {"pkg": {"name": "linux-firmware-nvidia", "secfixes": {"20240909-r0": ["CVE-2024-9999"]}}},
  {"pkg": {"name": "openssl", "secfixes": {"3.3.2-r0": ["CVE-2024-6119"]}}}
 ]
}`

func TestLoadAlpineSecdb(t *testing.T) {
	advisories, feedUpdated, err := loadAlpineSecdb(bufio.NewReader(strings.NewReader(alpineFixture)))
	if err != nil {
		t.Fatal(err)
	}
	if feedUpdated != "" {
		t.Errorf("secdb declares no feed timestamp; got %q", feedUpdated)
	}
	if len(advisories) != 3 {
		t.Fatalf("got %d advisories, want 3 (bundled CVEs split, non-kernel excluded): %+v", len(advisories), advisories)
	}
	seen := map[string]bool{}
	for _, a := range advisories {
		seen[a.CVE] = true
		if a.Package != "linux-lts" {
			t.Errorf("non-kernel package leaked: %+v", a)
		}
	}
	for _, want := range []string{"CVE-2024-44986", "CVE-2024-44987", "CVE-2024-50001"} {
		if !seen[want] {
			t.Errorf("missing %s in %v", want, seen)
		}
	}
}

func TestMatchSecdbStates(t *testing.T) {
	advisories, _, err := loadAlpineSecdb(bufio.NewReader(strings.NewReader(alpineFixture)))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		version string
		cve     string
		want    string
	}{
		{"6.6.57-r0", "CVE-2024-44986", StateAffected},
		{"6.6.58-r0", "CVE-2024-44986", StateFixed},
		{"6.6.58-r0", "CVE-2024-50001", StateAffected},
		{"6.6.59-r0", "CVE-2024-50001", StateFixed},
		{"6.6.60-r0", "CVE-2024-44986", StateFixed},
	}
	for _, c := range cases {
		packages := []kernel.KernelPackage{
			{Name: "linux-lts", Version: c.version, Flavor: "lts",
				KernelRelease: "6.6.58-0-lts", Ecosystem: kernel.EcosystemAPK, Provenance: kernel.ProvenancePackageDB},
		}
		findings := MatchSecdb("v3.20", packages, advisories, TrustFresh)
		byCVE := map[string]Finding{}
		for _, f := range findings {
			byCVE[f.CVE] = f
		}
		if f := byCVE[c.cve]; f.State != c.want {
			t.Errorf("linux-lts %s / %s = %s (%s), want %s", c.version, c.cve, f.State, f.Explanation, c.want)
		}
	}
}

func TestAlpineBranchResolution(t *testing.T) {
	cases := map[string]struct {
		branch string
		ok     bool
	}{
		"3.20.3": {"v3.20", true},
		"3.21":   {"v3.21", true},
		"3.20":   {"v3.20", true},
	}
	for version, want := range cases {
		got, ok := AlpineBranch(version)
		if got != want.branch || ok != want.ok {
			t.Errorf("AlpineBranch(%q) = %q,%v want %q,%v", version, got, ok, want.branch, want.ok)
		}
	}
	if got, ok := AlpineBranch("3.999_edge"); !ok || got != "edge" {
		t.Errorf("edge branch must resolve to edge: %q %v", got, ok)
	}
	if _, ok := AlpineBranch(""); ok {
		t.Error("empty version must fail")
	}
	if _, ok := AlpineBranch("9.9"); ok {
		t.Error("unknown series must fail (Alpine uses 3.x)")
	}
}

// ---------------------------------------------------------------------------
// Arch AVG
// ---------------------------------------------------------------------------

const archFixture = `[
 {"name": "AVG-2087", "severity": "High", "type": "multiple issues",
  "affected": "6.6.1.arch1-1", "fixed": "6.6.2.arch1-1", "status": "Fixed",
  "issues": ["CVE-2024-1086"], "packages": ["linux"]},
 {"name": "AVG-2090", "severity": "Critical", "type": "arbitrary code execution",
  "affected": "6.7.1.arch1-1", "fixed": "", "status": "Vulnerable",
  "issues": ["CVE-2024-26816"], "packages": ["linux-zen"]},
 {"name": "AVG-2091", "severity": "Medium", "type": "information disclosure",
  "affected": "6.6.3.arch1-1", "fixed": "", "status": "Testing",
  "issues": ["CVE-2024-99999"], "packages": ["openssl"]}
]`

func TestLoadArchAVG(t *testing.T) {
	advisories, _, err := loadArchAVG(bufio.NewReader(strings.NewReader(archFixture)))
	if err != nil {
		t.Fatal(err)
	}
	if len(advisories) != 2 {
		t.Fatalf("got %d advisories, want 2 (non-kernel AVG excluded): %+v", len(advisories), advisories)
	}
	if advisories[0].Package != "linux" || advisories[0].AffectedFrom != "6.6.1.arch1-1" ||
		advisories[0].FixedVersion != "6.6.2.arch1-1" || advisories[0].Severity != "HIGH" {
		t.Errorf("AVG fields lost: %+v", advisories[0])
	}
	if advisories[1].Package != "linux-zen" || advisories[1].Severity != "CRITICAL" {
		t.Errorf("AVG severity mapping wrong: %+v", advisories[1])
	}
}

func TestMatchArchStates(t *testing.T) {
	advisories, _, err := loadArchAVG(bufio.NewReader(strings.NewReader(archFixture)))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		version string
		cve     string
		want    string
	}{
		{"older than introduction", "6.6.0.arch1-1", "CVE-2024-1086", StateNotAffected},
		{"inside range", "6.6.1.arch1-1", "CVE-2024-1086", StateAffected},
		{"at fix", "6.6.2.arch1-1", "CVE-2024-1086", StateFixed},
		{"after fix", "6.6.3.arch1-1", "CVE-2024-1086", StateFixed},
		{"unfixed vulnerable", "6.7.1.arch1-1", "CVE-2024-26816", StateAffected},
	}
	for _, c := range cases {
		packages := []kernel.KernelPackage{
			{Name: "linux", Version: c.version, Flavor: "default",
				KernelRelease: "6.6.2-arch1-1", Ecosystem: kernel.EcosystemPacman, Provenance: kernel.ProvenancePackageDB},
			{Name: "linux-zen", Version: c.version, Flavor: "zen",
				Ecosystem: kernel.EcosystemPacman, Provenance: kernel.ProvenancePackageDB},
		}
		findings := MatchArch(packages, advisories, TrustFresh)
		byCVE := map[string]Finding{}
		for _, f := range findings {
			byCVE[f.CVE] = f
		}
		if f := byCVE[c.cve]; f.State != c.want {
			t.Errorf("%s: linux %s / %s = %s (%s), want %s", c.name, c.version, c.cve, f.State, f.Explanation, c.want)
		}
	}
	// Testing status without an affected boundary -> UNDER_INVESTIGATION.
	packages := []kernel.KernelPackage{
		{Name: "linux", Version: "6.6.2.arch1-1", Ecosystem: kernel.EcosystemPacman, Provenance: kernel.ProvenancePackageDB},
	}
	findings := MatchArch(packages, advisories, TrustFresh)
	for _, f := range findings {
		if f.CVE == "CVE-2024-99999" {
			t.Errorf("non-kernel AVG must not match: %+v", f)
		}
	}
}

// ---------------------------------------------------------------------------
// OSV (Ubuntu + upstream)
// ---------------------------------------------------------------------------

const osvFixture = `{
 "vulns": [
  {"id": "UBUNTU-CVE-2024-1086",
   "aliases": ["CVE-2024-1086"],
   "summary": "use-after-free in netfilter",
   "published": "2024-01-03T00:00:00Z",
   "modified": "2024-06-02T00:00:00Z",
   "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"}],
   "affected": [
    {"package": {"ecosystem": "Ubuntu:22.04:LTS", "name": "linux-image-5.15.0-91-generic"},
     "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.15.0-92.102"}]}]}
   ],
   "references": [{"type": "REPORT", "url": "https://ubuntu.com/security/CVE-2024-1086"}]},
  {"id": "UBUNTU-CVE-2024-7777",
   "aliases": ["CVE-2024-7777"],
   "withdrawn": "2024-05-01T00:00:00Z",
   "affected": [
    {"package": {"ecosystem": "Ubuntu:22.04:LTS", "name": "linux-image-5.15.0-91-generic"},
     "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.15.0-93.103"}]}]}
   ]},
  {"id": "GHSA-xxxx", "aliases": [],
   "affected": []}
 ]
}`

func TestLoadOSVResponse(t *testing.T) {
	advisories, _, err := loadOSVResponse(bufio.NewReader(strings.NewReader(osvFixture)))
	if err != nil {
		t.Fatal(err)
	}
	if len(advisories) != 2 {
		t.Fatalf("got %d advisories, want 2: %+v", len(advisories), advisories)
	}
	first := advisories[0]
	if first.CVE != "CVE-2024-1086" || first.AdvisoryID != "UBUNTU-CVE-2024-1086" {
		t.Errorf("canonical CVE resolution failed: %+v", first)
	}
	if first.FixedVersion != "5.15.0-92.102" {
		t.Errorf("fixed event lost: %+v", first)
	}
	if first.CVSSSource != "CVSS 3.1" || !strings.HasPrefix(first.CVSSVector, "CVSS:3.1/") {
		t.Errorf("CVSS attribution lost: %+v", first)
	}
	// Withdrawn record preserved with its withdrawal timestamp.
	withdrawn := advisories[1]
	if withdrawn.CVE != "CVE-2024-7777" || withdrawn.Withdrawn == "" {
		t.Errorf("withdrawn record must carry its timestamp: %+v", withdrawn)
	}
}

func TestUbuntuEcosystemMapping(t *testing.T) {
	cases := map[string]string{
		"22.04": "Ubuntu:22.04:LTS",
		"20.04": "Ubuntu:20.04:LTS",
		"24.04": "Ubuntu:24.04:LTS",
		"23.10": "Ubuntu:23.10",
		"25.04": "Ubuntu:25.04",
		"24.10": "Ubuntu:24.10",
	}
	for version, want := range cases {
		got, ok := ubuntuEcosystem(version)
		if !ok || got != want {
			t.Errorf("ubuntuEcosystem(%q) = %q,%v want %q", version, got, ok, want)
		}
	}
	if _, ok := ubuntuEcosystem(""); ok {
		t.Error("empty version must fail")
	}
}

func TestUbuntuQuerySourceTransmitsOnlyIdentity(t *testing.T) {
	src := UbuntuQuerySource("Ubuntu:22.04:LTS", "linux-image-5.15.0-91-generic", "5.15.0-91.101")
	if src.Method != "POST" {
		t.Error("OSV query must use POST")
	}
	if !strings.Contains(src.Body, "linux-image-5.15.0-91-generic") ||
		!strings.Contains(src.Body, "5.15.0-91.101") ||
		!strings.Contains(src.Body, "Ubuntu:22.04:LTS") {
		t.Errorf("query body missing package identity: %s", src.Body)
	}
	for _, forbidden := range []string{"hostname", "/etc/", "/home/", "password", "uname"} {
		if strings.Contains(strings.ToLower(src.Body), forbidden) {
			t.Errorf("query body must not contain %q: %s", forbidden, src.Body)
		}
	}
}

func TestMatchUbuntuStates(t *testing.T) {
	advisories, _, err := loadOSVResponse(bufio.NewReader(strings.NewReader(osvFixture)))
	if err != nil {
		t.Fatal(err)
	}
	p := kernel.KernelPackage{
		Name: "linux-image-5.15.0-91-generic", Version: "5.15.0-91.101",
		KernelRelease: "5.15.0-91-generic", Ecosystem: kernel.EcosystemDPKG,
		Provenance: kernel.ProvenancePackageDB,
	}
	findings := MatchUbuntu(p, advisories, TrustFresh, "Ubuntu:22.04:LTS")
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(findings))
	}
	byCVE := map[string]Finding{}
	for _, f := range findings {
		byCVE[f.CVE] = f
	}
	if f := byCVE["CVE-2024-1086"]; f.State != StateAffected || f.FixedVersion != "5.15.0-92.102" {
		t.Errorf("OSV affected verdict wrong: %+v", f)
	}
	if f := byCVE["CVE-2024-7777"]; f.State != StateUnverified {
		t.Errorf("withdrawn record must be UNVERIFIED, never a live verdict: %+v", f)
	}
}

func TestUpstreamVersionOf(t *testing.T) {
	cases := map[string]string{
		"6.6.58-0-lts":                 "6.6.58",
		"6.1.0-18-amd64":               "6.1.0",
		"5.14.0-427.13.1.el9_4.x86_64": "5.14.0",
		"6.6.2-arch1-1":                "6.6.2",
		"6.8.0-40-generic":             "6.8.0",
		"custom-kernel":                "",
		"":                             "",
	}
	for release, want := range cases {
		if got := UpstreamVersionOf(release); got != want {
			t.Errorf("UpstreamVersionOf(%q) = %q, want %q", release, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// NVD
// ---------------------------------------------------------------------------

const nvdFixture = `{
 "resultsPerPage": 1,
 "vulnerabilities": [
  {"cve": {
    "id": "CVE-2024-1086",
    "published": "2024-01-03T00:00:00.000",
    "lastModified": "2024-06-02T00:00:00.000",
    "vulnStatus": "Modified",
    "descriptions": [{"lang": "en", "value": "A use-after-free in netfilter."}],
    "metrics": {
      "cvssMetricV31": [{"cvssData": {"baseScore": 7.8, "vectorString": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "version": "3.1"}, "source": "nvd@nist.gov"}]
    },
    "references": [{"url": "https://example.com/advisory"}]
  }}
 ]
}`

func TestParseNVD(t *testing.T) {
	rec, err := ParseNVD([]byte(nvdFixture))
	if err != nil {
		t.Fatal(err)
	}
	if rec.CVE != "CVE-2024-1086" || rec.CVSSScore != "7.8" || rec.CVSSSource != "NVD CVSS 3.1" {
		t.Errorf("NVD extraction wrong: %+v", rec)
	}
	if rec.Withdrawn {
		t.Error("non-rejected record must not be withdrawn")
	}
	if len(rec.References) != 1 {
		t.Errorf("references lost: %+v", rec)
	}

	rejected := strings.Replace(nvdFixture, `"vulnStatus": "Modified"`, `"vulnStatus": "Rejected"`, 1)
	rec, err = ParseNVD([]byte(rejected))
	if err != nil {
		t.Fatal(err)
	}
	if !rec.Withdrawn {
		t.Error("Rejected NVD record must be flagged withdrawn")
	}
}

// ---------------------------------------------------------------------------
// RPM family: aggregate UNVERIFIED
// ---------------------------------------------------------------------------

func TestMatchRPMAggregateUnverified(t *testing.T) {
	packages := []kernel.KernelPackage{
		{Name: "kernel", Version: "5.14.0-427.13.1.el9_4", KernelRelease: "5.14.0-427.13.1.el9_4.x86_64",
			Ecosystem: kernel.EcosystemRPM, Provenance: kernel.ProvenanceFilesystem},
	}
	advisories := []Advisory{
		{Provider: ProviderRedHat, CVE: "CVE-2024-1086", Package: "kernel", FixedVersion: "0:5.14.0-427.13.1.el9_4"},
		{Provider: ProviderRedHat, CVE: "CVE-2024-26759", Package: "kernel", FixedVersion: "0:5.14.0-427.20.1.el9_4"},
	}
	findings, note := MatchRPM(packages, advisories, ProviderRedHat, TrustFresh)
	if len(findings) != 0 {
		t.Errorf("RPM matching must produce no per-CVE findings (UNVERIFIED by design): %+v", findings)
	}
	if !strings.Contains(note, "UNVERIFIED") || !strings.Contains(note, "never invokes rpm, dnf or yum") {
		t.Errorf("aggregate note must disclose the limitation honestly: %s", note)
	}
}

func TestIsValidCVE(t *testing.T) {
	valid := []string{"CVE-2024-1086", "CVE-1999-0001", "CVE-2026-123456"}
	invalid := []string{"", "CVE-46838", "CVE-2024-108", "CVE-2024-ABCD", "cve-2024-1234", "DSA-5678-1", "TEMP-0000000-AAAAAA"}
	for _, id := range valid {
		if !isValidCVE(id) {
			t.Errorf("isValidCVE(%q) = false, want true", id)
		}
	}
	for _, id := range invalid {
		if isValidCVE(id) {
			t.Errorf("isValidCVE(%q) = true, want false", id)
		}
	}
}

func TestSecdbMalformedCVEDropped(t *testing.T) {
	fixture := `{"distroversion": "v3.20", "packages": [
	 {"pkg": {"name": "linux-lts", "secfixes": {"6.6.13-r1": ["CVE-46838", "CVE-2024-44986"]}}}
	]}`
	advisories, _, err := loadAlpineSecdb(bufio.NewReader(strings.NewReader(fixture)))
	if err != nil {
		t.Fatal(err)
	}
	if len(advisories) != 1 || advisories[0].CVE != "CVE-2024-44986" {
		t.Fatalf("malformed CVE id must be dropped, valid one kept: %+v", advisories)
	}
}
