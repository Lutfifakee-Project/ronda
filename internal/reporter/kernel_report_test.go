package reporter

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Lutfifakee-Project/ronda/internal/kernel"
	"github.com/Lutfifakee-Project/ronda/internal/kernelintel"
)

// computeCounts mirrors kernelintel's counter aggregation for tests.
func computeCounts(a *kernelintel.Assessment) {
	for _, f := range a.Findings {
		switch f.State {
		case kernelintel.StateAffected:
			a.Counts.Affected++
		case kernelintel.StateFixed:
			a.Counts.Fixed++
		case kernelintel.StateNotAffected:
			a.Counts.NotAffected++
		case kernelintel.StateUnderInvestigation:
			a.Counts.UnderInvestigation++
		case kernelintel.StateUnverified:
			a.Counts.Unverified++
		}
	}
	a.Counts.UpstreamOnly = len(a.Upstream)
}

func sampleAssessment() *kernelintel.Assessment {
	a := &kernelintel.Assessment{
		Mode: "live",
		PendingReboot: &kernel.PendingReboot{
			Likely:         true,
			RunningRelease: "6.1.0-18-amd64",
			RunningPackage: "linux-image-6.1.0-18-amd64 6.1.112-1",
			NewerInstalled: []string{"linux-image-6.1.0-19-amd64 6.1.120-1 (6.1.0-19-amd64)"},
			Evidence:       []string{"running kernel 6.1.0-18-amd64 (6.1.112-1) is older than installed kernel package linux-image-6.1.0-19-amd64 (release 6.1.0-19-amd64, flavor )"},
			Explanation:    "a newer same-flavor kernel package is installed while the running kernel is older",
		},
	}
	a.Identity.OSRelease = kernel.OSRelease{
		ID: "debian", Name: "Debian GNU/Linux", VersionID: "12", Codename: "bookworm",
		Family: kernel.FamilyDebian, Ecosystem: kernel.EcosystemDPKG,
		Lifecycle: kernel.LifecycleExtended, LifecycleBasis: "Debian bookworm regular support ended 2026-06-10; LTS until 2028-06-10",
	}
	a.Identity.Running = kernel.RunningKernel{Available: true, Release: "6.1.0-18-amd64", Arch: "amd64", Source: "uname(2)"}
	a.Identity.Packages = []kernel.KernelPackage{
		{Name: "linux-image-6.1.0-18-amd64", Version: "6.1.112-1", SourcePackage: "linux",
			KernelRelease: "6.1.0-18-amd64", Ecosystem: kernel.EcosystemDPKG, Provenance: kernel.ProvenancePackageDB},
	}
	a.Findings = []kernelintel.Finding{
		{
			CVE: "CVE-2024-1086", Distro: "debian", Release: "bookworm",
			Package: "linux-image-6.1.0-18-amd64", SourcePackage: "linux",
			InstalledVersion: "6.1.112-1", FixedVersion: "6.1.200-1",
			State: kernelintel.StateAffected, Severity: "HIGH",
			Provider: kernelintel.ProviderDebian, DataTrust: kernelintel.TrustFresh,
			MatchingMethod: kernelintel.MatchVendorStatus, Confidence: "confirmed",
			Explanation:   "installed is older than Debian's fix",
			KernelRelease: "6.1.0-18-amd64",
			References:    []string{"https://security-tracker.debian.org/tracker/CVE-2024-1086"},
		},
		{
			CVE: "CVE-2024-26759", Distro: "debian", Release: "bookworm",
			Package: "linux-image-6.1.0-18-amd64", InstalledVersion: "6.1.112-1",
			FixedVersion: "6.1.82-1", State: kernelintel.StateFixed,
			Provider: kernelintel.ProviderDebian, DataTrust: kernelintel.TrustFresh,
			MatchingMethod: kernelintel.MatchVendorStatus, Confidence: "confirmed",
			Explanation: "at or after the fix",
		},
	}
	a.Upstream = []kernelintel.UpstreamHit{
		{CVE: "CVE-2024-99901", UpstreamVersion: "6.1.0", Source: kernelintel.ProviderOSV,
			Note: "upstream kernel record; context only"},
	}
	a.Feeds = []kernelintel.FeedSummary{
		{Provider: kernelintel.ProviderDebian, State: kernelintel.TrustFresh,
			FetchedAt: "2026-11-01T00:00:00Z", Age: "2s", Records: 4},
	}
	a.Lifecycle = kernelintel.LifecycleNote{
		State: kernel.LifecycleExtended,
		Basis: "Debian bookworm regular support ended 2026-06-10; LTS until 2028-06-10",
	}
	computeCounts(a)
	return a
}

func TestKernelThreeFormatsAgree(t *testing.T) {
	a := sampleAssessment()
	var term, js, htmlBuf bytes.Buffer
	if err := WriteKernel(&term, a, "terminal"); err != nil {
		t.Fatal(err)
	}
	if err := WriteKernel(&js, a, "json"); err != nil {
		t.Fatal(err)
	}
	if err := WriteKernel(&htmlBuf, a, "html"); err != nil {
		t.Fatal(err)
	}
	termOut, jsonOut, htmlOut := term.String(), js.String(), htmlBuf.String()

	// The affected finding must appear in all three with the same verdict,
	// severity, provider and fixed version.
	for _, out := range []string{termOut, jsonOut, htmlOut} {
		for _, want := range []string{"CVE-2024-1086", "AFFECTED", "HIGH", "6.1.200-1", "debian-security-tracker"} {
			if !strings.Contains(out, want) {
				t.Errorf("format output missing %q", want)
			}
		}
	}
	// Trust states and feed freshness must be visible in all three.
	for _, out := range []string{termOut, jsonOut, htmlOut} {
		if !strings.Contains(out, "fresh-official-data") {
			t.Errorf("feed trust state missing")
		}
	}
	// The fixed and upstream findings must not be inflated into affected.
	if strings.Contains(jsonOut, `"affected":2`) {
		t.Error("affected count inflated")
	}
	// Terminal shows the pending reboot evidence.
	if !strings.Contains(termOut, "LIKELY") || !strings.Contains(termOut, "6.1.0-19-amd64") {
		t.Errorf("pending reboot evidence missing from terminal output")
	}
	// HTML must not claim security when nothing matched — covered by the
	// empty assessment test below; here it must render the finding table.
	if !strings.Contains(htmlOut, "state-AFFECTED") {
		t.Error("HTML state class missing")
	}
}

func TestKernelJSONSchema(t *testing.T) {
	a := sampleAssessment()
	var buf bytes.Buffer
	if err := WriteKernel(&buf, a, "json"); err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Schema string `json:"schema"`
		Kernel struct {
			Identity kernel.Report `json:"identity"`
			Findings []struct {
				CVE     string `json:"cve"`
				State   string `json:"state"`
				Package string `json:"package"`
			} `json:"findings"`
			Counts struct {
				Affected int `json:"affected"`
				Fixed    int `json:"fixed"`
			} `json:"counts"`
			Feeds []struct {
				Provider string `json:"provider"`
				State    string `json:"state"`
			} `json:"feeds"`
			PendingReboot *struct {
				Likely bool `json:"likely"`
			} `json:"pendingReboot"`
		} `json:"kernel"`
	}
	if err := json.Unmarshal(buf.Bytes(), &envelope); err != nil {
		t.Fatalf("kernel JSON invalid: %v", err)
	}
	if envelope.Schema != "ronda.kernel.v1" {
		t.Errorf("schema = %q", envelope.Schema)
	}
	if envelope.Kernel.Counts.Affected != 1 || envelope.Kernel.Counts.Fixed != 1 {
		t.Errorf("counts wrong: %+v", envelope.Kernel.Counts)
	}
	if len(envelope.Kernel.Findings) != 2 {
		t.Errorf("findings wrong: %d", len(envelope.Kernel.Findings))
	}
	if envelope.Kernel.PendingReboot == nil || !envelope.Kernel.PendingReboot.Likely {
		t.Error("pending reboot lost in JSON")
	}
}

func TestKernelEmptyIsNeverSecure(t *testing.T) {
	a := &kernelintel.Assessment{Mode: "offline-rootfs"}
	a.Identity.OSRelease = kernel.OSRelease{ID: "rocky", VersionID: "9.4", Lifecycle: kernel.LifecycleUnknown}
	a.Lifecycle = kernelintel.LifecycleNote{State: kernel.LifecycleUnknown,
		Warning: "RONDA has no reliable support-window data for this release; the status is unknown and kernel CVE verification stays UNVERIFIED, which is never interpreted as supported."}
	computeCounts(a)

	var term, js, htmlBuf bytes.Buffer
	if err := WriteKernel(&term, a, "terminal"); err != nil {
		t.Fatal(err)
	}
	if err := WriteKernel(&js, a, "json"); err != nil {
		t.Fatal(err)
	}
	if err := WriteKernel(&htmlBuf, a, "html"); err != nil {
		t.Fatal(err)
	}
	for name, out := range map[string]string{"terminal": term.String(), "json": js.String(), "html": htmlBuf.String()} {
		if !strings.Contains(out, "not a statement that the system is secure") {
			t.Errorf("%s must carry the no-findings disclaimer", name)
		}
	}
	if !strings.Contains(term.String(), "UNVERIFIED") {
		t.Error("unknown lifecycle must surface as UNVERIFIED disclosure in terminal")
	}
	// The Rocky note about Red Hat status must stay visible.
	if !strings.Contains(htmlBuf.String(), "never interpreted as supported") {
		t.Error("HTML must render the lifecycle warning")
	}
}

func TestKernelUNVERIFIEDVisibility(t *testing.T) {
	a := sampleAssessment()
	a.Findings = append(a.Findings, kernelintel.Finding{
		CVE: "CVE-2024-26816", Package: "linux-image-6.1.0-18-amd64",
		InstalledVersion: "6.1.112-1", State: kernelintel.StateUnverified,
		Provider: kernelintel.ProviderDebian, DataTrust: kernelintel.TrustFresh,
		Confidence:     "unverified",
		Explanation:    "Debian has not determined the status yet",
		RunningRelease: "6.1.0-18-amd64",
	})
	computeCounts(a)
	var term bytes.Buffer
	if err := WriteKernel(&term, a, "terminal"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(term.String(), "UNVERIFIED") {
		t.Error("UNVERIFIED finding must be visible, never dropped")
	}
	var js bytes.Buffer
	if err := WriteKernel(&js, a, "json"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(js.String(), `"unverified": 1`) {
		t.Error("unverified count missing from JSON")
	}
}
