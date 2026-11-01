package kernelintel

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Lutfifakee-Project/ronda/internal/kernel"
)

// OSV API endpoints. Queries transmit only the package identity and version
// needed for the lookup: never hostnames, users, paths, inventories or scan
// content (Phase 6 privacy rules).
const (
	osvQueryURLProduction = "https://api.osv.dev/v1/query"
	nvdCVEURLProduction   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	osvMaxBodyB           = 64 << 20 // in-memory JSON API cap (Ubuntu kernel queries reach ~35 MB)
)

// Endpoints are variables so tests can retarget them at a local server;
// the allowlist of the hardened client still decides what is reachable.
var (
	osvQueryURL = osvQueryURLProduction
	nvdCVEURL   = nvdCVEURLProduction
)

// osvQuery is the minimal OSV batch-of-one query body.
type osvQuery struct {
	Package osvPkg `json:"package"`
	Version string `json:"version,omitempty"`
}

type osvPkg struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

// osvResponse is the subset of the OSV response schema RONDA consumes.
// Withdrawn records carry a non-empty "withdrawn" timestamp and are kept
// with their state disclosed, never used as live advisories.
type osvResponse struct {
	Vulns []osvVuln `json:"vulns"`
}

type osvVuln struct {
	ID        string   `json:"id"` // UBUNTU-CVE-..., GHSA-..., or CVE-...
	Aliases   []string `json:"aliases"`
	Summary   string   `json:"summary"`
	Details   string   `json:"details"`
	Published string   `json:"published"`
	Modified  string   `json:"modified"`
	Withdrawn string   `json:"withdrawn"`
	Severity  []struct {
		Type  string `json:"type"` // CVSS_V3, CVSS_V4, Ubuntu
		Score string `json:"score"`
	} `json:"severity"`
	Affected   []osvAffected `json:"affected"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
}

type osvAffected struct {
	Package osvPkg `json:"package"`
	Ranges  []struct {
		Type   string              `json:"type"`   // ECOSYSTEM, GIT, SEMVER
		Events []map[string]string `json:"events"` // {"introduced":"..."} / {"fixed":"..."}
	} `json:"ranges"`
	EcosystemSpecific json.RawMessage `json:"ecosystem_specific,omitempty"`
}

// ubuntuEcosystem maps an Ubuntu version ID to the OSV ecosystem name.
// LTS releases are YY.04 with an even year.
func ubuntuEcosystem(versionID string) (string, bool) {
	if versionID == "" {
		return "", false
	}
	parts := strings.Split(versionID, ".")
	if len(parts) != 2 {
		return "", false
	}
	year, month := parts[0], parts[1]
	if month == "04" && len(year) == 2 && (year[1]-'0')%2 == 0 {
		return "Ubuntu:" + versionID + ":LTS", true
	}
	return "Ubuntu:" + versionID, true
}

// UbuntuQuerySource builds the per-package OSV query source. The cache key
// includes the exact package name and version so offline reruns of the same
// system hit the cache without network.
func UbuntuQuerySource(eco, pkgName, pkgVersion string) FeedSource {
	body, _ := json.Marshal(osvQuery{
		Package: osvPkg{Ecosystem: eco, Name: pkgName},
		Version: pkgVersion,
	})
	return FeedSource{
		Provider:  ProviderUbuntuOSV,
		Distro:    "ubuntu",
		Release:   eco + "|" + pkgName + "@" + pkgVersion,
		URL:       osvQueryURL,
		MaxBytes:  osvMaxBodyB,
		Freshness: 24 * time.Hour,
		Method:    "POST",
		Body:      string(body),
		Format:    "osv-response",
		// OSV Ubuntu keys records on source packages; the response spans
		// many releases, so parsing is restricted to the queried pair.
		MatchEcosystem: eco,
		MatchPackage:   pkgName,
	}
}

// loadOSVResponse normalizes an OSV query response without ecosystem or
// package filtering (used by tests and by unfiltered consumers).
func loadOSVResponse(r *bufio.Reader) ([]Advisory, string, error) {
	return loadOSVResponseFiltered(r, "", "")
}

// loadOSVResponseFiltered normalizes an OSV query response, keeping only
// affected[] entries for the queried ecosystem and package. OSV records span
// many releases; the version query only matched one of them.
func loadOSVResponseFiltered(r *bufio.Reader, matchEco, matchPkg string) ([]Advisory, string, error) {
	var resp osvResponse
	dec := json.NewDecoder(bufio.NewReaderSize(r, 1<<20))
	if err := dec.Decode(&resp); err != nil {
		return nil, "", fmt.Errorf("OSV JSON invalid: %w", err)
	}
	var out []Advisory
	for _, v := range resp.Vulns {
		cve := canonicalCVE(v)
		if cve == "" {
			continue
		}
		for _, aff := range v.Affected {
			if matchEco != "" && aff.Package.Ecosystem != matchEco {
				continue
			}
			if matchPkg != "" && aff.Package.Name != matchPkg {
				continue
			}
			fixed, introduced := osvFixedEvent(aff)
			if fixed == "" && introduced == "" {
				continue
			}
			sev, score, source, vector := osvSeverity(v)
			out = append(out, Advisory{
				Provider:     ProviderUbuntuOSV,
				DistroID:     "ubuntu",
				Release:      aff.Package.Ecosystem,
				CVE:          cve,
				AdvisoryID:   v.ID,
				Package:      aff.Package.Name,
				AffectedFrom: introduced,
				FixedVersion: fixed,
				Status:       "affected",
				Normalized:   "affected",
				Severity:     sev,
				CVSSScore:    score,
				CVSSSource:   source,
				CVSSVector:   vector,
				Published:    v.Published,
				Modified:     v.Modified,
				Withdrawn:    v.Withdrawn,
				SourceURL:    osvQueryURL,
			})
			break // one advisory per queried package record
		}
	}
	return out, "", nil
}

// canonicalCVE resolves the CVE id for an OSV record, preferring the alias
// list over the record id. Ubuntu OSV ids carry the CVE directly
// ("UBUNTU-CVE-2024-1086"); Livepatch notices (LSN-*) have none and are
// skipped.
func canonicalCVE(v osvVuln) string {
	if strings.HasPrefix(v.ID, "CVE-") {
		return v.ID
	}
	if strings.HasPrefix(v.ID, "UBUNTU-CVE-") {
		return strings.TrimPrefix(v.ID, "UBUNTU-")
	}
	for _, a := range v.Aliases {
		if strings.HasPrefix(a, "CVE-") {
			return a
		}
	}
	return ""
}

// osvFixedEvent extracts the fixed (and introduced) events for an affected
// range. Only ECOSYSTEM ranges carry distribution package versions.
func osvFixedEvent(aff osvAffected) (fixed, introduced string) {
	for _, rng := range aff.Ranges {
		if rng.Type != "ECOSYSTEM" {
			continue
		}
		for _, ev := range rng.Events {
			if f, ok := ev["fixed"]; ok && fixed == "" {
				fixed = f
			}
			if i, ok := ev["introduced"]; ok && introduced == "" {
				introduced = i
			}
		}
	}
	return fixed, introduced
}

// osvSeverity picks the strongest CVSS the record carries, preserving the
// score source and version (CVSS 2.0 / 3.1 / 4.0 are never mixed). Word
// severities from vendor-specific entries ("Ubuntu": "medium") map to the
// finding severity vocabulary; unknown forms stay empty rather than guessed.
func osvSeverity(v osvVuln) (severity, score, source, vector string) {
	for _, s := range v.Severity {
		switch s.Type {
		case "CVSS_V4":
			if score == "" || strings.HasPrefix(score, "CVSS:4") {
				score, source, vector = s.Score, "CVSS 4.0", s.Score
			}
		case "CVSS_V3":
			if score == "" {
				score, source, vector = s.Score, "CVSS 3.1", s.Score
			}
		case "CVSS_V2":
			if score == "" {
				score, source, vector = s.Score, "CVSS 2.0", s.Score
			}
		default:
			if severity == "" {
				severity = mapSeverity(s.Score)
			}
		}
	}
	return severity, score, source, vector
}

// QueryUbuntuOSV queries OSV for one installed Ubuntu kernel package and
// normalizes the response. Only AFFECTED records can come back: an empty
// response means "no known vulnerability for this exact version", which is
// recorded as a note, never as per-CVE NOT_AFFECTED evidence.
func (fc *FeedClient) QueryUbuntuOSV(ctx context.Context, eco, name, version string) (FeedResult, error) {
	src := UbuntuQuerySource(eco, name, version)
	return fc.LoadFeed(ctx, src)
}

// MatchUbuntu turns one Ubuntu OSV query result into findings for the
// queried package.
func MatchUbuntu(p kernel.KernelPackage, advisories []Advisory, trust string, eco string) []Finding {
	var out []Finding
	for i := range advisories {
		rec := &advisories[i]
		f := Finding{
			CVE:              rec.CVE,
			AdvisoryID:       rec.AdvisoryID,
			Distro:           "ubuntu",
			Release:          eco,
			Package:          p.Name,
			SourcePackage:    p.SourcePackage,
			InstalledVersion: p.Version,
			FixedVersion:     rec.FixedVersion,
			KernelRelease:    p.KernelRelease,
			Flavor:           p.Flavor,
			Severity:         rec.Severity,
			CVSSScore:        rec.CVSSScore,
			CVSSSource:       rec.CVSSSource,
			CVSSVector:       rec.CVSSVector,
			Published:        rec.Published,
			Modified:         rec.Modified,
			Provider:         ProviderUbuntuOSV,
			DataTrust:        trust,
			MatchingMethod:   MatchVendorStatus,
			Confidence:       "confirmed",
			State:            StateAffected,
			Explanation:      "Ubuntu OSV records the exact installed version " + p.Version + " of " + p.Name + " inside the affected range" + fixedSuffix(rec.FixedVersion),
		}
		if rec.Modified != "" {
			f.Modified = rec.Modified
		}
		if rec.Withdrawn != "" {
			// Withdrawn records are context, never live advisories.
			f.State = StateUnverified
			f.Confidence = "unverified"
			f.Explanation = "the OSV record for this CVE was withdrawn by its publisher; the withdrawal reason is not machine-readable, so no verdict is claimed"
		}
		out = append(out, f)
	}
	sortFindings(out)
	return out
}

func fixedSuffix(fixed string) string {
	if fixed != "" {
		return "; the fix is " + fixed
	}
	return "; no fixed version is published yet"
}

// ---------------------------------------------------------------------------
// Upstream kernel (OSV "Linux" ecosystem) — supplemental only
// ---------------------------------------------------------------------------

// upstreamVerRe extracts the upstream kernel version from a uname release.
var upstreamVerRe = regexp.MustCompile(`(\d+\.\d+(\.\d+)?)`)

// UpstreamVersionOf returns the plain upstream version ("6.6.58") from a
// release string, or "" when the release has no parseable upstream prefix.
func UpstreamVersionOf(release string) string {
	if release == "" {
		return ""
	}
	m := upstreamVerRe.FindStringSubmatch(release)
	if m == nil {
		return ""
	}
	return m[1]
}

// UpstreamQuerySource builds the NVD CPE query for the upstream kernel
// version. The OSV "Linux" ecosystem keys records on git commit ranges, so
// version queries there return nothing; NVD's CPE index
// (cpe:2.3:o:linux:linux_kernel:<version>) is the machine-readable upstream
// source that matches by version. RONDA transmits only the upstream kernel
// version, nothing else.
func UpstreamQuerySource(upstreamVersion string) FeedSource {
	cpe := "cpe:2.3:o:linux:linux_kernel:" + upstreamVersion + ":*:*:*:*:*:*:*"
	return FeedSource{
		Provider:  ProviderOSV,
		Distro:    "linux",
		Release:   "upstream@" + upstreamVersion,
		URL:       nvdCVEURL + "?cpeName=" + cpe + "&resultsPerPage=" + strconv.Itoa(upstreamMaxResults),
		MaxBytes:  osvMaxBodyB,
		Freshness: 24 * time.Hour,
		Format:    "nvd-upstream",
	}
}

// upstreamMaxResults bounds one upstream listing.
const upstreamMaxResults = 200

// QueryUpstream fetches upstream kernel CVEs for one upstream version and
// returns them as UpstreamHits. These are never distribution-confirmed
// findings and are reported separately with an explicit non-applicability
// note.
func (fc *FeedClient) QueryUpstream(ctx context.Context, upstreamVersion string) ([]UpstreamHit, FeedResult, error) {
	res, err := fc.LoadFeed(ctx, UpstreamQuerySource(upstreamVersion))
	if err != nil || res.Miss {
		return nil, res, err
	}
	var out []UpstreamHit
	for _, a := range res.Entry.Advisories {
		if a.Normalized == "withdrawn" {
			// Withdrawn upstream records are dropped from the context list;
			// the cache entry still records them for transparency.
			continue
		}
		out = append(out, UpstreamHit{
			CVE:             a.CVE,
			UpstreamVersion: upstreamVersion,
			Published:       a.Published,
			Modified:        a.Modified,
			Severity:        a.Severity,
			Summary:         a.Status,
			Source:          a.Provider,
			Note:            "upstream kernel record; distributions backport fixes and renumber versions, so this is context only and never a distribution-confirmed vulnerability",
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].CVE < out[j].CVE })
	return out, res, nil
}

// loadNVDUpstream parses an NVD cves/2.0 CPE listing into upstream-only
// advisories. Records stay UPSTREAM_ONLY forever: they are context, never
// distribution findings.
func loadNVDUpstream(r *bufio.Reader) ([]Advisory, string, error) {
	var resp struct {
		ResultsPerPage  int `json:"resultsPerPage"`
		TotalResults    int `json:"totalResults"`
		Vulnerabilities []struct {
			CVE struct {
				ID           string `json:"id"`
				Published    string `json:"published"`
				LastModified string `json:"lastModified"`
				VulnStatus   string `json:"vulnStatus"`
				Metrics      map[string][]struct {
					CVSSData struct {
						BaseScore    float64 `json:"baseScore"`
						VectorString string  `json:"vectorString"`
					} `json:"cvssData"`
				} `json:"metrics"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}
	dec := json.NewDecoder(bufio.NewReaderSize(r, 1<<20))
	if err := dec.Decode(&resp); err != nil {
		return nil, "", fmt.Errorf("NVD JSON invalid: %w", err)
	}
	var out []Advisory
	for _, v := range resp.Vulnerabilities {
		c := v.CVE
		if !isValidCVE(c.ID) {
			continue
		}
		a := Advisory{
			Provider:   ProviderNVD,
			DistroID:   "linux",
			Release:    "upstream",
			CVE:        c.ID,
			Package:    "kernel",
			Status:     c.VulnStatus,
			Normalized: "affected",
			Published:  c.Published,
			Modified:   c.LastModified,
			SourceURL:  nvdCVEURLProduction,
		}
		if strings.EqualFold(c.VulnStatus, "Rejected") {
			a.Normalized = "withdrawn"
		}
		if m, ok := c.Metrics["cvssMetricV31"]; ok && len(m) > 0 {
			a.CVSSScore = fmt.Sprintf("%g", m[0].CVSSData.BaseScore)
			a.CVSSVector = m[0].CVSSData.VectorString
			a.CVSSSource = "CVSS 3.1"
		} else if m, ok := c.Metrics["cvssMetricV40"]; ok && len(m) > 0 {
			a.CVSSScore = fmt.Sprintf("%g", m[0].CVSSData.BaseScore)
			a.CVSSVector = m[0].CVSSData.VectorString
			a.CVSSSource = "CVSS 4.0"
		} else if m, ok := c.Metrics["cvssMetricV2"]; ok && len(m) > 0 {
			a.CVSSScore = fmt.Sprintf("%g", m[0].CVSSData.BaseScore)
			a.CVSSVector = m[0].CVSSData.VectorString
			a.CVSSSource = "CVSS 2.0"
		}
		out = append(out, a)
		if len(out) >= upstreamMaxResults {
			break
		}
	}
	return out, "", nil
}

// ---------------------------------------------------------------------------
// NVD — supplemental enrichment, opt-in, strictly rate limited
// ---------------------------------------------------------------------------

// nvdLimiter spaces NVD API calls by at least 6 seconds: the public NVD API
// allows 5 requests per 30 seconds without an API key.
var nvdLimiter = time.NewTicker(6 * time.Second)

// NVDLookup fetches one CVE record from NVD. Used only for optional
// enrichment (--enrich); the default path never calls NVD.
func (fc *FeedClient) NVDLookup(ctx context.Context, cve string) (NVDRecord, error) {
	<-nvdLimiter.C
	url := nvdCVEURL + "?cveId=" + cve
	data, err := fc.HTTP.Get(ctx, url)
	if err != nil {
		return NVDRecord{}, err
	}
	return ParseNVD(data)
}

// NVDRecord is the parsed subset of an NVD CVE record.
type NVDRecord struct {
	CVE        string   `json:"id"`
	Published  string   `json:"published"`
	Modified   string   `json:"lastModified"`
	Status     string   `json:"vulnStatus"` // Analyzed, Modified, Rejected, Awaiting Analysis
	Withdrawn  bool     `json:"-"`
	Summary    string   `json:"summary,omitempty"`
	CVSSScore  string   `json:"cvssScore,omitempty"`
	CVSSSource string   `json:"cvssSource,omitempty"`
	CVSSVector string   `json:"cvssVector,omitempty"`
	References []string `json:"references,omitempty"`
}

// ParseNVD extracts the CVE fields from an NVD cves/2.0 response. Withdrawn
// ("Rejected") records are flagged and never enriched into findings.
func ParseNVD(data []byte) (NVDRecord, error) {
	var resp struct {
		Vulnerabilities []struct {
			CVE struct {
				ID           string `json:"id"`
				Published    string `json:"published"`
				LastModified string `json:"lastModified"`
				VulnStatus   string `json:"vulnStatus"`
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
				Metrics map[string][]struct {
					CVSSData struct {
						BaseScore    float64 `json:"baseScore"`
						VectorString string  `json:"vectorString"`
						Version      string  `json:"version"`
					} `json:"cvssData"`
					Source string `json:"source"`
				} `json:"metrics"`
				References []struct {
					URL string `json:"url"`
				} `json:"references"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return NVDRecord{}, fmt.Errorf("NVD JSON invalid: %w", err)
	}
	var out NVDRecord
	for _, v := range resp.Vulnerabilities {
		c := v.CVE
		out = NVDRecord{CVE: c.ID, Published: c.Published, Modified: c.LastModified, Status: c.VulnStatus}
		if strings.EqualFold(c.VulnStatus, "Rejected") {
			out.Withdrawn = true
		}
		for _, d := range c.Descriptions {
			if d.Lang == "en" && out.Summary == "" {
				out.Summary = d.Value
			}
		}
		// Prefer the newest CVSS version present; never mix scales.
		if m, ok := c.Metrics["cvssMetricV40"]; ok && len(m) > 0 {
			out.CVSSScore = fmt.Sprintf("%g", m[0].CVSSData.BaseScore)
			out.CVSSVector = m[0].CVSSData.VectorString
			out.CVSSSource = "NVD CVSS 4.0"
		} else if m, ok := c.Metrics["cvssMetricV31"]; ok && len(m) > 0 {
			out.CVSSScore = fmt.Sprintf("%g", m[0].CVSSData.BaseScore)
			out.CVSSVector = m[0].CVSSData.VectorString
			out.CVSSSource = "NVD CVSS 3.1"
		} else if m, ok := c.Metrics["cvssMetricV2"]; ok && len(m) > 0 {
			out.CVSSScore = fmt.Sprintf("%g", m[0].CVSSData.BaseScore)
			out.CVSSVector = m[0].CVSSData.VectorString
			out.CVSSSource = "NVD CVSS 2.0"
		}
		for _, r := range c.References {
			out.References = append(out.References, r.URL)
		}
		return out, nil
	}
	return out, fmt.Errorf("CVE not found in NVD response")
}
