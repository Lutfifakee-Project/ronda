package kernelintel

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Lutfifakee-Project/ronda/internal/kernel"
)

// Red Hat Security Data API: kernel-scoped OVAL advisory listing. The query
// transmits only the package name "kernel" — no host data leaves the machine.
// RONDA never calls rpm/dnf/yum, so on RPM systems the installed package
// identity stays filesystem-derived and CVE matching is reported as
// UNVERIFIED (aggregate), per the Phase 6 spec.
const redhatOVALURLProduction = "https://access.redhat.com/hydra/rest/securitydata/cve.json?package=kernel&page=1"

const almaOSVURLProduction = "https://security.almalinux.org/osv.json"

var (
	redhatOVALURL = redhatOVALURLProduction
	almaOSVURL    = almaOSVURLProduction
)

// RedHatSources returns the kernel-scoped Red Hat security data sources.
// The listing is paged; RONDA fetches a bounded number of pages and stops
// early when a page comes back short.
func RedHatSources() []FeedSource {
	srcs := make([]FeedSource, 0, redHatPages)
	for page := 1; page <= redHatPages; page++ {
		srcs = append(srcs, FeedSource{
			Provider:  ProviderRedHat,
			Distro:    "rhel",
			Release:   fmt.Sprintf("kernel-cves-page%d", page),
			URL:       redhatListURL(page),
			MaxBytes:  64 << 20,
			Freshness: 12 * time.Hour,
			Format:    "redhat-cves",
		})
	}
	return srcs
}

// redhatListURL builds one page of the kernel CVE listing.
func redhatListURL(page int) string {
	if page <= 1 {
		return redhatOVALURL
	}
	return "https://access.redhat.com/hydra/rest/securitydata/cve.json?package=kernel&page=" + strconv.Itoa(page)
}

// redHatPages bounds how many listing pages one assessment downloads.
const redHatPages = 3

// AlmaSource returns the AlmaLinux OSV dataset source.
func AlmaSource() FeedSource {
	return FeedSource{
		Provider:  ProviderAlmaOSV,
		Distro:    "almalinux",
		Release:   "osv",
		URL:       almaOSVURL,
		MaxBytes:  256 << 20,
		Freshness: 12 * time.Hour,
		Format:    "almalinux-osv",
	}
}

// rhCVERecord is one row of the security data API kernel CVE listing. The
// listing carries the fixed kernel NVRs ("kernel-0:5.14.0-687.59.1.el9_8")
// for every affected stream instead of package_state details.
type rhCVERecord struct {
	CVE              string   `json:"CVE"`
	Severity         string   `json:"severity"`
	PublicDate       string   `json:"public_date"`
	Advisories       []string `json:"advisories"`
	AffectedPackages []string `json:"affected_packages"`
	CVSS3Score       string   `json:"cvss3_score"`
	CVSS3Vector      string   `json:"cvss3_scoring_vector"`
	ResourceURL      string   `json:"resource_url"`
	PackageState     []struct {
		ProductName  string `json:"product_name"`
		FixState     string `json:"fix_state"`
		PackageName  string `json:"package_name"`
		FixedVersion string `json:"fixed_version"`
	} `json:"package_state"`
}

// rhStream extracts the distribution stream suffix from a kernel NVR:
// "5.14.0-687.59.1.el9_8" -> "el9_8", "" when there is no known suffix.
func rhStream(nvr string) string {
	if i := strings.LastIndexByte(nvr, '.'); i > 0 {
		s := nvr[i+1:]
		if strings.HasPrefix(s, "el") || strings.HasPrefix(s, "fc") {
			return s
		}
	}
	return ""
}

// loadRedHatCVEListing parses the kernel CVE listing with a streaming
// decoder. Each row yields one advisory per kernel stream with that
// stream's fixed NVR, so aggregate disclosures can name the fix streams.
func loadRedHatCVEListing(r *bufio.Reader) ([]Advisory, string, error) {
	dec := json.NewDecoder(bufio.NewReaderSize(io.LimitReader(r, 512<<20), 1<<20))
	tok, err := dec.Token()
	if err != nil {
		return nil, "", fmt.Errorf("Red Hat security data JSON invalid: %w", err)
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil, "", fmt.Errorf("Red Hat security data JSON must start with an array or object")
	}
	var out []Advisory
	handle := func(raw json.RawMessage) error {
		var row rhCVERecord
		if err := json.Unmarshal(raw, &row); err != nil {
			return nil // tolerate malformed rows
		}
		if !isValidCVE(row.CVE) {
			return nil
		}
		refs := []string(nil)
		if row.ResourceURL != "" {
			refs = []string{row.ResourceURL}
		}
		advisoryID := ""
		if len(row.Advisories) > 0 {
			advisoryID = row.Advisories[0]
		}
		// package_state details, when the record carries them.
		streamFixed := make(map[string]string)
		for _, ps := range row.PackageState {
			if ps.PackageName == "kernel" && ps.FixedVersion != "" && ps.FixState == "affected" {
				evr := strings.TrimPrefix(ps.FixedVersion, "kernel-")
				if s := rhStream(evr); s != "" {
					streamFixed[s] = evr
				}
			}
		}
		// The listing mode reports fixed NVRs via affected_packages.
		for _, pkg := range row.AffectedPackages {
			if pkg == "kernel" || !strings.HasPrefix(pkg, "kernel") {
				continue
			}
			nvr := pkg
			if i := strings.IndexByte(nvr, ':'); i >= 0 {
				// "kernel-0:5.14.0-..." name-epoch:version-release
				nvr = nvr[strings.IndexByte(nvr, ':')+1:]
			} else if i := strings.IndexByte(nvr, '-'); i >= 0 {
				nvr = nvr[i+1:]
			}
			if s := rhStream(nvr); s != "" {
				if _, exists := streamFixed[s]; !exists {
					streamFixed[s] = nvr
				}
			}
		}
		if len(streamFixed) == 0 {
			streamFixed[""] = ""
		}
		for stream, fixed := range streamFixed {
			release := stream
			if release == "" {
				release = "multiple-streams"
			}
			out = append(out, Advisory{
				Provider:     ProviderRedHat,
				DistroID:     "rhel",
				Release:      release,
				CVE:          row.CVE,
				AdvisoryID:   advisoryID,
				Package:      "kernel",
				FixedVersion: fixed,
				Status:       "fixed",
				Normalized:   "resolved",
				Severity:     mapSeverity(row.Severity),
				CVSSScore:    row.CVSS3Score,
				CVSSSource:   "CVSS 3.1",
				CVSSVector:   row.CVSS3Vector,
				Published:    row.PublicDate,
				References:   refs,
				SourceURL:    redhatOVALURL,
			})
			if len(out) >= maxAdvisoriesPerFeed {
				return nil
			}
		}
		return nil
	}
	switch delim {
	case '{':
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return nil, "", err
			}
			key, _ := keyTok.(string)
			if key != "data" {
				var skip json.RawMessage
				if err := dec.Decode(&skip); err != nil {
					return nil, "", err
				}
				continue
			}
			if err := streamJSONArray(dec, handle); err != nil {
				return nil, "", err
			}
		}
	case '[':
		if err := streamJSONArray(dec, handle); err != nil {
			return nil, "", err
		}
	}
	return out, "", nil
}

// streamJSONArray decodes array elements one raw message at a time so the
// feed is never fully buffered in memory.
func streamJSONArray(dec *json.Decoder, fn func(json.RawMessage) error) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != '[' {
		return fmt.Errorf("expected a JSON array")
	}
	for dec.More() {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return err
		}
		if err := fn(raw); err != nil {
			return err
		}
	}
	_, err = dec.Token() // closing ']'
	return err
}

// loadAlmaOSV parses the AlmaLinux OSV dataset with a streaming decoder,
// keeping kernel packages only.
func loadAlmaOSV(r *bufio.Reader) ([]Advisory, string, error) {
	dec := json.NewDecoder(bufio.NewReaderSize(io.LimitReader(r, 512<<20), 1<<20))
	tok, err := dec.Token()
	if err != nil {
		return nil, "", fmt.Errorf("AlmaLinux OSV JSON invalid: %w", err)
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil, "", fmt.Errorf("AlmaLinux OSV JSON must start with an object or array")
	}
	var out []Advisory
	keep := func(v osvVuln) {
		cve := canonicalCVE(v)
		if cve == "" {
			return
		}
		for _, aff := range v.Affected {
			name := aff.Package.Name
			if name != "kernel" && !strings.HasPrefix(name, "kernel-") {
				continue
			}
			fixed, introduced := osvFixedEvent(aff)
			if fixed == "" && introduced == "" {
				continue
			}
			out = append(out, Advisory{
				Provider:     ProviderAlmaOSV,
				DistroID:     "almalinux",
				Release:      aff.Package.Ecosystem,
				CVE:          cve,
				AdvisoryID:   v.ID,
				Package:      name,
				AffectedFrom: introduced,
				FixedVersion: fixed,
				Status:       "affected",
				Normalized:   "affected",
				Published:    v.Published,
				Modified:     v.Modified,
				SourceURL:    almaOSVURL,
			})
			if len(out) >= maxAdvisoriesPerFeed {
				return
			}
		}
	}
	handleVuln := func(raw json.RawMessage) error {
		var v osvVuln
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil // tolerate malformed rows
		}
		keep(v)
		return nil
	}
	switch delim {
	case '{':
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return nil, "", err
			}
			key, _ := keyTok.(string)
			if key != "advisories" && key != "vulns" {
				var skip json.RawMessage
				if err := dec.Decode(&skip); err != nil {
					return nil, "", err
				}
				continue
			}
			if err := streamJSONArray(dec, handleVuln); err != nil {
				return nil, "", err
			}
		}
	case '[':
		if err := streamJSONArray(dec, handleVuln); err != nil {
			return nil, "", err
		}
	}
	sortAdvisories(out)
	return out, "", nil
}

// MatchRPM produces the honest RPM-family result: the vendor advisory set is
// available, but the installed package identity is filesystem-derived
// because the RPM database is not statically parseable. Per the Phase 6
// spec the matching is reported UNVERIFIED in aggregate — never as per-CVE
// verdicts and never as silent "no findings".
func MatchRPM(packages []kernel.KernelPackage, advisories []Advisory, provider, trust string) (findings []Finding, aggregateNote string) {
	if len(packages) == 0 {
		return nil, "no installed kernel releases identified; vendor advisories cannot be applied"
	}
	if len(advisories) == 0 {
		return nil, "the vendor feed contained no kernel advisories; absence of entries never proves absence of vulnerabilities"
	}
	releases := make(map[string]bool)
	for _, p := range packages {
		if p.KernelRelease != "" {
			releases[p.KernelRelease] = true
		}
	}
	note := fmt.Sprintf(
		"%d kernel advisories from %s cover this distribution family, referencing releases %s; the RPM package database is not statically parseable without rpm tooling, so installed package versions are UNVERIFIED and per-CVE matching is deliberately not attempted (RONDA never invokes rpm, dnf or yum)",
		len(advisories), provider, strings.Join(safeKeys(releases), ", "))
	return nil, note
}

func safeKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	if len(out) > 8 {
		out = append(out[:8], fmt.Sprintf("... (%d total)", len(out)))
	}
	return out
}
