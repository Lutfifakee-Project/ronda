package kernelintel

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/Lutfifakee-Project/ronda/internal/kernel"
	"github.com/Lutfifakee-Project/ronda/internal/versioncmp"
)

// debianTrackerURL is the Debian Security Tracker's machine-readable
// dataset. It is one large JSON object keyed by source package; RONDA
// streams it and keeps only the kernel source package entries.
const debianTrackerURLProduction = "https://security-tracker.debian.org/tracker/data/json"

// Test-overridable feed endpoints; the official client allowlist still
// decides reachability.
var debianTrackerURL = debianTrackerURLProduction

// debianCodenames maps Debian version IDs to suite codenames. Versions not
// in the map make release-scoped matching UNVERIFIED rather than guessed.
var debianCodenames = map[string]string{
	"8":  "jessie",
	"9":  "stretch",
	"10": "buster",
	"11": "bullseye",
	"12": "bookworm",
	"13": "trixie",
	"14": "forky",
}

// DebianSource returns the feed source for one Debian codename.
func DebianSource(codename string) FeedSource {
	return FeedSource{
		Provider:  ProviderDebian,
		Distro:    "debian",
		Release:   codename,
		URL:       debianTrackerURL,
		MaxBytes:  512 << 20, // the full tracker JSON; streamed to disk
		Freshness: 24 * time.Hour,
		Format:    "debian-tracker",
	}
}

// DebianCodename resolves the codename for a Debian version ID.
func DebianCodename(versionID string) (string, bool) {
	cn, ok := debianCodenames[versionID]
	return cn, ok
}

// debianTrackerEntry is one CVE record for one source package in the
// tracker JSON.
type debianTrackerEntry struct {
	Description string                         `json:"description"`
	Releases    map[string]debianReleaseStatus `json:"releases"`
	Debianbug   int                            `json:"debianbug"`
}

type debianReleaseStatus struct {
	Status       string            `json:"status"`        // resolved, vulnerable, ignored, open, undetermined, end-of-life
	FixedVersion string            `json:"fixed_version"` // empty when unfixed
	Urgency      string            `json:"urgency"`       // high, medium, low, unimportant, not yet assigned
	Repositories map[string]string `json:"repositories"`
	NodeName     string            `json:"node_name"`
}

// loadDebianTracker streams the tracker JSON, keeping only kernel source
// packages ("linux", "linux-signed*", "linux-*" flavors). The dataset has no
// feed-declared generation timestamp; the cache records the fetch time and
// reports never invent one.
func loadDebianTracker(r *bufio.Reader) ([]Advisory, string, error) {
	return loadDebianTrackerRelease(r, "")
}

// debianTrackerLoader returns a loader that retains only the records of one
// Debian release. The tracker JSON carries every release at once, but a
// cache entry is keyed per release (CacheKey includes the release) and
// MatchDebian consumes only same-release records, so retaining the other
// releases multiplied parse, cache-write and cache-load memory roughly
// sevenfold without changing any verdict. An empty keepRelease retains all
// releases (used by the generic loader and by tests).
func debianTrackerLoader(keepRelease string) LoadFunc {
	return func(r *bufio.Reader) ([]Advisory, string, error) {
		return loadDebianTrackerRelease(r, keepRelease)
	}
}

// debianReleasesFor decodes a "releases" object while discarding every
// release except Keep. Status values of dropped releases are never buffered
// beyond one json.RawMessage at a time.
type debianReleasesFor struct {
	Keep    string
	Status  debianReleaseStatus
	Present bool
}

func (d *debianReleasesFor) UnmarshalJSON(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return fmt.Errorf("tracker releases must be an object")
	}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := keyTok.(string)
		if !ok {
			return fmt.Errorf("tracker releases key is not a string")
		}
		if key == d.Keep {
			if err := dec.Decode(&d.Status); err != nil {
				return err
			}
			d.Present = true
		} else {
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return err
			}
		}
	}
	_, err = dec.Token() // closing '}'
	return err
}

// decodeDebianScopedEntries walks one tracker source's entry object and
// appends advisories for keepRelease only. It runs while the decoder sits on
// the entry object value, so entries are never buffered as a whole. It
// returns reached=true when the advisory bound was hit mid-source; the
// remaining entries of this source are skipped exactly like the unscoped
// path's early return.
func decodeDebianScopedEntries(dec *json.Decoder, keepRelease, source string, out *[]Advisory) (bool, error) {
	tok, err := dec.Token()
	if err != nil {
		return false, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return false, fmt.Errorf("tracker entries for %s must be an object", source)
	}
	for dec.More() {
		idTok, err := dec.Token()
		if err != nil {
			return false, err
		}
		id, ok := idTok.(string)
		if !ok {
			return false, fmt.Errorf("tracker entry key for %s is not a string", source)
		}
		cve := debianCVEID(id)
		var entry struct {
			Releases debianReleasesFor `json:"releases"`
		}
		entry.Releases.Keep = keepRelease
		if err := dec.Decode(&entry); err != nil {
			return false, fmt.Errorf("tracker entry %s for %s: %w", id, source, err)
		}
		if cve == "" || !entry.Releases.Present {
			continue
		}
		st := entry.Releases.Status
		normalized := debianNormalized(st.Status)
		if normalized == "" {
			continue
		}
		*out = append(*out, Advisory{
			Provider:     ProviderDebian,
			DistroID:     "debian",
			Release:      keepRelease,
			CVE:          cve,
			Package:      source,
			FixedVersion: st.FixedVersion,
			Status:       st.Status,
			Normalized:   normalized,
			Severity:     debianSeverity(st.Urgency),
			References:   []string{debianTrackerRefURL(cve)},
			SourceURL:    debianTrackerURL,
		})
		if len(*out) >= maxAdvisoriesPerFeed {
			// Deterministic truncation: sort what was retained and stop reading.
			sortDebianAdvisories(*out)
			_, _ = dec.Token() // consume the closing '}'
			return true, nil
		}
	}
	_, err = dec.Token() // closing '}'
	return false, err
}

// loadDebianTrackerRelease streams the tracker JSON. When keepRelease is
// non-empty, only advisories for that release are retained.
func loadDebianTrackerRelease(r *bufio.Reader, keepRelease string) ([]Advisory, string, error) {
	dec := json.NewDecoder(bufio.NewReaderSize(r, 1<<20))
	tok, err := dec.Token()
	if err != nil {
		return nil, "", fmt.Errorf("tracker JSON must be an object: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, "", fmt.Errorf("tracker JSON must be an object")
	}
	var out []Advisory
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, "", err
		}
		source, ok := keyTok.(string)
		if !ok {
			return nil, "", fmt.Errorf("tracker JSON object key is not a string")
		}
		if !isDebianKernelSource(source) {
			// Skip non-kernel packages without buffering them.
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return nil, "", err
			}
			continue
		}
		if keepRelease != "" {
			// Release-scoped path: walk the entry object token by token and
			// decode each entry with the release filter, so neither the other
			// suites' status maps nor a materialized entry map ever exists.
			reached, err := decodeDebianScopedEntries(dec, keepRelease, source, &out)
			if err != nil {
				return nil, "", err
			}
			if reached {
				sortDebianAdvisories(out)
				return out, "", nil
			}
			continue
		}
		var entries map[string]debianTrackerEntry
		if err := dec.Decode(&entries); err != nil {
			return nil, "", fmt.Errorf("tracker entries for %s: %w", source, err)
		}
		// Iterate deterministically. Go map iteration order is randomized per
		// run, so an unordered walk combined with the advisory bound below
		// retained a random subset of CVEs and made matching non-reproducible
		// (observed during acceptance: two parses of the byte-identical tracker
		// response kept disjoint ~5000-CVE subsets). Sorted keys give
		// byte-identical advisories for identical input, truncation included.
		ids := make([]string, 0, len(entries))
		for id := range entries {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			cve := debianCVEID(id)
			if cve == "" {
				continue // DSA-/TEMP-keyed records carry no CVE identifier
			}
			entry := entries[id]
			releases := make([]string, 0, len(entry.Releases))
			for release := range entry.Releases {
				releases = append(releases, release)
			}
			sort.Strings(releases)
			for _, release := range releases {
				if keepRelease != "" && release != keepRelease {
					continue // release-scoped entry: other releases never match
				}
				st := entry.Releases[release]
				normalized := debianNormalized(st.Status)
				if normalized == "" {
					continue
				}
				out = append(out, Advisory{
					Provider:     ProviderDebian,
					DistroID:     "debian",
					Release:      release,
					CVE:          cve,
					Package:      source,
					FixedVersion: st.FixedVersion,
					Status:       st.Status,
					Normalized:   normalized,
					Severity:     debianSeverity(st.Urgency),
					References:   []string{debianTrackerRefURL(cve)},
					SourceURL:    debianTrackerURL,
				})
				if len(out) >= maxAdvisoriesPerFeed {
					sort.SliceStable(out, func(i, j int) bool {
						if out[i].CVE != out[j].CVE {
							return out[i].CVE < out[j].CVE
						}
						return out[i].Package < out[j].Package
					})
					return out, "", nil
				}
			}
		}
	}
	if _, err := dec.Token(); err != nil { // closing '}'
		if err != io.EOF {
			return nil, "", err
		}
	}
	return out, "", nil
}

// debianTrackerRefURL returns the canonical tracker page for one CVE.
func debianTrackerRefURL(cve string) string {
	return "https://security-tracker.debian.org/tracker/" + cve
}

// sortDebianAdvisories orders by CVE then package (the deterministic order
// used for truncation and cache writes).
func sortDebianAdvisories(out []Advisory) {
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].CVE != out[j].CVE {
			return out[i].CVE < out[j].CVE
		}
		return out[i].Package < out[j].Package
	})
}

// maxAdvisoriesPerFeed bounds memory against a hostile or oversized feed.
// It is sized above the real Debian tracker kernel family (roughly 90,000
// release records from ~21,000 linux CVEs across tracked releases, plus the
// linux-* flavor sources) so legitimate vendor data is never silently
// truncated: the earlier 20,000 bound cut the linux source mid-stream and,
// combined with randomized map iteration, made every run assess a different
// random CVE subset. It is a var so tests can pin deterministic truncation.
var maxAdvisoriesPerFeed = 200000

// isDebianKernelSource filters tracker source packages to the kernel family.
func isDebianKernelSource(source string) bool {
	return source == "linux" || strings.HasPrefix(source, "linux-")
}

// debianCVEID extracts the CVE identifier from a tracker entry key. DSA-,
// TEMP-keyed and malformed entries return "" (they are not reported).
func debianCVEID(id string) string {
	if isValidCVE(id) {
		return id
	}
	return ""
}

// debianNormalized maps tracker status keywords to the normalized states.
func debianNormalized(status string) string {
	switch status {
	case "resolved":
		return "resolved"
	case "vulnerable", "open":
		return "affected"
	case "ignored":
		return "not-affected" // Debian: negligible impact or not applicable
	case "undetermined":
		return "under-investigation"
	case "end-of-life":
		return "end-of-life"
	}
	return ""
}

// debianSeverity maps tracker urgency to the finding severity vocabulary.
func debianSeverity(urgency string) string {
	switch urgency {
	case "high":
		return "HIGH"
	case "medium":
		return "MEDIUM"
	case "low":
		return "LOW"
	case "unimportant":
		return "LOW"
	}
	return ""
}

// MatchDebian evaluates installed Debian/Ubuntu packages against tracker
// records for one release. The vendor fixed_version decides via the dpkg
// comparator; upstream kernel versions are never consulted.
func MatchDebian(release string, packages []kernel.KernelPackage, advisories []Advisory, trust string) []Finding {
	// Index advisories by source package.
	bySource := make(map[string][]*Advisory)
	for i := range advisories {
		if advisories[i].Release != release {
			continue
		}
		bySource[advisories[i].Package] = append(bySource[advisories[i].Package], &advisories[i])
	}
	if len(bySource) == 0 {
		return nil
	}
	var out []Finding
	for _, p := range packages {
		if p.Ecosystem != kernel.EcosystemDPKG || p.Version == "" {
			continue
		}
		src := p.SourcePackage
		if src == "" {
			// Without a source mapping the binary name is the only key;
			// Debian kernel binary packages ("linux-image-6.1.0-18-amd64")
			// are not tracker keys, so this stays UNVERIFIED per package.
			if !isDebianKernelSource(p.Name) {
				continue
			}
			src = p.Name
		}
		records := bySource[src]
		for _, rec := range records {
			out = append(out, debianFinding(p, rec, trust))
		}
	}
	sortFindings(out)
	return out
}

// debianFinding builds one Finding from a tracker record.
func debianFinding(p kernel.KernelPackage, rec *Advisory, trust string) Finding {
	f := Finding{
		CVE:              rec.CVE,
		Distro:           rec.DistroID,
		Release:          rec.Release,
		Package:          p.Name,
		SourcePackage:    p.SourcePackage,
		InstalledVersion: p.Version,
		FixedVersion:     rec.FixedVersion,
		KernelRelease:    p.KernelRelease,
		Flavor:           p.Flavor,
		Severity:         rec.Severity,
		Published:        rec.Published,
		Modified:         rec.Modified,
		References:       rec.References,
		Provider:         rec.Provider,
		DataTrust:        trust,
		MatchingMethod:   MatchVendorStatus,
		Confidence:       "confirmed",
		AdvisoryID:       rec.AdvisoryID,
	}
	switch rec.Normalized {
	case "resolved":
		if rec.FixedVersion == "" {
			// "resolved" without a fixed version happens for not-affected
			// resolutions; Debian's authoritative wording is preserved and
			// the verdict stays unclaimed.
			f.State = StateUnverified
			f.Confidence = "unverified"
			f.MatchingMethod = MatchUnverified
			f.Explanation = "Debian marks this resolved but publishes no fixed version for " + rec.Release + "; state UNVERIFIED"
			return f
		}
		c, err := versioncmp.CompareDebian(p.Version, rec.FixedVersion)
		if err != nil {
			f.State = StateUnverified
			f.Confidence = "unverified"
			f.MatchingMethod = MatchUnverified
			f.Explanation = "installed or fixed version did not parse under Debian rules: " + err.Error()
			return f
		}
		if c < 0 {
			f.State = StateAffected
			f.Explanation = "Debian marks the source package " + rec.Package + " resolved in " + rec.Release +
				" with fix " + rec.FixedVersion + "; installed " + p.Version + " is older, so the package is affected (distributions backport fixes: only Debian's own fixed_version decides)"
		} else {
			f.State = StateFixed
			f.Explanation = "installed " + p.Version + " is at or after Debian's fixed version " + rec.FixedVersion + " for " + rec.Release
		}
	case "affected":
		f.State = StateAffected
		if rec.FixedVersion != "" {
			f.Explanation = "Debian reports the source package vulnerable in " + rec.Release + "; fix " + rec.FixedVersion + " exists upstream of the installed " + p.Version
		} else {
			f.Explanation = "Debian reports the source package vulnerable in " + rec.Release + " with no fix released yet; installed " + p.Version
		}
	case "not-affected":
		f.State = StateNotAffected
		f.Explanation = "Debian marks this issue ignored for " + rec.Release + " (negligible impact or not applicable to the package); vendor status is authoritative"
	case "under-investigation":
		f.State = StateUnderInvestigation
		f.Confidence = "unverified"
		f.Explanation = "Debian has not determined the status for " + rec.Release + " yet"
	case "end-of-life":
		f.State = StateUnverified
		f.Confidence = "unverified"
		f.Explanation = "the package reached end-of-life in " + rec.Release + "; Debian no longer evaluates this issue for it"
	default:
		f.State = StateUnverified
		f.Confidence = "unverified"
		f.Explanation = "unrecognized tracker status " + rec.Status
	}
	return f
}

// sortFindings orders findings by CVE then package for stable output.
func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].CVE != fs[j].CVE {
			return fs[i].CVE < fs[j].CVE
		}
		return fs[i].Package < fs[j].Package
	})
}
