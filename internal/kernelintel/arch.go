package kernelintel

import (
	"bufio"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Lutfifakee-Project/ronda/internal/kernel"
	"github.com/Lutfifakee-Project/ronda/internal/versioncmp"
)

// Arch Security Team "AVG" dataset: one JSON array of advisories covering
// every tracked package, including the kernel flavors.
const archAVGURLProduction = "https://security.archlinux.org/issues/all.json"

var archAVGURL = archAVGURLProduction

// ArchSource returns the feed source for the Arch security dataset.
func ArchSource() FeedSource {
	return FeedSource{
		Provider:  ProviderArch,
		Distro:    "arch",
		Release:   "rolling",
		URL:       archAVGURL,
		MaxBytes:  32 << 20,
		Freshness: 6 * time.Hour,
		Format:    "arch-avg",
	}
}

// avgEntry is one Arch Vulnerability Group record.
type avgEntry struct {
	Name     string   `json:"name"`
	Severity string   `json:"severity"`
	Type     string   `json:"type"`
	Affected string   `json:"affected"` // first affected pkgver-pkgrel
	Fixed    string   `json:"fixed"`    // first fixed pkgver-pkgrel
	Status   string   `json:"status"`   // Vulnerable, Fixed, Testing, Unknown
	Ticket   string   `json:"ticket"`
	Issues   []string `json:"issues"` // CVE ids
	Packages []string `json:"packages"`
}

// loadArchAVG parses the AVG dataset, keeping kernel packages only. The
// dataset declares no generation timestamp.
func loadArchAVG(r *bufio.Reader) ([]Advisory, string, error) {
	var entries []avgEntry
	dec := json.NewDecoder(bufio.NewReaderSize(r, 1<<20))
	if err := dec.Decode(&entries); err != nil {
		return nil, "", fmt.Errorf("AVG JSON invalid: %w", err)
	}
	var out []Advisory
	for _, e := range entries {
		if !containsKernelPkg(e.Packages) {
			continue
		}
		for _, cve := range e.Issues {
			if !isValidCVE(cve) {
				continue
			}
			out = append(out, Advisory{
				Provider:     ProviderArch,
				DistroID:     "arch",
				Release:      "rolling",
				CVE:          cve,
				AdvisoryID:   e.Name,
				Package:      firstKernelPkg(e.Packages),
				AffectedFrom: e.Affected,
				FixedVersion: e.Fixed,
				Status:       e.Status,
				Normalized:   archNormalized(e.Status),
				Severity:     mapSeverity(e.Severity),
				References:   []string{"https://security.archlinux.org/" + e.Name},
				SourceURL:    archAVGURL,
			})
			if len(out) >= maxAdvisoriesPerFeed {
				sortAdvisories(out)
				return out, "", nil
			}
		}
	}
	sortAdvisories(out)
	return out, "", nil
}

func containsKernelPkg(pkgs []string) bool {
	for _, p := range pkgs {
		switch p {
		case "linux", "linux-lts", "linux-zen", "linux-hardened", "linux-rt", "linux-rt-lts":
			return true
		}
	}
	return false
}

func firstKernelPkg(pkgs []string) string {
	for _, p := range pkgs {
		switch p {
		case "linux", "linux-lts", "linux-zen", "linux-hardened", "linux-rt", "linux-rt-lts":
			return p
		}
	}
	if len(pkgs) > 0 {
		return pkgs[0]
	}
	return ""
}

func archNormalized(status string) string {
	switch status {
	case "Fixed":
		return "resolved"
	case "Vulnerable":
		return "affected"
	case "Testing":
		return "under-investigation"
	}
	return "unknown"
}

// MatchArch evaluates installed Arch kernel packages against AVG records.
// AVG records carry the introducing (affected) and first fixed versions, so
// versions older than the introduction are NOT affected — a vendor-derivable
// state, unlike the secdb absence rule.
func MatchArch(packages []kernel.KernelPackage, advisories []Advisory, trust string) []Finding {
	byPkg := make(map[string][]*Advisory)
	for i := range advisories {
		byPkg[advisories[i].Package] = append(byPkg[advisories[i].Package], &advisories[i])
	}
	if len(byPkg) == 0 {
		return nil
	}
	var out []Finding
	for _, p := range packages {
		if p.Ecosystem != kernel.EcosystemPacman || p.Version == "" {
			continue
		}
		for _, rec := range byPkg[p.Name] {
			f := Finding{
				CVE:              rec.CVE,
				AdvisoryID:       rec.AdvisoryID,
				Distro:           rec.DistroID,
				Release:          rec.Release,
				Package:          p.Name,
				SourcePackage:    p.SourcePackage,
				InstalledVersion: p.Version,
				FixedVersion:     rec.FixedVersion,
				KernelRelease:    p.KernelRelease,
				Flavor:           p.Flavor,
				Severity:         rec.Severity,
				Provider:         rec.Provider,
				DataTrust:        trust,
				MatchingMethod:   MatchVendorStatus,
				Confidence:       "confirmed",
				References:       rec.References,
			}
			state, explanation := archState(p.Version, rec)
			f.State = state
			f.Explanation = explanation
			if state == StateUnverified {
				f.Confidence = "unverified"
				f.MatchingMethod = MatchUnverified
			}
			out = append(out, f)
		}
	}
	sortFindings(out)
	return out
}

// archState derives the verdict from AVG affected/fixed boundaries.
func archState(installed string, rec *Advisory) (string, string) {
	if rec.FixedVersion != "" {
		cFix, err := versioncmp.CompareArch(installed, rec.FixedVersion)
		if err != nil {
			return StateUnverified, "installed or fixed version did not parse under pacman rules: " + err.Error()
		}
		if cFix >= 0 {
			return StateFixed, "installed " + installed + " is at or after the AVG fixed version " + rec.FixedVersion
		}
	}
	if rec.AffectedFrom != "" {
		cAff, err := versioncmp.CompareArch(installed, rec.AffectedFrom)
		if err != nil {
			return StateUnverified, "installed or affected version did not parse under pacman rules: " + err.Error()
		}
		if cAff < 0 {
			return StateNotAffected, "installed " + installed + " predates the version (" + rec.AffectedFrom + ") where the AVG says the issue was introduced"
		}
		return StateAffected, "AVG records the issue for versions from " + rec.AffectedFrom + " to before " +
			orString(rec.FixedVersion, "the first fix (none released yet)") + "; installed " + installed + " is inside that range"
	}
	// No affected boundary: treat as affected when unfixed, per AVG status.
	if rec.Normalized == "affected" {
		return StateAffected, "AVG marks the package vulnerable with no fixed version released yet; installed " + installed
	}
	return StateUnderInvestigation, "AVG status " + rec.Status + " does not bound the affected range yet"
}

func orString(v, alt string) string {
	if v != "" {
		return v
	}
	return alt
}
