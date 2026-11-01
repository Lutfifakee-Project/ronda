package kernelintel

import (
	"bufio"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Lutfifakee-Project/ronda/internal/kernel"
	"github.com/Lutfifakee-Project/ronda/internal/versioncmp"
)

// Alpine secdb base URL. Branch directories hold main.json and community.json
// with per-package secfixes maps.
const alpineSecdbBaseProduction = "https://secdb.alpinelinux.org/"

var alpineSecdbBase = alpineSecdbBaseProduction

// AlpineSources returns the secdb feed sources for one Alpine branch
// ("v3.20", "edge").
func AlpineSources(branch string) []FeedSource {
	srcs := make([]FeedSource, 0, 2)
	for _, repo := range []string{"main", "community"} {
		srcs = append(srcs, FeedSource{
			Provider:  ProviderAlpine,
			Distro:    "alpine",
			Release:   branch,
			URL:       alpineSecdbBase + branch + "/" + repo + ".json",
			MaxBytes:  64 << 20,
			Freshness: 6 * time.Hour,
			Format:    "alpine-secdb",
		})
	}
	return srcs
}

// AlpineBranch resolves the secdb branch from the Alpine version ID. Edge
// versions carry "edge" or "_alpha" markers; stable branches map to "vX.Y".
func AlpineBranch(versionID string) (string, bool) {
	if versionID == "" {
		return "", false
	}
	if strings.Contains(versionID, "edge") || strings.Contains(versionID, "_alpha") {
		return "edge", true
	}
	if strings.HasPrefix(versionID, "3.") {
		if parts := strings.Split(versionID, "."); len(parts) >= 2 {
			return "v" + parts[0] + "." + parts[1], true
		}
	}
	return "", false
}

// secdbFile mirrors the secdb repository JSON structure.
type secdbFile struct {
	Distroversion string `json:"distroversion"`
	URL           string `json:"url"`
	Packages      []struct {
		Pkg struct {
			Name     string              `json:"name"`
			Secfixes map[string][]string `json:"secfixes"`
		} `json:"pkg"`
	} `json:"packages"`
}

// loadAlpineSecdb parses one secdb repository file. secfixes values are
// arrays whose elements may bundle several CVE ids separated by spaces.
// The secdb declares no feed generation timestamp.
func loadAlpineSecdb(r *bufio.Reader) ([]Advisory, string, error) {
	var file secdbFile
	dec := json.NewDecoder(bufio.NewReaderSize(r, 1<<20))
	if err := dec.Decode(&file); err != nil {
		return nil, "", fmt.Errorf("secdb JSON invalid: %w", err)
	}
	var out []Advisory
	for _, p := range file.Packages {
		name := p.Pkg.Name
		if !isAlpineKernelPackage(name) {
			continue
		}
		for fixed, cves := range p.Pkg.Secfixes {
			for _, bundled := range cves {
				for _, cve := range strings.Fields(bundled) {
					cve = strings.TrimSpace(cve)
					if !isValidCVE(cve) {
						// secdb occasionally carries malformed ids
						// (e.g. "CVE-46838"); they are dropped rather
						// than reported.
						continue
					}
					out = append(out, Advisory{
						Provider:     ProviderAlpine,
						DistroID:     "alpine",
						Release:      file.Distroversion,
						CVE:          cve,
						Package:      name,
						FixedVersion: fixed,
						Status:       "fixed",
						Normalized:   "resolved",
						References:   []string{"https://security.alpinelinux.org/vuln/" + cve},
						SourceURL:    alpineSecdbBase,
					})
					if len(out) >= maxAdvisoriesPerFeed {
						sortAdvisories(out)
						return out, "", nil
					}
				}
			}
		}
	}
	sortAdvisories(out)
	return out, "", nil
}

// isAlpineKernelPackage filters secdb package names to kernel packages.
func isAlpineKernelPackage(name string) bool {
	if name == "linux-lts" || name == "linux-virt" || name == "linux-edge" {
		return true
	}
	return strings.HasPrefix(name, "linux-") && !strings.Contains(name, "firmware") &&
		!strings.Contains(name, "headers") && !strings.Contains(name, "docs")
}

func sortAdvisories(out []Advisory) {
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].CVE != out[j].CVE {
			return out[i].CVE < out[j].CVE
		}
		return out[i].Package < out[j].Package
	})
}

// MatchSecdb evaluates installed Alpine kernel packages against secdb
// secfixes records. The secdb is a fix database: it only lists versions
// that resolve a CVE. Absence of a CVE for a branch is never interpreted
// as not-affected because the branch may predate the issue's discovery.
func MatchSecdb(branch string, packages []kernel.KernelPackage, advisories []Advisory, trust string) []Finding {
	byPkg := make(map[string][]*Advisory)
	for i := range advisories {
		if advisories[i].Release != "" && branch != "" && !strings.EqualFold(advisories[i].Release, branch) &&
			!strings.EqualFold(advisories[i].Release, strings.TrimPrefix(branch, "v")) {
			continue
		}
		byPkg[advisories[i].Package] = append(byPkg[advisories[i].Package], &advisories[i])
	}
	if len(byPkg) == 0 {
		return nil
	}
	var out []Finding
	for _, p := range packages {
		if p.Ecosystem != kernel.EcosystemAPK || p.Version == "" {
			continue
		}
		records := byPkg[p.Name]
		if records == nil {
			// Flavor metapackages and derived names: try the exact name
			// only; Alpine secfixes key on the exact package name.
			continue
		}
		for _, rec := range records {
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
				Provider:         rec.Provider,
				DataTrust:        trust,
				MatchingMethod:   MatchVendorStatus,
				Confidence:       "confirmed",
				References:       rec.References,
			}
			c, err := versioncmp.CompareAlpine(p.Version, rec.FixedVersion)
			if err != nil {
				f.State = StateUnverified
				f.Confidence = "unverified"
				f.MatchingMethod = MatchUnverified
				f.Explanation = "installed or fixed version did not parse under Alpine rules: " + err.Error()
			} else if c < 0 {
				f.State = StateAffected
				f.Explanation = "Alpine secdb records " + rec.FixedVersion + " as the fixed package version; installed " + p.Version + " is older"
			} else {
				f.State = StateFixed
				f.Explanation = "installed " + p.Version + " is at or after the secdb fixed version " + rec.FixedVersion
			}
			out = append(out, f)
		}
	}
	sortFindings(out)
	return out
}
