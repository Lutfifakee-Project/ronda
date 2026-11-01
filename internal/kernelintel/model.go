// Package kernelintel implements distribution-aware Linux kernel CVE
// intelligence on top of authoritative vendor security data.
//
// Design rules enforced throughout the package:
//
//   - Vendor status is authoritative. Upstream kernel CVE ranges never
//     decide whether a distribution package is affected.
//   - Every result carries its data source, feed freshness and matching
//     method; unknown or unsupported data produces UNVERIFIED, never a
//     guess and never a silent "secure".
//   - Feed downloads use the hardened official client (HTTPS allowlist,
//     size caps, safe redirects), cache persistently across CLI invocations
//     and work offline from the cache; an offline cache miss is UNVERIFIED.
//   - Nothing is executed, nothing is modified on the target, and only the
//     minimum package identity required for a query ever leaves the host.
package kernelintel

import (
	"strings"
	"time"

	"github.com/Lutfifakee-Project/ronda/internal/kernel"
)

// Feed providers implemented in this package.
const (
	ProviderDebian    = "debian-security-tracker"
	ProviderUbuntuOSV = "ubuntu-osv"
	ProviderAlpine    = "alpine-secdb"
	ProviderArch      = "arch-security"
	ProviderRedHat    = "redhat-securitydata"
	ProviderAlmaOSV   = "almalinux-osv"
	ProviderOSV       = "osv-upstream-linux"
	ProviderNVD       = "nvd"
)

// Advisory states, mirroring the vocabulary of the vendor feeds.
const (
	// StateAffected means the vendor marked the package as affected in the
	// relevant release and no fix is installed.
	StateAffected = "AFFECTED"
	// StateFixed means the installed version is at or after the vendor fix.
	StateFixed = "FIXED"
	// StateNotAffected means the vendor explicitly marked the package not
	// affected in the relevant release (configuration, negligible impact,
	// will-not-fix decisions keep their vendor wording in the explanation).
	StateNotAffected = "NOT_AFFECTED"
	// StateUnderInvestigation means the vendor has not finished triage.
	StateUnderInvestigation = "UNDER_INVESTIGATION"
	// StateUpstreamOnly means only upstream kernel data exists; it is never
	// reported as a distribution-confirmed vulnerability.
	StateUpstreamOnly = "UPSTREAM_ONLY"
	// StatePackageNotInstalled means the advisory concerns a kernel flavor
	// or package that is not installed on this target.
	StatePackageNotInstalled = "PACKAGE_NOT_INSTALLED"
	// StateUnverified means the state could not be determined.
	StateUnverified = "UNVERIFIED"
)

// Matching methods describe how a verdict was reached.
const (
	// MatchVendorStatus means the vendor feed directly evaluated the exact
	// installed package version (Debian tracker fixed_version, OSV ranges,
	// secdb secfixes, AVG affected/fixed).
	MatchVendorStatus = "vendor-status-and-version-comparison"
	// MatchVendorRangeOnly means only a vendor version range applied; the
	// exact installed package could not be confirmed (filesystem-derived
	// RPM inventory). Matching stays UNVERIFIED in that case.
	MatchVendorRangeOnly = "vendor-range-only"
	// MatchUnverified means no authoritative evaluation exists.
	MatchUnverified = "unverified"
	// MatchUpstreamRange means the verdict came from upstream kernel data.
	MatchUpstreamRange = "upstream-version-range"
)

// Trust levels for feed data, surfaced in every report.
const (
	TrustFresh   = "fresh-official-data"
	TrustCached  = "cached-official-data"
	TrustStale   = "stale-cached-data"
	TrustNone    = "no-reference-available"
	TrustOffline = "offline-cache"
)

// Advisory is one normalized vendor vulnerability record for a kernel
// package. Fields map to the Phase 6 finding model.
type Advisory struct {
	Provider     string `json:"provider"` // Provider* constant
	DistroID     string `json:"distroId"` // debian, ubuntu, alpine, arch, ...
	Release      string `json:"release"`  // codename or version the record applies to
	CVE          string `json:"cve"`      // canonical CVE identifier
	AdvisoryID   string `json:"advisoryId,omitempty"`
	Package      string `json:"package"`                // package name the record keys on
	AffectedFrom string `json:"affectedFrom,omitempty"` // introduction version when the feed publishes one
	FixedVersion string `json:"fixedVersion,omitempty"`
	Status       string `json:"status"` // vendor status keyword, verbatim
	// Normalized is one of: affected, fixed, not-affected, under-investigation,
	// will-not-fix, unknown. It is the machine-readable vendor state.
	Normalized string   `json:"normalized"`
	Severity   string   `json:"severity,omitempty"` // vendor severity string
	CVSSScore  string   `json:"cvssScore,omitempty"`
	CVSSSource string   `json:"cvssSource,omitempty"`
	CVSSVector string   `json:"cvssVector,omitempty"`
	Published  string   `json:"published,omitempty"`
	Modified   string   `json:"modified,omitempty"`
	References []string `json:"references,omitempty"`
	// Withdrawn flags records the publisher retracted; they are context,
	// never live advisories.
	Withdrawn string `json:"withdrawn,omitempty"`
	// SourceURL is the feed URL the record was parsed from.
	SourceURL string `json:"sourceUrl"`
	// FeedUpdated is the feed-declared generation timestamp when the feed
	// provides one; never invented from scanner time.
	FeedUpdated string `json:"feedUpdated,omitempty"`
}

// CacheEntry is one cached feed snapshot.
type CacheEntry struct {
	Provider string `json:"provider"`
	Distro   string `json:"distro"`
	Release  string `json:"release"`
	URL      string `json:"url"`
	// FetchedAt is when RONDA downloaded the data (UTC).
	FetchedAt time.Time `json:"fetchedAt"`
	// FeedUpdated is the feed-declared timestamp, empty when the feed does
	// not declare one.
	FeedUpdated string `json:"feedUpdated,omitempty"`
	// RawDigest is the SHA-256 of the raw response body as downloaded.
	RawDigest string `json:"rawDigest"`
	// Advisories is the parsed, kernel-filtered subset. It is what matching
	// consumes; the raw feed is never re-parsed on later runs.
	Advisories []Advisory `json:"advisories"`
	// Digest is the SHA-256 of the canonical marshaled Advisories slice,
	// verified on every load so a tampered cache file is a miss, never a
	// trusted verdict.
	Digest string `json:"digest"`
	// Format names the parser that produced Advisories.
	Format string `json:"format"`
}

// FeedResult carries a loaded feed plus its trust state.
type FeedResult struct {
	Entry CacheEntry
	// State is one of the Trust* constants.
	State string
	// Age is the cache age of the entry (0 for fresh downloads).
	Age time.Duration
	// Note explains limitations (e.g. offline miss or stale data).
	Note string
	// Miss is true when no usable data was available.
	Miss bool
}

// FeedSource describes one fetchable feed location.
type FeedSource struct {
	Provider string
	Distro   string
	Release  string
	URL      string
	// MaxBytes bounds the raw response (disk-streamed, never fully in RAM).
	MaxBytes int64
	// Freshness is how long a cached copy stays trusted as fresh.
	Freshness time.Duration
	// Method is "GET" or "POST".
	Method string
	// Body is the minimal JSON query body for POST feeds.
	Body string
	// Format names the parser for this source.
	Format string
	// MatchEcosystem and MatchPackage restrict OSV response parsing to the
	// affected[] entries of the queried ecosystem and package; OSV records
	// span many releases and the version match only applies to one.
	MatchEcosystem string
	MatchPackage   string
}

// Assessment is the complete kernel CVE intelligence result for one target.
type Assessment struct {
	// Root and Mode mirror the kernel audit.
	Root string `json:"root,omitempty"`
	Mode string `json:"mode"`

	Identity kernel.Report `json:"identity"`

	// Findings are the per-CVE verdicts (affected, not-affected,
	// under-investigation, upstream-only), deduplicated.
	Findings []Finding `json:"findings"`

	// Upstream lists upstream-only kernel CVE context. These are never
	// distribution-confirmed vulnerabilities.
	Upstream []UpstreamHit `json:"upstream,omitempty"`

	// Lifecycle is the disclosure about release support status.
	Lifecycle LifecycleNote `json:"lifecycle"`

	// PendingReboot mirrors the identity audit's reboot assessment.
	PendingReboot *kernel.PendingReboot `json:"pendingReboot,omitempty"`

	// Feeds lists every feed consulted and its trust state.
	Feeds []FeedSummary `json:"feeds"`

	// Notes carries limitations, refusals and disclosures.
	Notes []string `json:"notes,omitempty"`

	// Duration and summary counters for the report.
	DurationMS int64         `json:"durationMs"`
	Counts     FindingCounts `json:"counts"`
}

// LifecycleNote explains the release support status.
type LifecycleNote struct {
	State string `json:"state"`
	Basis string `json:"basis,omitempty"`
	// Warning is set for EOL and extended-support states.
	Warning string `json:"warning,omitempty"`
}

// FeedSummary records one feed consultation for reporting.
type FeedSummary struct {
	Provider    string `json:"provider"`
	Release     string `json:"release,omitempty"`
	URL         string `json:"url,omitempty"`
	State       string `json:"state"`
	FetchedAt   string `json:"fetchedAt,omitempty"`
	FeedUpdated string `json:"feedUpdated,omitempty"`
	Age         string `json:"age,omitempty"`
	Records     int    `json:"records"`
	Note        string `json:"note,omitempty"`
}

// Finding is one deduplicated per-CVE verdict for one installed package.
type Finding struct {
	CVE string `json:"cve"`
	// AdvisoryID is the vendor advisory or tracker entry id, when the feed
	// has one (DSA, RHSA, AVG, USN).
	AdvisoryID string `json:"advisoryId,omitempty"`
	Distro     string `json:"distro"`
	Release    string `json:"release"`
	// Flavor is the kernel flavor of the affected installed package.
	Flavor string `json:"flavor,omitempty"`
	// Package is the affected installed binary package name.
	Package string `json:"package"`
	// SourcePackage is the source package when known from package metadata.
	SourcePackage string `json:"sourcePackage,omitempty"`
	// InstalledVersion is the exact installed package version.
	InstalledVersion string `json:"installedVersion"`
	// RunningRelease is the running kernel release on live hosts; empty for
	// offline targets.
	RunningRelease string `json:"runningRelease,omitempty"`
	// FixedVersion is the vendor fixed package version when known.
	FixedVersion string `json:"fixedVersion,omitempty"`
	// State is one of the State* constants.
	State string `json:"state"`
	// Severity is CRITICAL/HIGH/MEDIUM/LOW mapped from vendor data; empty
	// when the vendor provides none (never invented).
	Severity string `json:"severity,omitempty"`
	// CVSS carries the score with its source and version.
	CVSSScore  string `json:"cvssScore,omitempty"`
	CVSSSource string `json:"cvssSource,omitempty"`
	CVSSVector string `json:"cvssVector,omitempty"`
	// Published and Modified come from the vendor record.
	Published string `json:"published,omitempty"`
	Modified  string `json:"modified,omitempty"`
	// References lists the vendor reference URLs.
	References []string `json:"references,omitempty"`
	// Provider is the authoritative feed for the verdict.
	Provider string `json:"provider"`
	// Sources lists every feed that contributed, for multi-feed dedup.
	Sources []FeedSummary `json:"sources,omitempty"`
	// DataTrust is the trust level of the backing feed data.
	DataTrust string `json:"dataTrust"`
	// MatchingMethod is one of the Match* constants.
	MatchingMethod string `json:"matchingMethod"`
	// Confidence: "confirmed" for direct vendor evaluation of the exact
	// installed version, "probable" when the evaluation relies on
	// filesystem-derived package identity, "unverified" otherwise.
	Confidence string `json:"confidence"`
	// Explanation is a human-readable justification of the verdict.
	Explanation string `json:"explanation"`
	// KernelRelease is the uname release of the affected installed kernel
	// package, when derivable.
	KernelRelease string `json:"kernelRelease,omitempty"`
}

// UpstreamHit is one upstream kernel CVE that matches the upstream version
// of the running or installed kernel. It is context, never a distro verdict.
type UpstreamHit struct {
	CVE             string   `json:"cve"`
	UpstreamVersion string   `json:"upstreamVersion"`
	Published       string   `json:"published,omitempty"`
	Modified        string   `json:"modified,omitempty"`
	Severity        string   `json:"severity,omitempty"`
	Summary         string   `json:"summary,omitempty"`
	References      []string `json:"references,omitempty"`
	Source          string   `json:"source"`
	// Note explains why this is not a distribution-confirmed finding.
	Note string `json:"note"`
}

// FindingCounts summarizes the assessment.
type FindingCounts struct {
	Affected            int `json:"affected"`
	Fixed               int `json:"fixed"`
	NotAffected         int `json:"notAffected"`
	UnderInvestigation  int `json:"underInvestigation"`
	UpstreamOnly        int `json:"upstreamOnly"`
	Unverified          int `json:"unverified"`
	PackageNotInstalled int `json:"packageNotInstalled"`
}

// Severity mapping from vendor severity strings. The mapping is
// conservative: unknown vendor severities map to empty (the reporter then
// presents the finding without an invented severity rather than guessing).
func mapSeverity(vendor string) string {
	switch normalizeKey(vendor) {
	case "critical":
		return "CRITICAL"
	case "important", "high":
		return "HIGH"
	case "medium", "moderate":
		return "MEDIUM"
	case "low", "negligible", "unimportant":
		return "LOW"
	case "info", "informational", "none":
		return "INFO"
	}
	return ""
}

// isValidCVE enforces the CVE identifier syntax (CVE-YYYY-NNNN+). Feeds
// occasionally carry malformed ids (e.g. "CVE-46838"); they are dropped
// rather than reported.
func isValidCVE(id string) bool {
	if !strings.HasPrefix(id, "CVE-") {
		return false
	}
	parts := strings.Split(id, "-")
	if len(parts) != 3 {
		return false
	}
	if len(parts[1]) != 4 {
		return false
	}
	for _, p := range parts[1:] {
		for i := 0; i < len(p); i++ {
			if p[i] < '0' || p[i] > '9' {
				return false
			}
		}
	}
	return len(parts[2]) >= 4
}

func normalizeKey(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out = append(out, c)
	}
	return string(out)
}
