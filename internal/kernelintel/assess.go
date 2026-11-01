package kernelintel

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Lutfifakee-Project/ronda/internal/kernel"
)

// Options controls one assessment run.
type Options struct {
	// Root: "" or "/" is the live host; anything else is an offline RootFS.
	Root string
	// Offline restricts everything to the local feed cache.
	Offline bool
	// IncludeUpstream controls the supplemental OSV upstream query.
	IncludeUpstream bool
	// Refresh forces feed re-downloads even when the cache is fresh.
	Refresh bool
	// Timeout bounds the whole assessment.
	Timeout time.Duration
}

// Test-overridable constructors (the kernel package uses the same pattern
// for uname). Production values build the real cache and hardened client.
var (
	newCacheHook      = NewCache
	newFeedClientHook = NewFeedClient
)

// Assess runs the complete kernel CVE intelligence flow for one target:
// identity audit, feed loading, matching, upstream context and lifecycle
// disclosure. It is strictly read-only.
func Assess(ctx context.Context, opts Options) (*Assessment, error) {
	start := time.Now()
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	identity := kernel.Audit(opts.Root)
	a := &Assessment{
		Root:          identity.Root,
		Mode:          identity.Mode,
		Identity:      *identity,
		PendingReboot: identity.PendingReboot,
	}
	a.Lifecycle = lifecycleNote(identity.OSRelease)

	// Hook indirection lets tests retarget the cache and feed client; the
	// production defaults are the real cache dir and hardened client.
	cache := newCacheHook()
	fc := newFeedClientHook(cache, opts.Offline)
	fc.Refresh = opts.Refresh

	switch {
	case identity.OSRelease.Family == kernel.FamilyDebian && identity.OSRelease.ID == "ubuntu":
		// Ubuntu has its own authoritative machine-readable data (OSV);
		// the Debian tracker does not cover Ubuntu releases.
		a.assessUbuntu(ctx, fc, identity)
	case identity.OSRelease.Family == kernel.FamilyDebian:
		a.assessDebian(ctx, fc, identity, opts)
	case identity.OSRelease.Family == kernel.FamilyAlpine:
		a.assessAlpine(ctx, fc, identity, opts)
	case identity.OSRelease.Family == kernel.FamilyArch:
		a.assessArch(ctx, fc, identity, opts)
	case identity.OSRelease.Family == kernel.FamilyRHEL:
		a.assessRHEL(ctx, fc, identity, opts)
	default:
		a.Notes = append(a.Notes,
			"no authoritative vendor vulnerability feed is implemented for this distribution family; per-CVE matching is UNVERIFIED")
	}

	if opts.IncludeUpstream {
		a.assessUpstream(ctx, fc, identity)
	}
	a.finalize(start)
	return a, nil
}

func lifecycleNote(os kernel.OSRelease) LifecycleNote {
	n := LifecycleNote{State: os.Lifecycle, Basis: os.LifecycleBasis}
	switch os.Lifecycle {
	case kernel.LifecycleEOL:
		n.Warning = "this release is past its published support window: security maintenance may have stopped. An empty CVE list never means the system is secure."
	case kernel.LifecycleExtended:
		n.Warning = "regular support ended; the vendor's extended security program applies (Ubuntu ESM additionally requires a subscription RONDA cannot verify)."
	case kernel.LifecycleUnknown:
		n.Warning = "RONDA has no reliable support-window data for this release; the status is unknown and kernel CVE verification stays UNVERIFIED, which is never interpreted as supported."
	}
	return n
}

// assessDebian runs the Debian tracker flow.
func (a *Assessment) assessDebian(ctx context.Context, fc *FeedClient, identity *kernel.Report, opts Options) {
	os := identity.OSRelease
	codename := os.Codename
	if codename == "" {
		if cn, ok := DebianCodename(os.VersionID); ok {
			codename = cn
			a.Notes = append(a.Notes, "codename "+cn+" derived from VERSION_ID "+os.VersionID)
		}
	}
	if codename == "" {
		a.Notes = append(a.Notes,
			"Debian release codename could not be determined; the security tracker is release-scoped, so per-CVE matching is UNVERIFIED")
		return
	}
	res, err := fc.LoadFeed(ctx, DebianSource(codename))
	a.recordFeed(res, err)
	if res.Miss {
		a.Notes = append(a.Notes, "Debian tracker unavailable: per-CVE matching is UNVERIFIED")
		return
	}
	a.Findings = append(a.Findings, MatchDebian(codename, identity.Packages, res.Entry.Advisories, res.State)...)
	a.dedupFindings()
}

// assessUbuntu runs the Ubuntu OSV flow: one minimal query per installed
// kernel image package, transmitting only the package name and version.
// Only AFFECTED records can come back from a version query; absence of
// records is disclosed as a note, never as per-CVE evidence.
func (a *Assessment) assessUbuntu(ctx context.Context, fc *FeedClient, identity *kernel.Report) {
	os := identity.OSRelease
	eco, ok := ubuntuEcosystem(os.VersionID)
	if !ok {
		a.Notes = append(a.Notes,
			"Ubuntu OSV ecosystem could not be derived from VERSION_ID "+os.VersionID+"; matching is UNVERIFIED")
		return
	}
	queried, affectedPkgs := 0, 0
	for _, p := range identity.Packages {
		if p.Ecosystem != kernel.EcosystemDPKG || p.Version == "" {
			continue
		}
		// Only image-bearing packages carry the running kernel; meta
		// packages have no own version meaning for advisories.
		if p.Kind != kernel.KindImage {
			continue
		}
		// OSV Ubuntu keys records on source packages. Query the dpkg
		// Source: name first; signed-image and flavor wrappers fall back to
		// the canonical source ("linux" or "linux-<flavor>").
		srcName := p.SourcePackage
		if srcName == "" {
			srcName = ubuntuSourceGuess(p.Name)
		}
		res, err := fc.QueryUbuntuOSV(ctx, eco, srcName, p.Version)
		a.recordFeed(res, err)
		if res.Miss {
			a.Notes = append(a.Notes,
				"OSV query for "+p.Name+" unavailable: matching for this package is UNVERIFIED")
			continue
		}
		if len(res.Entry.Advisories) == 0 {
			if retry, ok := ubuntuSourceRetry(srcName, p.Name); ok {
				res2, err2 := fc.QueryUbuntuOSV(ctx, eco, retry, p.Version)
				a.recordFeed(res2, err2)
				if !res2.Miss && len(res2.Entry.Advisories) > 0 {
					res = res2
				}
			}
		}
		queried++
		a.Findings = append(a.Findings, MatchUbuntu(p, res.Entry.Advisories, res.State, eco)...)
		if len(res.Entry.Advisories) > 0 {
			affectedPkgs++
		}
	}
	a.dedupFindings()
	if queried > 0 {
		a.Notes = append(a.Notes, fmt.Sprintf(
			"%d installed kernel package versions were checked against Ubuntu OSV data (ecosystem %s); packages with known vulnerabilities: %d. A package without returned records is not known-affected per the queried data at fetch time — absence of records is not per-CVE evidence",
			queried, eco, affectedPkgs))
	}
}

// ubuntuSourceGuess derives the canonical Ubuntu kernel source package name
// from a binary package name when dpkg published no Source field. Derived
// names are only used as OSV query keys, never asserted as provenance.
func ubuntuSourceGuess(name string) string {
	rest := name
	for _, prefix := range []string{"linux-image-unsigned-", "linux-image-", "linux-modules-"} {
		if strings.HasPrefix(rest, prefix) {
			rest = strings.TrimPrefix(rest, prefix)
			break
		}
	}
	// "6.8.0-1013-aws" -> "linux-aws"; "6.8.0-40-generic" -> "linux".
	for _, token := range strings.Split(rest, "-") {
		switch token {
		case "aws", "azure", "gcp", "oracle", "kvm", "raspi", "lowlatency",
			"nvidia", "intel-iotg", "ibm", "gke", "gkeop", "rim":
			return "linux-" + token
		}
	}
	return "linux"
}

// ubuntuSourceRetry maps wrapper source packages to the OSV-tracked source.
func ubuntuSourceRetry(srcName, binary string) (string, bool) {
	switch {
	case strings.HasPrefix(srcName, "linux-signed"):
		return "linux", true
	case srcName == "":
		return ubuntuSourceGuess(binary), true
	}
	return "", false
}

// assessAlpine runs the secdb flow.
func (a *Assessment) assessAlpine(ctx context.Context, fc *FeedClient, identity *kernel.Report, opts Options) {
	os := identity.OSRelease
	branch, ok := AlpineBranch(os.VersionID)
	if !ok {
		a.Notes = append(a.Notes,
			"Alpine secdb branch could not be derived from VERSION_ID "+os.VersionID+"; per-CVE matching is UNVERIFIED")
		return
	}
	var advisories []Advisory
	trust := ""
	for _, src := range AlpineSources(branch) {
		res, err := fc.LoadFeed(ctx, src)
		a.recordFeed(res, err)
		if !res.Miss {
			advisories = append(advisories, res.Entry.Advisories...)
			trust = worstTrust(trust, res.State)
		}
	}
	if len(advisories) == 0 {
		a.Notes = append(a.Notes, "Alpine secdb unavailable: per-CVE matching is UNVERIFIED")
		return
	}
	a.Findings = append(a.Findings, MatchSecdb(branch, identity.Packages, advisories, trust)...)
	a.dedupFindings()
}

// assessArch runs the AVG flow.
func (a *Assessment) assessArch(ctx context.Context, fc *FeedClient, identity *kernel.Report, opts Options) {
	res, err := fc.LoadFeed(ctx, ArchSource())
	a.recordFeed(res, err)
	if res.Miss {
		a.Notes = append(a.Notes, "Arch security data unavailable: per-CVE matching is UNVERIFIED")
		return
	}
	a.Findings = append(a.Findings, MatchArch(identity.Packages, res.Entry.Advisories, res.State)...)
	a.dedupFindings()
}

// assessRHEL runs the RPM-family flow. Matching is aggregate-UNVERIFIED by
// design because the RPM database is not statically parseable; the vendor
// advisory availability is still disclosed.
func (a *Assessment) assessRHEL(ctx context.Context, fc *FeedClient, identity *kernel.Report, opts Options) {
	os := identity.OSRelease
	switch os.ID {
	case "almalinux":
		res, err := fc.LoadFeed(ctx, AlmaSource())
		a.recordFeed(res, err)
		if res.Miss {
			a.Notes = append(a.Notes, "AlmaLinux OSV data unavailable; kernel CVE matching is UNVERIFIED")
			return
		}
		if note := a.rpmAggregate(identity, res.Entry.Advisories, ProviderAlmaOSV, res.State); note != "" {
			a.Notes = append(a.Notes, note)
		}
	case "rocky":
		a.Notes = append(a.Notes,
			"Rocky Linux: no official machine-readable feed implemented in this phase; kernel CVE matching is UNVERIFIED. Red Hat status is never applied to Rocky automatically.")
		// Red Hat kernel advisory availability is disclosed for context.
		a.loadRedHatPages(ctx, fc, identity)
	default:
		a.loadRedHatPages(ctx, fc, identity)
	}
}

// loadRedHatPages downloads the bounded Red Hat kernel listing pages and
// emits the aggregate disclosure.
func (a *Assessment) loadRedHatPages(ctx context.Context, fc *FeedClient, identity *kernel.Report) {
	var advisories []Advisory
	trust := ""
	for _, src := range RedHatSources() {
		res, err := fc.LoadFeed(ctx, src)
		a.recordFeed(res, err)
		if res.Miss {
			if len(advisories) == 0 {
				a.Notes = append(a.Notes, "Red Hat security data unavailable; kernel CVE matching is UNVERIFIED")
				return
			}
			continue
		}
		advisories = append(advisories, res.Entry.Advisories...)
		trust = worstTrust(trust, res.State)
	}
	if note := a.rpmAggregate(identity, advisories, ProviderRedHat, trust); note != "" {
		a.Notes = append(a.Notes, note)
	}
}

// rpmAggregate emits the RPM-family aggregate disclosure.
func (a *Assessment) rpmAggregate(identity *kernel.Report, advisories []Advisory, provider, trust string) string {
	_, note := MatchRPM(identity.Packages, advisories, provider, trust)
	return note
}

// assessUpstream queries the supplemental upstream kernel data.
func (a *Assessment) assessUpstream(ctx context.Context, fc *FeedClient, identity *kernel.Report) {
	version := ""
	if identity.Running.Available {
		version = UpstreamVersionOf(identity.Running.Release)
	}
	if version == "" {
		// Fall back to the newest installed kernel release.
		for _, p := range identity.Packages {
			if v := UpstreamVersionOf(p.KernelRelease); v != "" {
				version = v
				break
			}
		}
	}
	if version == "" {
		a.Notes = append(a.Notes, "no upstream kernel version could be derived; upstream supplemental data skipped")
		return
	}
	hits, res, err := fc.QueryUpstream(ctx, version)
	a.recordFeed(res, err)
	if err != nil || res.Miss {
		a.Notes = append(a.Notes, "upstream kernel data unavailable ("+version+"): context is skipped, no verdicts are affected")
		return
	}
	a.Upstream = hits
	a.Notes = append(a.Notes, fmt.Sprintf(
		"%d upstream kernel CVE records reference version %s; upstream version ranges never decide distribution applicability (vendor status is authoritative), so these are context only",
		len(hits), version))
}

// worstTrust keeps the weaker trust level when merging feeds.
func worstTrust(cur, next string) string {
	if cur == "" {
		return next
	}
	if trustRank(next) < trustRank(cur) {
		return next
	}
	return cur
}

func trustRank(state string) int {
	switch state {
	case TrustFresh:
		return 0
	case TrustCached:
		return 1
	case TrustOffline:
		return 2
	case TrustStale:
		return 3
	}
	return 4
}

// recordFeed appends one feed consultation to the report.
func (a *Assessment) recordFeed(res FeedResult, err error) {
	summary := FeedSummary{
		Provider:    res.Entry.Provider,
		URL:         res.Entry.URL,
		State:       res.State,
		FetchedAt:   res.Entry.FetchedAt.UTC().Format(time.RFC3339),
		FeedUpdated: res.Entry.FeedUpdated,
		Records:     len(res.Entry.Advisories),
		Note:        res.Note,
	}
	if summary.Provider == "" {
		summary.Provider = "unknown"
	}
	if res.Age > 0 {
		summary.Age = res.Age.Truncate(time.Second).String()
	}
	a.Feeds = append(a.Feeds, summary)
}

// dedupFindings collapses duplicates so one (CVE, package) pair appears
// once. Multiple feeds for the same pair keep the first (vendor) verdict and
// record the others as supporting sources; aliases never split findings.
func (a *Assessment) dedupFindings() {
	sort.SliceStable(a.Findings, func(i, j int) bool {
		if a.Findings[i].CVE != a.Findings[j].CVE {
			return a.Findings[i].CVE < a.Findings[j].CVE
		}
		return a.Findings[i].Package < a.Findings[j].Package
	})
	out := a.Findings[:0]
	for i := range a.Findings {
		f := a.Findings[i]
		if i > 0 {
			prev := &out[len(out)-1]
			if prev.CVE == f.CVE && prev.Package == f.Package {
				// Duplicate: keep the more severe verdict and retain the
				// other source as supporting evidence, never discarding it.
				if severityRank(f.State) > severityRank(prev.State) {
					merged := f
					merged.Sources = append(f.Sources, sourceOf(prev))
					merged.Sources = append(merged.Sources, prev.Sources...)
					out[len(out)-1] = merged
				} else {
					prev.Sources = append(prev.Sources, sourceOf(&f))
				}
				continue
			}
		}
		out = append(out, f)
	}
	a.Findings = out
}

// severityRank orders states for dedup preference: affected verdicts are
// never lost to fixed verdicts from another feed.
func severityRank(state string) int {
	switch state {
	case StateAffected:
		return 5
	case StateUnderInvestigation:
		return 4
	case StateUnverified:
		return 3
	case StateFixed:
		return 2
	case StateNotAffected:
		return 1
	}
	return 0
}

func sourceOf(f *Finding) FeedSummary {
	return FeedSummary{Provider: f.Provider, State: f.DataTrust, Records: 1}
}

// finalize computes counters and appends standard disclosures.
func (a *Assessment) finalize(start time.Time) {
	for i := range a.Findings {
		switch a.Findings[i].State {
		case StateAffected:
			a.Counts.Affected++
		case StateFixed:
			a.Counts.Fixed++
		case StateNotAffected:
			a.Counts.NotAffected++
		case StateUnderInvestigation:
			a.Counts.UnderInvestigation++
		case StateUnverified:
			a.Counts.Unverified++
		case StatePackageNotInstalled:
			a.Counts.PackageNotInstalled++
		}
	}
	a.Counts.UpstreamOnly = len(a.Upstream)

	if a.Identity.OSRelease.ID != "" && len(a.Findings) == 0 && a.Counts.UpstreamOnly == 0 {
		a.Notes = append(a.Notes,
			"no matching CVE data was found for the installed kernel packages: this is not a statement that the system is secure")
	}
	if a.Mode == "live" && a.Identity.Running.Available {
		for i := range a.Findings {
			a.Findings[i].RunningRelease = a.Identity.Running.Release
		}
	}
	a.DurationMS = time.Since(start).Milliseconds()
}

// HasAffected reports whether any distribution-confirmed affected finding
// exists. It drives the exit code, never the report wording.
func (a *Assessment) HasAffected() bool {
	return a.Counts.Affected > 0
}

// String summaries the assessment for terminal output headers.
func (a *Assessment) Summary() string {
	var b strings.Builder
	b.WriteString(a.Identity.Summary())
	b.WriteString("; CVE findings: ")
	fmt.Fprintf(&b, "%d affected, %d fixed, %d not-affected, %d under investigation, %d unverified, %d upstream-only",
		a.Counts.Affected, a.Counts.Fixed, a.Counts.NotAffected,
		a.Counts.UnderInvestigation, a.Counts.Unverified, a.Counts.UpstreamOnly)
	return b.String()
}
