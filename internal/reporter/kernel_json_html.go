package reporter

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"strings"

	"github.com/Lutfifakee-Project/ronda/internal/kernel"
	"github.com/Lutfifakee-Project/ronda/internal/kernelintel"
)

// writeKernelJSON renders the stable machine-readable kernel assessment.
// The envelope carries the schema name so JSON consumers can branch safely;
// the assessment itself marshals through its own json tags.
func writeKernelJSON(w io.Writer, a *kernelintel.Assessment) error {
	// Shallow copy so the machine-readable report itself carries the
	// no-findings disclaimer without mutating the caller's assessment.
	shallow := *a
	if len(shallow.Findings) == 0 && len(shallow.Upstream) == 0 {
		shallow.Notes = append(append([]string(nil), shallow.Notes...),
			"no matching CVE data was found; this is not a statement that the system is secure")
	}
	envelope := struct {
		Schema string                  `json:"schema"`
		Kernel *kernelintel.Assessment `json:"kernel"`
	}{Schema: "ronda.kernel.v1", Kernel: &shallow}
	data, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return err
	}
	_, err = w.Write(append(data, '\n'))
	return err
}

// writeKernelHTML renders the kernel report with inventory, CVE summary,
// package and fixed versions, source attribution, feed freshness and the
// explicit uncertainty statements.
func writeKernelHTML(w io.Writer, a *kernelintel.Assessment) error {
	esc := html.EscapeString
	var b strings.Builder
	line(&b, "<!doctype html>")
	line(&b, "<html lang='en'>")
	line(&b, "<head>")
	line(&b, "<meta charset='utf-8'>")
	line(&b, "<meta name='viewport' content='width=device-width, initial-scale=1'>")
	line(&b, "<title>RONDA kernel CVE report</title>")
	line(&b, "<style>")
	line(&b, "body{font-family:system-ui,sans-serif;margin:2rem;color:#111}")
	line(&b, "table{border-collapse:collapse;width:100%;margin-top:1rem}")
	line(&b, "th,td{border:1px solid #ccc;padding:.4rem .6rem;text-align:left;font-size:.9rem;vertical-align:top}")
	line(&b, "th{background:#f3f3f3}")
	line(&b, ".sev-CRITICAL{color:#b00020;font-weight:700}")
	line(&b, ".sev-HIGH{color:#c2410c;font-weight:700}")
	line(&b, ".sev-MEDIUM{color:#a16207}")
	line(&b, ".sev-LOW{color:#555}")
	line(&b, ".sev-INFO{color:#666}")
	line(&b, ".state-AFFECTED{font-weight:700;color:#b00020}")
	line(&b, ".state-FIXED{color:#166534}")
	line(&b, ".state-NOT_AFFECTED{color:#166534}")
	line(&b, ".state-UNVERIFIED,.state-UNDER_INVESTIGATION{color:#a16207;font-weight:600}")
	line(&b, ".meta{color:#555;font-size:.9rem}")
	line(&b, ".warn{background:#fef3c7;padding:.6rem .8rem;border-left:4px solid #d97706;margin:.8rem 0}")
	line(&b, "</style>")
	line(&b, "</head>")
	line(&b, "<body>")
	line(&b, "<h1>RONDA Kernel CVE Intelligence</h1>")

	os := a.Identity.OSRelease
	rootLabel := a.Identity.Root
	if rootLabel == "" {
		rootLabel = "/ (live host)"
	}
	line(&b, fmt.Sprintf("<p class='meta'>Root: %s, distribution: %s %s, lifecycle: %s</p>",
		esc(rootLabel), esc(os.ID), esc(os.VersionID), esc(os.Lifecycle)))
	if os.LifecycleBasis != "" {
		line(&b, "<p class='meta'>Lifecycle basis: "+esc(os.LifecycleBasis)+"</p>")
	}
	line(&b, "<p class='meta'>Assessment duration: "+fmt.Sprintf("%d ms", a.DurationMS)+"</p>")

	if a.Lifecycle.Warning != "" {
		line(&b, "<div class='warn'>"+esc(a.Lifecycle.Warning)+"</div>")
	}

	// Running kernel.
	line(&b, "<h2>Running kernel</h2>")
	if a.Identity.Mode == "live" && a.Identity.Running.Available {
		line(&b, fmt.Sprintf("<p>%s (arch %s, flavor %s, source %s)</p>",
			esc(a.Identity.Running.Release), esc(a.Identity.Running.Arch),
			esc(orDash(a.Identity.Running.Flavor)), esc(a.Identity.Running.Source)))
	} else {
		line(&b, "<p>NOT_APPLICABLE &mdash; offline RootFS target; the scanner host's kernel is never attributed to the target.</p>")
	}
	if len(a.Identity.Container) > 0 {
		line(&b, "<p class='warn'>Container indicators present. The running kernel belongs to the host; installed packages belong to this userspace.</p>")
	}

	// Pending reboot.
	if pr := a.PendingReboot; pr != nil {
		line(&b, "<h2>Pending reboot assessment</h2>")
		line(&b, "<p>"+esc(rebootVerdict(pr))+"</p>")
		if pr.RunningPackage != "" {
			line(&b, "<p class='meta'>Running release maps to installed package: "+esc(pr.RunningPackage)+"</p>")
		}
		if len(pr.Evidence) > 0 {
			line(&b, "<ul>")
			for _, ev := range pr.Evidence {
				line(&b, "<li>"+esc(ev)+"</li>")
			}
			line(&b, "</ul>")
		}
	}

	// Inventory.
	line(&b, "<h2>Installed kernel packages</h2>")
	if len(a.Identity.Packages) == 0 {
		line(&b, "<p>No installed kernel packages could be identified from the available metadata.</p>")
	} else {
		line(&b, "<table><thead><tr><th>Package</th><th>Version</th><th>Flavor</th><th>Kernel release</th><th>Architecture</th><th>Source package</th><th>Provenance</th></tr></thead><tbody>")
		for _, p := range a.Identity.Packages {
			prov := p.Provenance
			if prov == kernel.ProvenanceFilesystem {
				prov += " (ownership UNVERIFIED)"
			}
			line(&b, fmt.Sprintf("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>",
				esc(p.Name), esc(orDash(p.Version)), esc(orDash(p.Flavor)),
				esc(orDash(p.KernelRelease)), esc(orDash(p.Architecture)),
				esc(orDash(p.SourcePackage)), esc(prov)))
		}
		line(&b, "</tbody></table>")
	}

	// CVE findings.
	line(&b, "<h2>CVE findings</h2>")
	line(&b, fmt.Sprintf("<p class='meta'>%d affected, %d fixed, %d not-affected, %d under investigation, %d unverified, %d package-not-installed, %d upstream-only</p>",
		a.Counts.Affected, a.Counts.Fixed, a.Counts.NotAffected, a.Counts.UnderInvestigation,
		a.Counts.Unverified, a.Counts.PackageNotInstalled, a.Counts.UpstreamOnly))
	if len(a.Findings) == 0 {
		line(&b, "<p>No matching CVE data was found. This is not a statement that the system is secure; it means the consulted vendor data reported no applicable vulnerability for the installed kernel packages.</p>")
	} else {
		line(&b, "<table><thead><tr><th>State</th><th>Severity</th><th>CVE</th><th>Package</th><th>Installed</th><th>Fixed in</th><th>Flavor</th><th>CVSS</th><th>Provider</th><th>Data trust</th><th>Matching method</th><th>Confidence</th><th>Explanation</th></tr></thead><tbody>")
		findings := make([]kernelintel.Finding, len(a.Findings))
		copy(findings, a.Findings)
		sortKernelFindings(findings)
		for _, f := range findings {
			line(&b, fmt.Sprintf("<tr><td class='state-%s'>%s</td><td class='sev-%s'>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>",
				esc(f.State), esc(f.State), esc(f.Severity), esc(orDash(f.Severity)),
				esc(f.CVE), esc(f.Package), esc(f.InstalledVersion),
				esc(orDash(f.FixedVersion)), esc(orDash(f.Flavor)),
				esc(orDash(f.CVSSScore)), esc(f.Provider), esc(f.DataTrust),
				esc(f.MatchingMethod), esc(f.Confidence), esc(f.Explanation)))
		}
		line(&b, "</tbody></table>")
	}

	// Upstream context.
	if len(a.Upstream) > 0 {
		line(&b, "<h2>Upstream kernel context (supplemental)</h2>")
		line(&b, "<p class='warn'>These records come from upstream kernel data. Distributions backport fixes and renumber versions, so upstream version ranges never decide distribution applicability.</p>")
		line(&b, "<table><thead><tr><th>CVE</th><th>Upstream version</th><th>Source</th></tr></thead><tbody>")
		for _, u := range a.Upstream {
			line(&b, fmt.Sprintf("<tr><td>%s</td><td>%s</td><td>%s</td></tr>",
				esc(u.CVE), esc(u.UpstreamVersion), esc(u.Source)))
		}
		line(&b, "</tbody></table>")
	}

	// Feeds.
	line(&b, "<h2>Data feeds</h2>")
	if len(a.Feeds) == 0 {
		line(&b, "<p>No vendor feed was consulted (no implemented feed for this family or offline cache miss).</p>")
	} else {
		line(&b, "<table><thead><tr><th>Provider</th><th>State</th><th>Fetched at</th><th>Age</th><th>Feed-declared timestamp</th><th>Records</th><th>Note</th></tr></thead><tbody>")
		for _, f := range a.Feeds {
			line(&b, fmt.Sprintf("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%d</td><td>%s</td></tr>",
				esc(f.Provider), esc(f.State), esc(orDash(f.FetchedAt)),
				esc(orDash(f.Age)), esc(orDash(f.FeedUpdated)), f.Records, esc(orDash(f.Note))))
		}
		line(&b, "</tbody></table>")
	}

	if len(a.Notes) > 0 {
		line(&b, "<h2>Notes and limitations</h2><ul>")
		for _, n := range a.Notes {
			line(&b, "<li>"+esc(n)+"</li>")
		}
		line(&b, "</ul>")
	}
	line(&b, "<p class='meta'>Static analysis and vendor feed matching are not proof of exploitation or of safety. Absence of findings is not proof of absence of vulnerabilities.</p>")
	line(&b, "</body></html>")
	_, err := w.Write([]byte(b.String()))
	return err
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
