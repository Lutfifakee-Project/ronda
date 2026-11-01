package reporter

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Lutfifakee-Project/ronda/internal/kernel"
	"github.com/Lutfifakee-Project/ronda/internal/kernelintel"
)

// WriteKernel renders the kernel CVE intelligence assessment in the
// requested format (terminal, json or html). The output keeps the three
// formats consistent: the same findings, the same feed trust states, the
// same uncertainty disclosures.
func WriteKernel(w io.Writer, a *kernelintel.Assessment, format string) error {
	switch format {
	case "json":
		return writeKernelJSON(w, a)
	case "html":
		return writeKernelHTML(w, a)
	default:
		return writeKernelTerminal(w, a)
	}
}

func kernelStateRank(state string) int {
	switch state {
	case kernelintel.StateAffected:
		return 5
	case kernelintel.StateUnderInvestigation:
		return 4
	case kernelintel.StateUnverified:
		return 3
	case kernelintel.StateFixed:
		return 2
	case kernelintel.StateNotAffected:
		return 1
	}
	return 0
}

func sortKernelFindings(fs []kernelintel.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		ra, rb := kernelStateRank(fs[i].State), kernelStateRank(fs[j].State)
		if ra != rb {
			return ra > rb
		}
		if fs[i].Severity != fs[j].Severity {
			return severityRank(fs[i].Severity) > severityRank(fs[j].Severity)
		}
		return fs[i].CVE < fs[j].CVE
	})
}

func severityRank(s string) int {
	switch s {
	case "CRITICAL":
		return 5
	case "HIGH":
		return 4
	case "MEDIUM":
		return 3
	case "LOW":
		return 2
	case "INFO":
		return 1
	}
	return 0
}

// writeKernelTerminal renders the human report.
func writeKernelTerminal(w io.Writer, a *kernelintel.Assessment) error {
	fmt.Fprintln(w, "RONDA Kernel CVE Intelligence")
	fmt.Fprintln(w)

	os := a.Identity.OSRelease
	fmt.Fprintln(w, "Distribution:  "+displayDistro(os))
	fmt.Fprintln(w, "Lifecycle:     "+os.Lifecycle)
	if os.LifecycleBasis != "" {
		fmt.Fprintln(w, "  basis:       "+os.LifecycleBasis)
	}
	if a.Identity.Mode == "live" && a.Identity.Running.Available {
		fmt.Fprintln(w, "Running kernel: "+a.Identity.Running.Release+" ("+a.Identity.Running.Arch+")")
		if a.Identity.Running.Flavor != "" {
			fmt.Fprintln(w, "  flavor:     "+a.Identity.Running.Flavor)
		}
	} else {
		fmt.Fprintln(w, "Running kernel: NOT_APPLICABLE (offline RootFS target)")
	}
	if len(a.Identity.Container) > 0 {
		fmt.Fprintln(w, "Container:     yes (running kernel belongs to the host, not this userspace)")
	}
	fmt.Fprintln(w, "Installed kernel packages:")
	if len(a.Identity.Packages) == 0 {
		fmt.Fprintln(w, "  (none identified)")
	}
	for _, p := range a.Identity.Packages {
		line := "  " + p.Name
		if p.Version != "" {
			line += " " + p.Version
		}
		if p.Flavor != "" {
			line += " [flavor: " + p.Flavor + "]"
		}
		if p.KernelRelease != "" && p.KernelRelease != p.Version {
			line += " (release " + p.KernelRelease + ")"
		}
		fmt.Fprintln(w, line)
		if p.Provenance == kernel.ProvenanceFilesystem {
			fmt.Fprintln(w, "    provenance: filesystem evidence only; package ownership UNVERIFIED")
		}
	}
	fmt.Fprintln(w)

	// Pending reboot assessment.
	if pr := a.PendingReboot; pr != nil {
		fmt.Fprintln(w, "Pending reboot: "+rebootVerdict(pr))
		for _, ev := range pr.Evidence {
			fmt.Fprintln(w, "  evidence: "+ev)
		}
	} else {
		fmt.Fprintln(w, "Pending reboot: no assessment (offline target or running kernel unavailable)")
	}
	fmt.Fprintln(w)

	// CVE findings.
	findings := make([]kernelintel.Finding, len(a.Findings))
	copy(findings, a.Findings)
	sortKernelFindings(findings)
	if len(findings) == 0 {
		fmt.Fprintln(w, "CVE findings: none")
		fmt.Fprintln(w, "  No matching CVE data was found.")
		fmt.Fprintln(w, "  This is not a statement that the system is secure: it means the")
		fmt.Fprintln(w, "  consulted vendor data reported no applicable vulnerability for")
		fmt.Fprintln(w, "  the installed kernel packages.")
	} else {
		fmt.Fprintf(w, "CVE findings: %d affected, %d fixed, %d not-affected, %d under investigation, %d unverified\n",
			a.Counts.Affected, a.Counts.Fixed, a.Counts.NotAffected, a.Counts.UnderInvestigation, a.Counts.Unverified)
		for _, f := range findings {
			fmt.Fprintln(w)
			sev := f.Severity
			if sev == "" {
				sev = "SEV-N/A"
			}
			fmt.Fprintf(w, "  [%s][%s] %s — %s\n", sev, f.State, f.CVE, f.Package+" "+f.InstalledVersion)
			if f.AdvisoryID != "" {
				fmt.Fprintln(w, "    advisory:   "+f.AdvisoryID)
			}
			if f.FixedVersion != "" {
				fmt.Fprintln(w, "    fixed in:   "+f.FixedVersion)
			}
			if f.CVSSScore != "" {
				fmt.Fprintln(w, "    CVSS:       "+f.CVSSScore+" ("+f.CVSSSource+")")
			}
			fmt.Fprintln(w, "    provider:   "+f.Provider+" | data: "+f.DataTrust+" | method: "+f.MatchingMethod+" | confidence: "+f.Confidence)
			fmt.Fprintln(w, "    detail:     "+f.Explanation)
			if len(f.References) > 0 {
				fmt.Fprintln(w, "    reference:  "+f.References[0])
			}
		}
	}

	// Upstream context.
	if len(a.Upstream) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "Upstream kernel context (supplemental, never distro-confirmed): %d records\n", len(a.Upstream))
		for i, u := range a.Upstream {
			if i >= 10 {
				fmt.Fprintf(w, "  ... and %d more\n", len(a.Upstream)-10)
				break
			}
			fmt.Fprintf(w, "  %s (upstream %s)\n", u.CVE, u.UpstreamVersion)
		}
	}

	// Feeds.
	if len(a.Feeds) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Data feeds:")
		for _, f := range a.Feeds {
			line := "  " + f.Provider + ": " + f.State
			if f.FetchedAt != "" {
				line += " (fetched " + f.FetchedAt
				if f.Age != "" {
					line += ", age " + f.Age
				}
				line += ")"
			}
			fmt.Fprintln(w, line)
			if f.Note != "" {
				fmt.Fprintln(w, "    "+f.Note)
			}
		}
	}

	// Lifecycle warning.
	if a.Lifecycle.Warning != "" {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "[!] "+a.Lifecycle.Warning)
	}

	if len(a.Notes) > 0 {
		fmt.Fprintln(w)
		for _, n := range a.Notes {
			fmt.Fprintln(w, "[i] "+n)
		}
	}
	return nil
}

func displayDistro(os kernel.OSRelease) string {
	if os.ID == "" {
		return "unknown"
	}
	name := os.ID
	if os.VersionID != "" {
		name += " " + os.VersionID
	}
	if os.Codename != "" {
		name += " (" + os.Codename + ")"
	}
	if os.Derivative {
		name += " [derivative]"
	}
	return name
}

func rebootVerdict(pr *kernel.PendingReboot) string {
	if pr.Likely {
		return "LIKELY (evidence below); RONDA never reboots or schedules reboots"
	}
	if strings.Contains(pr.Explanation, "UNVERIFIED") {
		return "UNVERIFIED (evidence below)"
	}
	return "no indicator found"
}

// WriteKernelSummary renders the compact kernel intelligence summary used
// inside "ronda system": identity, lifecycle, affected findings and the
// pending-reboot verdict, without the full inventory and feed tables. The
// full report stays available through "ronda kernel".
func WriteKernelSummary(w io.Writer, a *kernelintel.Assessment) error {
	os := a.Identity.OSRelease
	if os.ID == "" {
		fmt.Fprintln(w, "  distribution: unknown; CVE matching UNVERIFIED")
		return nil
	}
	dist := os.ID
	if os.VersionID != "" {
		dist += " " + os.VersionID
	}
	if os.Codename != "" {
		dist += " (" + os.Codename + ")"
	}
	fmt.Fprintln(w, "  distribution: "+dist+" | lifecycle: "+os.Lifecycle+" | ecosystem: "+orEco(os.Ecosystem))
	if a.Identity.Mode == "live" && a.Identity.Running.Available {
		fmt.Fprintln(w, "  running kernel: "+a.Identity.Running.Release+" ("+a.Identity.Running.Arch+")")
	} else {
		fmt.Fprintln(w, "  running kernel: NOT_APPLICABLE")
	}
	fmt.Fprintf(w, "  installed kernel packages: %d | CVE findings: %d affected, %d fixed, %d not-affected, %d under investigation, %d unverified\n",
		len(a.Identity.Packages), a.Counts.Affected, a.Counts.Fixed, a.Counts.NotAffected,
		a.Counts.UnderInvestigation, a.Counts.Unverified)
	findings := make([]kernelintel.Finding, 0, len(a.Findings))
	for _, f := range a.Findings {
		if f.State == kernelintel.StateAffected {
			findings = append(findings, f)
		}
	}
	sortKernelFindings(findings)
	for _, f := range findings {
		sev := f.Severity
		if sev == "" {
			sev = "SEV-N/A"
		}
		fmt.Fprintf(w, "  [%s] %s — %s %s; fixed in %s (%s, data: %s)\n",
			sev, f.CVE, f.Package, f.InstalledVersion, orDash(f.FixedVersion), f.Provider, f.DataTrust)
	}
	if pr := a.PendingReboot; pr != nil {
		fmt.Fprintln(w, "  pending reboot: "+rebootVerdict(pr))
		if pr.Likely {
			for _, ev := range pr.Evidence {
				fmt.Fprintln(w, "    evidence: "+ev)
			}
		}
	}
	if a.Lifecycle.Warning != "" {
		fmt.Fprintln(w, "  [!] "+a.Lifecycle.Warning)
	}
	for _, n := range a.Notes {
		if strings.Contains(n, "UNVERIFIED") || strings.Contains(n, "not a statement") {
			fmt.Fprintln(w, "  [i] "+n)
		}
	}
	return nil
}

func orEco(eco string) string {
	if eco == "" {
		return "unverified"
	}
	return eco
}
