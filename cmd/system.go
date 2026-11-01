package cmd

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/Lutfifakee-Project/ronda/internal/kernelintel"
	"github.com/Lutfifakee-Project/ronda/internal/persistence"
	"github.com/Lutfifakee-Project/ronda/internal/reporter"
	"github.com/Lutfifakee-Project/ronda/internal/system"
)

// printSystemHelp writes the system command help screen.
func printSystemHelp() {
	lines := []string{
		"Audit Linux system security (live host).",
		"",
		"Runs the Phase 5 persistence and backdoor engine against the live",
		"root filesystem (systemd units, cron, SSH keys, shell startup files,",
		"dynamic linker, PAM, kernel modules, udev rules, accounts) and keeps",
		"the legacy SSH/cron/PHP/systemd hygiene checks. Static analysis",
		"only: nothing is executed and nothing is modified.",
		"",
		"For a scan of an offline mounted root use:",
		"  ronda persist /mnt/rescued-root",
		"",
		"USAGE:",
		"  ronda system",
		"",
		"EXAMPLES:",
		"  ronda system",
		"",
		"LIMITATIONS:",
		"  Some checks require root; locations that cannot be read are",
		"  reported as denied or UNVERIFIED, never as clean.",
	}
	for _, l := range lines {
		fmt.Fprintln(os.Stdout, l)
	}
}

const systemHelp = "See ronda system --help"

func runSystem(args []string) int {
	if wantsHelp(args) {
		printSystemHelp()
		return ExitOK
	}

	rep := system.Audit()
	persist := persistence.Scan(context.Background(), "/")
	// Kernel CVE intelligence runs cache-only here: the system audit must
	// never depend on network connectivity. Use "ronda kernel" for a full
	// online assessment.
	kern, kerr := kernelintel.Assess(context.Background(), kernelintel.Options{
		Root:    "/",
		Offline: true,
		Timeout: 30 * time.Second,
	})

	fmt.Fprintln(os.Stdout, "RONDA System Audit")
	fmt.Fprintln(os.Stdout)

	total := len(rep.Findings) + len(persist.Findings)
	if total == 0 {
		fmt.Fprintln(os.Stdout, "[OK] No system security issues detected.")
	} else {
		// Legacy checks first (stable output shape), then persistence
		// findings by severity.
		sort.Slice(rep.Findings, func(i, j int) bool {
			return severityRank(rep.Findings[i].Severity) > severityRank(rep.Findings[j].Severity)
		})
		for _, f := range rep.Findings {
			fmt.Fprintf(os.Stdout, "[%s] %s\n", f.Severity, f.Title)
			if f.Path != "" {
				fmt.Fprintln(os.Stdout, "    path: "+f.Path)
			}
			if f.Evidence != "" {
				fmt.Fprintln(os.Stdout, "    evidence: "+f.Evidence)
			}
		}
		for _, f := range persist.Findings {
			fmt.Fprintf(os.Stdout, "[%s] %s\n", string(f.Severity), f.Title)
			if f.Rule != "" {
				meta := ""
				if m, ok := persistence.RuleMetadata(f.Rule); ok {
					meta = " (" + m.Category
					if len(m.MITRE) > 0 {
						meta += ", " + strings.Join(m.MITRE, " ")
					}
					meta += ")"
				}
				fmt.Fprintln(os.Stdout, "    rule: "+f.Rule+meta)
			}
			if f.Path != "" {
				fmt.Fprintln(os.Stdout, "    artifact: "+f.Path)
			}
			if f.Target != "" {
				fmt.Fprintln(os.Stdout, "    target: "+f.Target)
			}
			if f.Evidence != "" {
				fmt.Fprintln(os.Stdout, "    evidence: "+f.Evidence)
			}
		}
	}

	if persist.DeniedCount > 0 {
		fmt.Fprintf(os.Stdout, "\n%d persistence artifact location(s) could not be read; coverage is incomplete.\n", persist.DeniedCount)
	}
	if persist.UnverifiedCount > 0 {
		fmt.Fprintf(os.Stdout, "%d persistence scope(s) are UNVERIFIED, not clean.\n", persist.UnverifiedCount)
	}

	// Kernel CVE intelligence summary (cache-only, never a network call).
	if kerr == nil {
		fmt.Fprintln(os.Stdout)
		fmt.Fprintln(os.Stdout, "Kernel CVE intelligence (offline cache; run ronda kernel for a full online assessment):")
		if err := reporter.WriteKernelSummary(os.Stdout, kern); err != nil {
			fmt.Fprintln(os.Stdout, "[i] kernel intelligence rendering failed: "+err.Error())
		}
	} else {
		fmt.Fprintln(os.Stdout)
		fmt.Fprintln(os.Stdout, "Kernel CVE intelligence: UNVERIFIED ("+kerr.Error()+")")
	}

	if len(rep.Notes) > 0 {
		fmt.Fprintln(os.Stdout)
		for _, n := range rep.Notes {
			fmt.Fprintln(os.Stdout, "[i] "+n)
		}
	}

	return ExitOK
}

// severityRank ranks system finding severities for sorting.
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
