package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Lutfifakee-Project/ronda/internal/kernelintel"
	"github.com/Lutfifakee-Project/ronda/internal/reporter"
)

// printKernelHelp writes the kernel command help screen line by line so the
// source stays free of fragile quoting characters.
func printKernelHelp() {
	lines := []string{
		"Check Linux kernel CVEs against authoritative vendor security data.",
		"",
		"RONDA identifies the distribution, the running kernel and every installed",
		"kernel package, then matches them against the vendor's own advisory data",
		"(Debian Security Tracker, Ubuntu OSV, Alpine secdb, Arch security, Red Hat",
		"security data, AlmaLinux OSV). Distribution backports, package epochs and",
		"kernel flavors are respected: upstream version comparison alone never",
		"decides applicability.",
		"",
		"USAGE:",
		"  ronda kernel [options]",
		"",
		"OPTIONS:",
		"  --root <path>     Assess an offline mounted RootFS instead of the live host.",
		"  --offline         Use only the local feed cache; never touch the network.",
		"  --refresh         Force feed re-download even when the cache is fresh.",
		"  --upstream        Include supplemental upstream kernel CVE context (OSV).",
		"                    Upstream records are never reported as distro-confirmed.",
		"  --format <f>      Output format: terminal (default), json or html.",
		"  --timeout <secs>  Bound the whole assessment (default 120).",
		"",
		"OUTPUT:",
		"  Distribution and lifecycle, running kernel, installed kernel packages,",
		"  per-CVE states (affected / fixed / not-affected / under investigation /",
		"  unverified), fixed versions, vendor attribution, feed freshness and an",
		"  evidence-based pending-reboot assessment.",
		"",
		"EXAMPLES:",
		"  ronda kernel",
		"  ronda kernel --refresh",
		"  ronda kernel --offline --format json",
		"  ronda kernel --root /mnt/rescued-root",
		"",
		"LIMITATIONS:",
		"  RPM systems: the rpm database is not statically readable without the rpm",
		"  tooling, so installed package versions are UNVERIFIED and per-CVE matching",
		"  is deliberately not attempted. RONDA never invokes rpm, dnf or yum.",
		"  SUSE and Rocky: no machine-readable feed is implemented yet; matching is",
		"  UNVERIFIED and other vendors' status is never applied automatically.",
		"  An empty CVE list is never a statement that the system is secure.",
	}
	for _, l := range lines {
		fmt.Fprintln(os.Stdout, l)
	}
}

// kernelHelp is kept as a constant for callers that embed it (e.g. root help).
const kernelHelp = "See ronda kernel --help"

// runKernel executes the kernel CVE intelligence command. Exit codes follow
// the RONDA convention: 0 when no affected finding exists, 1 when CVE
// findings or a likely pending reboot exist, 2 on usage errors.
func runKernel(args []string) int {
	if wantsHelp(args) {
		printKernelHelp()
		return ExitOK
	}

	opts := kernelintel.Options{Timeout: 120 * time.Second}
	var format string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--root":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "ronda kernel: --root requires a path argument")
				return ExitUsage
			}
			i++
			if args[i] == "" {
				fmt.Fprintln(os.Stderr, "ronda kernel: --root requires a non-empty path")
				return ExitUsage
			}
			opts.Root = args[i]
		case "--offline":
			opts.Offline = true
		case "--refresh":
			opts.Refresh = true
		case "--upstream":
			opts.IncludeUpstream = true
		case "--format":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "ronda kernel: --format requires an argument (terminal, json or html)")
				return ExitUsage
			}
			i++
			format = strings.ToLower(args[i])
			switch format {
			case "terminal", "json", "html":
			default:
				fmt.Fprintf(os.Stderr, "ronda kernel: unsupported format %q (terminal, json, html)\n", format)
				return ExitUsage
			}
		case "--timeout":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "ronda kernel: --timeout requires a number of seconds")
				return ExitUsage
			}
			i++
			secs := 0
			if _, err := fmt.Sscanf(args[i], "%d", &secs); err != nil || secs <= 0 {
				fmt.Fprintln(os.Stderr, "ronda kernel: --timeout requires a positive integer")
				return ExitUsage
			}
			opts.Timeout = time.Duration(secs) * time.Second
		default:
			fmt.Fprintf(os.Stderr, "ronda kernel: unknown option %q\n", args[i])
			fmt.Fprintln(os.Stderr, "See ronda kernel --help")
			return ExitUsage
		}
	}

	assessment, err := kernelintel.Assess(context.Background(), opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ronda kernel: %v\n", err)
		return ExitUsage
	}

	if err := reporter.WriteKernel(os.Stdout, assessment, format); err != nil {
		fmt.Fprintf(os.Stderr, "ronda kernel: report rendering failed: %v\n", err)
		return ExitUsage
	}

	if assessment.HasAffected() {
		return ExitFindings
	}
	if pr := assessment.PendingReboot; pr != nil && pr.Likely {
		return ExitFindings
	}
	return ExitOK
}
