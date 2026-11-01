// Package cmd implements the RONDA command line interface.
//
// Every command is read-only. RONDA never modifies scanned files, never
// executes scanned PHP and never changes system configuration.
package cmd

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/Lutfifakee-Project/ronda/internal/version"
)

// Exit codes returned by Execute.
const (
	ExitOK       = 0
	ExitFindings = 1
	ExitUsage    = 2
)

// nl is a single newline byte, used instead of raw string literals so the
// source carries no fragile characters.
var nl = string([]byte{10})

// Execute runs the CLI and returns the process exit code.
func Execute(args []string) int {
	if len(args) == 0 {
		printUsage(os.Stdout)
		return ExitUsage
	}

	command := args[0]
	rest := args[1:]

	switch command {
	case "help", "--help", "-h":
		return runHelp(rest)
	case "version", "--version", "-v":
		return runVersion(rest)
	case "scan":
		return runScan(rest)
	case "persist":
		return runPersist(rest)
	case "kernel":
		return runKernel(rest)
	case "system":
		return runSystem(rest)
	case "update":
		return runUpdate(rest)
	default:
		fmt.Fprintf(os.Stderr, "ronda: unknown command %q", command)
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr)
		printUsage(os.Stderr)
		return ExitUsage
	}
}

// wantsHelp reports whether the argument list asks for command help.
func wantsHelp(args []string) bool {
	for _, arg := range args {
		if arg == "--help" || arg == "-h" || arg == "help" {
			return true
		}
	}
	return false
}

// printUsage writes the main help screen.
func printUsage(w io.Writer) {
	fmt.Fprintln(w, mainHelp())
}

// mainHelp returns the main help screen text.
func mainHelp() string {
	lines := []string{
		"RONDA - Local Linux Security Scanner",
		"Scan. Detect. Protect.",
		"",
		"USAGE:",
		"  ronda <command> [options]",
		"",
		"COMMANDS:",
		"  scan       Scan files, CMS and frameworks",
		"  persist    Scan Linux persistence and backdoors",
		"  kernel     Check Linux kernel vulnerabilities",
		"  system     Audit Linux system security",
		"  version    Show RONDA version",
		"  update     Check for updates",
		"  help       Show help information",
		"",
		"SCAN OPTIONS:",
		"  --wordpress    Scan WordPress",
		"  --drupal       Scan Drupal",
		"  --joomla       Scan Joomla",
		"  --laravel      Scan Laravel",
		"  --php          Scan PHP projects",
		"  --all          Run all scanning modules",
		"  --persist      Include persistence/backdoor scan of the target",
		"  --format       Report format (html, json)",
		"",
		"EXAMPLES:",
		"  ronda scan /home/",
		"  ronda scan /home/user/ --wordpress",
		"  ronda scan /home/ --all",
		"  ronda persist",
		"  ronda persist /mnt/rescued-root",
		"  ronda kernel",
		"  ronda system",
		"  ronda version",
		"  ronda update",
		"",
		"MORE HELP:",
		"  ronda <command> --help",
		"",
		"Project:",
		"  https://github.com/Lutfifakee-Project/ronda",
	}
	return strings.Join(lines, nl)
}

// runHelp prints the main help screen or a command specific one.
func runHelp(args []string) int {
	if len(args) == 0 {
		printUsage(os.Stdout)
		return ExitOK
	}

	switch strings.ToLower(strings.TrimSpace(args[0])) {
	case "scan":
		printScanHelp()
	case "persist":
		printPersistHelp()
	case "kernel":
		printKernelHelp()
	case "system":
		printSystemHelp()
	case "update":
		printUpdateHelp()
	case "version":
		printVersionHelp()
	default:
		fmt.Fprintf(os.Stderr, "ronda: no help topic %q", args[0])
		fmt.Fprintln(os.Stderr)
		return ExitUsage
	}
	return ExitOK
}

// runVersion prints build and detection rule information.
//
// Build metadata is reported exactly as provided at link time: when a value
// was not supplied (for example a plain "go build") it stays "dev" or
// "unknown" instead of being fabricated from unrelated sources.
func runVersion(args []string) int {
	if wantsHelp(args) {
		printVersionHelp()
		return ExitOK
	}

	fmt.Fprintln(os.Stdout, "RONDA "+version.Version)
	fmt.Fprintln(os.Stdout, "Detection rules: "+version.RulesVersion)
	fmt.Fprintln(os.Stdout, "Commit: "+version.Commit)
	fmt.Fprintln(os.Stdout, "Built: "+version.Date)
	fmt.Fprintln(os.Stdout, "Go: "+runtime.Version())
	fmt.Fprintln(os.Stdout, "Platform: "+runtime.GOOS+"/"+runtime.GOARCH)
	return ExitOK
}

func printVersionHelp() {
	lines := []string{
		"Show RONDA version information.",
		"",
		"USAGE:",
		"  ronda version",
		"",
		"OUTPUT:",
		"  Binary version, detection rules version, commit and build date,",
		"  Go runtime version and target OS/architecture. Commit and build",
		"  date are reported as provided at link time and stay \"dev\" or",
		"  \"unknown\" when the build did not supply them.",
		"",
		"EXAMPLES:",
		"  ronda version",
	}
	fmt.Fprintln(os.Stdout, strings.Join(lines, nl))
}
