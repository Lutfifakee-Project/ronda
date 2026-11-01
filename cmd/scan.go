package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/Lutfifakee-Project/ronda/internal/reporter"
	"github.com/Lutfifakee-Project/ronda/internal/scanner"
)

type scanOptions struct {
	Target    string
	Platforms []string
	All       bool
	Format    string
	Output    string
	Workers   int
	WPLocale  string
	Offline   bool
	Persist   bool
}

func printScanHelp() {
	lines := []string{
		"Scan files, CMS and frameworks.",
		"",
		"RONDA is read-only. It never modifies, deletes or executes scanned files.",
		"",
		"USAGE:",
		"  ronda scan <path> [options]",
		"",
		"OPTIONS:",
		"  --wordpress    Scan WordPress only",
		"  --drupal       Scan Drupal only",
		"  --joomla       Scan Joomla only",
		"  --laravel      Scan Laravel only",
		"  --php          Scan generic PHP projects only",
		"  --all          Run every scanning module (includes the",
		"                 persistence/backdoor scan of the target)",
		"  --persist      Include the persistence/backdoor scan of the",
		"                 target treated as a root filesystem",
		"  --format       Report format: terminal (default), html, json",
		"  --output       Write the report to this path",
		"  --workers      Number of concurrent hashing workers",
		"  --wp-locale    WordPress package locale override (e.g. en_US, id_ID)",
		"  --offline      Use only the local checksum cache (no network)",
		"",
		"PLATFORM FLAGS CAN BE COMBINED (e.g. --drupal --joomla).",
		"",
		"EXAMPLES:",
		"  ronda scan /home/",
		"  ronda scan /home/user/ --wordpress",
		"  ronda scan /home/ --all",
		"  ronda scan /mnt/rescued-root --persist",
		"  ronda scan /home/ --drupal --joomla",
		"  ronda scan /home/user/ --format json --output report.json",
		"",
		"EXIT CODES:",
		"  0  no actionable findings",
		"  1  actionable findings reported",
		"  2  invalid usage",
	}
	fmt.Fprintln(os.Stdout, strings.Join(lines, nl))
}

func runScan(args []string) int {
	if wantsHelp(args) {
		printScanHelp()
		return ExitOK
	}

	opts, err := parseScanArgs(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ronda scan: %v", err)
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr)
		printScanHelp()
		return ExitUsage
	}

	ctx := context.Background()
	result, err := scanner.Scan(ctx, scanner.Options{
		Target:    opts.Target,
		Platforms: opts.Platforms,
		All:       opts.All,
		Persist:   opts.Persist,
		Workers:   opts.Workers,
		WPLocale:  opts.WPLocale,
		Offline:   opts.Offline,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "ronda scan: %v", err)
		fmt.Fprintln(os.Stderr)
		return ExitUsage
	}

	if err := reporter.Write(os.Stdout, result, reporter.Options{
		Format: opts.Format,
		Output: opts.Output,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "ronda scan: %v", err)
		fmt.Fprintln(os.Stderr)
		return ExitUsage
	}

	if result.HasActionable() {
		return ExitFindings
	}
	return ExitOK
}

func parseScanArgs(args []string) (scanOptions, error) {
	opts := scanOptions{Format: "terminal"}
	platformFlags := make([]string, 0, 5)

	for i := 0; i < len(args); i++ {
		arg := args[i]

		switch {
		case arg == "--wordpress", arg == "--drupal", arg == "--joomla", arg == "--laravel", arg == "--php":
			platformFlags = append(platformFlags, strings.TrimPrefix(arg, "--"))
		case arg == "--all":
			opts.All = true
		case arg == "--offline":
			opts.Offline = true
		case arg == "--persist":
			opts.Persist = true
		case arg == "--format", arg == "--output", arg == "--workers", arg == "--wp-locale":
			if i+1 >= len(args) {
				return opts, errors.New(arg + " requires a value")
			}
			i++
			value := args[i]
			switch arg {
			case "--format":
				opts.Format = strings.ToLower(value)
			case "--output":
				opts.Output = value
			case "--wp-locale":
				opts.WPLocale = value
			case "--workers":
				var n int
				if _, err := fmt.Sscanf(value, "%d", &n); err != nil || n < 1 {
					return opts, errors.New("--workers must be a positive integer")
				}
				opts.Workers = n
			}
		case strings.HasPrefix(arg, "-"):
			return opts, fmt.Errorf("unknown option %q", arg)
		default:
			if opts.Target != "" {
				return opts, fmt.Errorf("unexpected argument %q", arg)
			}
			opts.Target = arg
		}
	}

	if opts.Target == "" {
		return opts, errors.New("a target path is required")
	}
	// Phase 3: platform flags combine (e.g. --drupal --joomla verifies both
	// platforms in one pass). A repeated flag stays a usage error so the
	// requested set stays unambiguous.
	seenFlag := make(map[string]bool, len(platformFlags))
	for _, p := range platformFlags {
		if seenFlag[p] {
			return opts, fmt.Errorf("platform flag --%s given twice", p)
		}
		seenFlag[p] = true
	}
	if len(platformFlags) > 0 && opts.All {
		return opts, errors.New("--all cannot be combined with explicit platform flags")
	}
	opts.Platforms = platformFlags

	switch opts.Format {
	case "terminal", "html", "json":
	default:
		return opts, fmt.Errorf("unsupported format %q (use terminal, html or json)", opts.Format)
	}

	return opts, nil
}
