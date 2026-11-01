package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/Lutfifakee-Project/ronda/internal/persistence"
	"github.com/Lutfifakee-Project/ronda/internal/reporter"
)

func printPersistHelp() {
	lines := []string{
		"Scan a Linux system for persistence mechanisms and backdoors.",
		"",
		"Inspects systemd units and timers, cron/anacron/at jobs, SSH",
		"authorized keys and configuration, shell startup scripts, dynamic",
		"linker configuration, PAM stacks, kernel module and udev rules and",
		"local account configuration. Static analysis only: nothing is",
		"executed, loaded or modified, no package managers or system tools",
		"are invoked and no network requests are made.",
		"",
		"USAGE:",
		"  ronda persist [root]",
		"",
		"ARGUMENTS:",
		"  root    Root filesystem to inspect. Defaults to / (the live host).",
		"          Any other directory is treated as an offline mounted root.",
		"",
		"OPTIONS:",
		"  --format    Report format: terminal (default), html, json",
		"  --output    Write the report to this path",
		"",
		"EXAMPLES:",
		"  ronda persist",
		"  ronda persist /mnt/rescued-root",
		"  ronda persist /mnt/rescued-root --format json --output persist.json",
		"",
		"EXIT CODES:",
		"  0  no actionable findings",
		"  1  actionable findings reported",
		"  2  invalid usage",
	}
	fmt.Fprintln(os.Stdout, strings.Join(lines, nl))
}

func runPersist(args []string) int {
	if wantsHelp(args) {
		printPersistHelp()
		return ExitOK
	}

	root := "/"
	format := "terminal"
	output := ""
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--format", arg == "--output":
			if i+1 >= len(args) {
				fmt.Fprintf(os.Stderr, "ronda persist: %v", errors.New(arg+" requires a value"))
				fmt.Fprintln(os.Stderr)
				return ExitUsage
			}
			i++
			if arg == "--format" {
				format = strings.ToLower(args[i])
			} else {
				output = args[i]
			}
		case strings.HasPrefix(arg, "-"):
			fmt.Fprintf(os.Stderr, "ronda persist: unknown option %q", arg)
			fmt.Fprintln(os.Stderr)
			fmt.Fprintln(os.Stderr)
			printPersistHelp()
			return ExitUsage
		default:
			if root != "/" {
				fmt.Fprintf(os.Stderr, "ronda persist: unexpected second argument %q", arg)
				fmt.Fprintln(os.Stderr)
				return ExitUsage
			}
			root = arg
		}
	}
	switch format {
	case "terminal", "html", "json":
	default:
		fmt.Fprintf(os.Stderr, "ronda persist: unsupported format %q (use terminal, html or json)", format)
		fmt.Fprintln(os.Stderr)
		return ExitUsage
	}

	if info, err := os.Stat(root); err != nil || !info.IsDir() {
		fmt.Fprintf(os.Stderr, "ronda persist: %s is not an accessible directory", root)
		fmt.Fprintln(os.Stderr)
		return ExitUsage
	}

	rep := persistence.Scan(context.Background(), root)

	if err := reporter.WritePersistence(os.Stdout, rep, reporter.Options{
		Format: format,
		Output: output,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "ronda persist: %v", err)
		fmt.Fprintln(os.Stderr)
		return ExitUsage
	}

	if rep.HasActionable() {
		return ExitFindings
	}
	return ExitOK
}
