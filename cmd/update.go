package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/Lutfifakee-Project/ronda/internal/release"
	"github.com/Lutfifakee-Project/ronda/internal/update"
	"github.com/Lutfifakee-Project/ronda/internal/version"
)

func printUpdateHelp() {
	lines := []string{
		"Check for a newer RONDA release.",
		"",
		"RONDA never replaces itself automatically during a scan. The updater",
		"only ever touches RONDA's own installation binary, after full",
		"verification, and never modifies scanned sites or system settings.",
		"",
		"USAGE:",
		"  ronda update [--check]",
		"  ronda update --install [--yes]",
		"",
		"OPTIONS:",
		"  --check      Check for a newer release without changing anything",
		"               (the default behavior)",
		"  --install    Download, verify and install the latest release. Only",
		"               available when a trusted release signing key is embedded",
		"               in this binary; otherwise it is refused by design",
		"  --yes        Skip the confirmation prompt for --install",
		"",
		"TRUST MODEL:",
		"  SHA-256 checksums detect corruption but cannot authenticate the",
		"  publisher. Authentication uses a detached Ed25519 signature over",
		"  SHA256SUMS, verified against a key embedded at build time. When the",
		"  status below is NOT_CONFIGURED, RONDA only reports updates and",
		"  prints the manual verification steps instead of installing.",
		"",
		"EXIT CODES:",
		"  0  check completed (up to date, newer release available, or no",
		"     release published yet)",
		"  1  installation or verification failed",
		"  2  invalid usage or the check could not be completed",
		"",
		"EXAMPLES:",
		"  ronda update",
		"  ronda update --check",
	}
	for _, l := range lines {
		fmt.Fprintln(os.Stdout, l)
	}
}

type updateOptions struct {
	Check   bool
	Install bool
	Yes     bool
}

func parseUpdateArgs(args []string) (updateOptions, error) {
	var opts updateOptions
	for _, arg := range args {
		switch arg {
		case "--check":
			opts.Check = true
		case "--install":
			opts.Install = true
		case "--yes":
			opts.Yes = true
		default:
			if strings.HasPrefix(arg, "-") {
				return opts, fmt.Errorf("unknown option %q", arg)
			}
			return opts, fmt.Errorf("unexpected argument %q", arg)
		}
	}
	if opts.Check && opts.Install {
		return opts, errors.New("--check cannot be combined with --install")
	}
	return opts, nil
}

func runUpdate(args []string) int {
	if wantsHelp(args) {
		printUpdateHelp()
		return ExitOK
	}
	opts, err := parseUpdateArgs(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ronda update: %v", err)
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr)
		printUpdateHelp()
		return ExitUsage
	}
	if opts.Install {
		return runUpdateInstall(opts)
	}
	return runUpdateCheck()
}

// runUpdateCheck reports the latest official release and the local trust
// status. It never downloads a binary and never modifies the installation.
func runUpdateCheck() int {
	fmt.Fprintln(os.Stdout, "Current version: "+version.Version)
	fmt.Fprintln(os.Stdout, "Signature verification: "+string(release.SigningStatus()))

	latest, err := update.NewChecker().LatestTag(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "ronda update: %v", err)
		fmt.Fprintln(os.Stderr)
		return ExitUsage
	}
	if latest == "" {
		fmt.Fprintln(os.Stdout, "No published release found.")
		fmt.Fprintln(os.Stdout, "This build may be a local release candidate; see the project README for manual installation.")
		return ExitOK
	}

	fmt.Fprintln(os.Stdout, "Latest release:  "+latest)
	cmp := update.CompareVersions(version.Version, latest)
	switch {
	case cmp > 0:
		fmt.Fprintln(os.Stdout, "The installed version is newer than the latest published release (local build or pre-release).")
		return ExitOK
	case cmp == 0:
		fmt.Fprintln(os.Stdout, "RONDA is up to date.")
		return ExitOK
	}

	fmt.Fprintln(os.Stdout, "A newer version is available.")
	if release.HasTrustedKey() {
		fmt.Fprintln(os.Stdout, "Review the release notes, then run:")
		fmt.Fprintln(os.Stdout, "  ronda update --install")
		return ExitOK
	}
	printManualUpdateSteps(latest)
	return ExitOK
}

// printManualUpdateSteps is shown whenever an update exists but signature
// verification is NOT_CONFIGURED: the user stays in control and performs the
// verification steps by hand.
func printManualUpdateSteps(latest string) {
	base := release.ReleasesBaseURL + "/download/v" + latest
	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout, "Automatic installation is disabled: no trusted release signing key is")
	fmt.Fprintln(os.Stdout, "embedded in this binary (signature verification NOT_CONFIGURED).")
	fmt.Fprintln(os.Stdout, "Update manually and verify before installing:")
	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout, "  1. Download from an official location:")
	fmt.Fprintln(os.Stdout, "       "+base+"/"+update.AssetName(runtime.GOARCH))
	fmt.Fprintln(os.Stdout, "       "+base+"/SHA256SUMS")
	fmt.Fprintln(os.Stdout, "  2. Verify the checksum:")
	fmt.Fprintln(os.Stdout, "       sha256sum -c SHA256SUMS")
	fmt.Fprintln(os.Stdout, "  3. Install with the project install.sh (it re-verifies the")
	fmt.Fprintln(os.Stdout, "     checksum, checks the ELF architecture and installs atomically).")
	fmt.Fprintln(os.Stdout, "     Download the installer first; never pipe it into a shell:")
	fmt.Fprintln(os.Stdout, "       https://raw.githubusercontent.com/"+release.RepoOwner+"/"+release.RepoName+"/main/install.sh")
	fmt.Fprintln(os.Stdout, "  4. Confirm the installed version:")
	fmt.Fprintln(os.Stdout, "       ronda version")
}

// runUpdateInstall performs an authenticated self-update. It is refused
// outright when no trusted signing key is embedded: without publisher
// authentication RONDA must not replace its own binary.
func runUpdateInstall(opts updateOptions) int {
	// Resolve the target release first: an install is meaningless offline
	// and the refusal messages below need the real version.
	latest, err := update.NewChecker().LatestTag(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "ronda update: %v", err)
		fmt.Fprintln(os.Stderr)
		return ExitUsage
	}
	if latest == "" {
		fmt.Fprintln(os.Stdout, "No published release found; nothing to install.")
		return ExitOK
	}

	if !release.HasTrustedKey() {
		fmt.Fprintln(os.Stdout, "Current version: "+version.Version)
		fmt.Fprintln(os.Stdout, "Signature verification: "+string(release.SigningStatus()))
		printManualUpdateSteps(latest)
		fmt.Fprintln(os.Stderr, "ronda update: --install refused: signature verification is NOT_CONFIGURED")
		return ExitUsage
	}

	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ronda update: cannot locate the running executable: %v", err)
		fmt.Fprintln(os.Stderr)
		return ExitUsage
	}

	if !opts.Yes {
		fmt.Fprintf(os.Stdout, "Install RONDA %s over the running %s? [y/N] ", latest, version.Version)
		answer, readErr := readConfirm()
		if readErr != nil || (answer != "y" && answer != "yes") {
			fmt.Fprintln(os.Stdout, "Update cancelled.")
			return ExitOK
		}
	}

	res, err := update.Perform(context.Background(), update.Options{
		DestPath:       exe,
		CurrentVersion: version.Version,
		TargetVersion:  latest,
		Arch:           runtime.GOARCH,
	})
	if err != nil {
		switch {
		case errors.Is(err, update.ErrAlreadyUpToDate):
			fmt.Fprintln(os.Stdout, "RONDA is up to date.")
			return ExitOK
		case errors.Is(err, release.ErrTrustNotConfigured):
			fmt.Fprintf(os.Stderr, "ronda update: %v", err)
			fmt.Fprintln(os.Stderr)
			return ExitUsage
		default:
			fmt.Fprintf(os.Stderr, "ronda update: %v", err)
			fmt.Fprintln(os.Stderr)
			return ExitFindings
		}
	}

	fmt.Fprintln(os.Stdout, "Updated RONDA "+res.From+" -> "+res.To)
	fmt.Fprintln(os.Stdout, "Installed: "+res.DestPath)
	if res.BackupPath != "" {
		fmt.Fprintln(os.Stdout, "Previous executable kept at: "+res.BackupPath)
	}
	fmt.Fprintln(os.Stdout, "Verified: Ed25519 signature, SHA-256, ELF architecture, version probe.")
	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout, "Run 'ronda version' to confirm.")
	return ExitOK
}

// readConfirm reads a single confirmation line from stdin.
func readConfirm() (string, error) {
	var line string
	if _, err := fmt.Fscanln(os.Stdin, &line); err != nil {
		// A bare Enter yields "unexpected newline": treat as "no".
		if strings.Contains(err.Error(), "unexpected newline") {
			return "", nil
		}
		return "", err
	}
	return strings.ToLower(strings.TrimSpace(line)), nil
}
