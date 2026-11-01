package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Lutfifakee-Project/ronda/internal/finding"
	"github.com/Lutfifakee-Project/ronda/internal/platforms/drupal"
	"github.com/Lutfifakee-Project/ronda/internal/platforms/joomla"
	"github.com/Lutfifakee-Project/ronda/internal/platforms/laravel"
	"github.com/Lutfifakee-Project/ronda/internal/platforms/refcheck"
	"github.com/Lutfifakee-Project/ronda/internal/platforms/wordpress"
)

// refcheckFileState aliases the shared per-file verification state used by
// the Drupal and Joomla platform results.
type refcheckFileState = refcheck.FileState

// installations holds every platform root found by one discovery walk.
//
// Discovery follows the WordPress conventions: directory names .git,
// node_modules and vendor are never entered, a recognised installation is
// never descended into, and only stat calls are used for the markers.
type installations struct {
	WordPress []string
	Drupal    []string
	Joomla    []string
	Laravel   []string
}

// discoverInstallations walks root once and records every platform root.
func discoverInstallations(root string) installations {
	var d installations
	seen := func(list []string, path string) []string {
		clean := filepath.Clean(path)
		for _, p := range list {
			if p == clean {
				return list
			}
		}
		return append(list, clean)
	}

	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil {
			return nil
		}
		if !info.IsDir() {
			return nil
		}
		name := info.Name()
		if name == ".git" || name == "node_modules" || name == "vendor" {
			return filepath.SkipDir
		}
		matched := false
		if wordpress.IsWordPress(path) {
			d.WordPress = seen(d.WordPress, path)
			matched = true
		}
		if drupal.IsDrupal(path) {
			d.Drupal = seen(d.Drupal, path)
			matched = true
		}
		if joomla.IsJoomla(path) {
			d.Joomla = seen(d.Joomla, path)
			matched = true
		}
		if laravel.IsLaravel(path) {
			d.Laravel = seen(d.Laravel, path)
			matched = true
		}
		if matched {
			return filepath.SkipDir
		}
		return nil
	})
	return d
}

// names lists the detected platforms in a stable order.
func (d installations) names() []string {
	out := make([]string, 0, 4)
	if len(d.WordPress) > 0 {
		out = append(out, "wordpress")
	}
	if len(d.Drupal) > 0 {
		out = append(out, "drupal")
	}
	if len(d.Joomla) > 0 {
		out = append(out, "joomla")
	}
	if len(d.Laravel) > 0 {
		out = append(out, "laravel")
	}
	return out
}

// wantsPlatform reports whether the platform was explicitly requested
// (--drupal etc.) or every module was requested (--all).
func wantsPlatform(opts Options, name string) bool {
	if opts.All {
		return true
	}
	for _, p := range opts.Platforms {
		if strings.EqualFold(strings.TrimSpace(p), name) {
			return true
		}
	}
	return false
}

// verifyPlatformRuns performs the per-platform verification for everything
// the scan requested. WordPress keeps its legacy behaviour of always being
// verified (even in default scans); the other platforms are opt-in so the
// default scan neither grows its cost nor makes new network requests.
func verifyPlatformRuns(ctx context.Context, opts Options, d installations, res *Result) {
	if wantsPlatform(opts, "drupal") {
		for _, root := range d.Drupal {
			r := drupal.Verify(ctx, root, drupal.VerifyOptions{Offline: opts.Offline, Store: opts.RefStore})
			res.Drupal = append(res.Drupal, r)
			res.Findings = append(res.Findings, drupalFindings(r)...)
		}
		if opts.Offline && len(res.Drupal) > 0 {
			res.Notes = append(res.Notes, "offline mode: Drupal references use the local cache only")
		}
	}
	if wantsPlatform(opts, "joomla") {
		for _, root := range d.Joomla {
			r := joomla.Verify(ctx, root, joomla.VerifyOptions{Offline: opts.Offline, Store: opts.RefStore})
			res.Joomla = append(res.Joomla, r)
			res.Findings = append(res.Findings, joomlaFindings(r)...)
		}
		if opts.Offline && len(res.Joomla) > 0 {
			res.Notes = append(res.Notes, "offline mode: Joomla references use the local cache only")
		}
	}
	if wantsPlatform(opts, "laravel") {
		for _, root := range d.Laravel {
			r := laravel.Verify(ctx, root)
			res.Laravel = append(res.Laravel, r)
			res.Findings = append(res.Findings, laravelFindings(r)...)
		}
	}
}

// requestedRoots collects the installation roots of every requested platform;
// they associate generic PHP findings with the installations the user asked
// about, so platform-specific modes keep reporting PHP backdoors inside the
// installation while excluding unrelated PHP elsewhere on the server.
func requestedRoots(opts Options, d installations) []string {
	var roots []string
	if wantsPlatform(opts, "wordpress") {
		roots = append(roots, d.WordPress...)
	}
	if wantsPlatform(opts, "drupal") {
		roots = append(roots, d.Drupal...)
	}
	if wantsPlatform(opts, "joomla") {
		roots = append(roots, d.Joomla...)
	}
	if wantsPlatform(opts, "laravel") {
		roots = append(roots, d.Laravel...)
	}
	return roots
}

// drupalFindings converts one Drupal verification result into the bounded
// finding set (per-file detail lives in the structured result).
func drupalFindings(d drupal.Result) []finding.Finding {
	if !d.Verified {
		return []finding.Finding{{
			Status:   finding.Unverified,
			Severity: finding.Info,
			Title:    "Drupal core integrity unverified",
			Platform: "drupal",
			Path:     d.Root,
			Evidence: d.Reason,
		}}
	}

	var out []finding.Finding
	if len(d.Modified) > 0 {
		out = append(out, finding.Finding{
			Status:   finding.Modified,
			Severity: finding.High,
			Title:    fmt.Sprintf("Drupal core files modified: %d", len(d.Modified)),
			Platform: "drupal",
			Path:     d.Root,
			Evidence: summarizeFileStates(d.Modified),
		})
	}
	if len(d.Missing) > 0 {
		out = append(out, finding.Finding{
			Status:   finding.Missing,
			Severity: finding.Medium,
			Title:    fmt.Sprintf("Drupal core files missing: %d", len(d.Missing)),
			Platform: "drupal",
			Path:     d.Root,
			Evidence: summarizeFileStates(d.Missing),
		})
	}
	if len(d.Unexpected) > 0 {
		out = append(out, finding.Finding{
			Status:   finding.Extra,
			Severity: finding.Low,
			Title:    fmt.Sprintf("Unexpected files in Drupal core directories: %d", len(d.Unexpected)),
			Platform: "drupal",
			Path:     d.Root,
			Evidence: summarizeStrings(d.Unexpected),
		})
	}
	return out
}

// joomlaFindings converts one Joomla verification result into findings.
func joomlaFindings(j joomla.Result) []finding.Finding {
	if !j.Verified {
		return []finding.Finding{{
			Status:   finding.Unverified,
			Severity: finding.Info,
			Title:    "Joomla core integrity unverified",
			Platform: "joomla",
			Path:     j.Root,
			Evidence: j.Reason,
		}}
	}

	var out []finding.Finding
	if len(j.Modified) > 0 {
		out = append(out, finding.Finding{
			Status:   finding.Modified,
			Severity: finding.High,
			Title:    fmt.Sprintf("Joomla core files modified: %d", len(j.Modified)),
			Platform: "joomla",
			Path:     j.Root,
			Evidence: summarizeFileStates(j.Modified),
		})
	}
	if len(j.Missing) > 0 {
		out = append(out, finding.Finding{
			Status:   finding.Missing,
			Severity: finding.Medium,
			Title:    fmt.Sprintf("Joomla core files missing: %d", len(j.Missing)),
			Platform: "joomla",
			Path:     j.Root,
			Evidence: summarizeFileStates(j.Missing),
		})
	}
	if len(j.Unexpected) > 0 {
		out = append(out, finding.Finding{
			Status:   finding.Extra,
			Severity: finding.Low,
			Title:    fmt.Sprintf("Unexpected files in Joomla core directories: %d", len(j.Unexpected)),
			Platform: "joomla",
			Path:     j.Root,
			Evidence: summarizeStrings(j.Unexpected),
		})
	}
	return out
}

// laravelFindings converts structural checks into findings. Package
// integrity is documented as UNVERIFIED through an informational finding so
// the trust level is always visible.
func laravelFindings(l laravel.Result) []finding.Finding {
	out := []finding.Finding{{
		Status:   finding.Unverified,
		Severity: finding.Info,
		Title:    "Laravel package integrity not verifiable",
		Platform: "laravel",
		Path:     l.Root,
		Evidence: l.IntegrityReason,
	}}

	for i := 0; i < len(l.Checks); i++ {
		c := l.Checks[i]
		switch c.Status {
		case "CRITICAL", "HIGH", "MEDIUM", "LOW":
			out = append(out, finding.Finding{
				Status:   finding.Suspicious,
				Severity: finding.Severity(c.Status),
				Title:    "Laravel " + c.Name,
				Platform: "laravel",
				Path:     c.Path,
				Line:     c.Line,
				Evidence: c.Detail,
			})
		}
	}
	return out
}

// summarizeFileStates renders up to maxEvidenceItems reference paths.
func summarizeFileStates(items []refcheckFileState) string {
	paths := make([]string, 0, len(items))
	for i := 0; i < len(items); i++ {
		paths = append(paths, items[i].Path)
	}
	return summarizeStrings(paths)
}
