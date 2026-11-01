// Package scanner orchestrates a read-only scan of a target directory.
//
// A scan walks the target, verifies platform installations against official
// references, hashes every regular file and runs the PHP analyzer over EVERY
// eligible PHP source. Integrity verification and threat analysis are kept
// independent: a checksum-CLEAN file is still analyzed, and a MODIFIED file
// whose code shows no suspicious behaviour produces no PHP finding. The scan
// never writes to the scanned tree, never executes scanned code and never
// follows symlinks outside the target.
package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Lutfifakee-Project/ronda/internal/analyzer"
	"github.com/Lutfifakee-Project/ronda/internal/discovery"
	"github.com/Lutfifakee-Project/ronda/internal/finding"
	"github.com/Lutfifakee-Project/ronda/internal/integrity"
	"github.com/Lutfifakee-Project/ronda/internal/persistence"
	"github.com/Lutfifakee-Project/ronda/internal/platforms/drupal"
	"github.com/Lutfifakee-Project/ronda/internal/platforms/joomla"
	"github.com/Lutfifakee-Project/ronda/internal/platforms/laravel"
	"github.com/Lutfifakee-Project/ronda/internal/platforms/refcheck"
	"github.com/Lutfifakee-Project/ronda/internal/platforms/wordpress"
	"github.com/Lutfifakee-Project/ronda/internal/version"
)

// Options controls a single scan.
type Options struct {
	Target    string
	Platforms []string
	All       bool
	Workers   int
	WPLocale  string
	Offline   bool
	// Persist runs the Phase 5 persistence/backdoor engine against the scan
	// target treated as a root filesystem. --all implies it.
	Persist bool
	// RefStore overrides the reference-manifest store used by the Drupal and
	// Joomla verifiers. Nil selects the default user-level store.
	RefStore *refcheck.Store
	// WPChecksumBase overrides the WordPress checksum API base URL. Empty
	// keeps the official api.wordpress.org endpoint. Test plumbing only.
	WPChecksumBase string
}

// Result is the outcome of a scan.
type Result struct {
	Target       string
	StartedAt    time.Time
	FinishedAt   time.Time
	Platforms    []string
	Findings     []finding.Finding
	Notes        []string
	FilesScanned int
	FilesSkipped int
	PHPFiles     int
	DeniedDirs   []string
	Errors       []string
	Truncated    bool
	Workers      int
	RulesVersion string
	WordPress    []wordpress.Result
	Drupal       []drupal.Result
	Joomla       []joomla.Result
	Laravel      []laravel.Result
	// Persistence carries the Phase 5 persistence/backdoor report. Nil when
	// the profile did not run.
	Persistence *persistence.Report
}

// HasActionable reports whether the scan produced findings that need review.
func (r Result) HasActionable() bool {
	for _, f := range r.Findings {
		if f.Severity.Rank() >= finding.Low.Rank() {
			return true
		}
	}
	return false
}

// Scan walks the target and returns everything RONDA could verify about it.
func Scan(ctx context.Context, opts Options) (Result, error) {
	res := Result{
		Target:       opts.Target,
		StartedAt:    time.Now(),
		RulesVersion: version.RulesVersion,
	}

	if strings.TrimSpace(opts.Target) == "" {
		return res, fmt.Errorf("a target path is required")
	}

	info, err := os.Stat(opts.Target)
	if err != nil {
		return res, err
	}
	if !info.IsDir() {
		return res, fmt.Errorf("%s is not a directory", opts.Target)
	}

	workers := opts.Workers
	if workers < 1 {
		workers = integrity.DefaultWorkers()
	}
	res.Workers = workers

	// Hidden entries are included in threat scans: dot-directories such as
	// .well-known or .cache are classic webshell hiding places, and the
	// version-control skips (.git, .svn, .hg) still apply through
	// DefaultSkipDirs. The .htaccess carve-out stays in discovery itself.
	walk, err := discovery.Walk(ctx, opts.Target, discovery.Options{IncludeHidden: true})
	if err != nil {
		return res, err
	}
	res.DeniedDirs = walk.Denied
	res.Truncated = walk.Truncated
	res.FilesScanned = len(walk.Files)
	// One discovery pass finds every platform installation. WordPress
	// keeps its legacy always-on verification; the other platforms are
	// verified only when explicitly requested or --all was given.
	found := discoverInstallations(walk.Root)
	res.Platforms = found.names()

	res.WordPress = verifyWordPressInstalls(ctx, found.WordPress, opts)
	for i := 0; i < len(res.WordPress); i++ {
		res.Findings = append(res.Findings, wpFindings(res.WordPress[i])...)
	}
	if opts.Offline {
		res.Notes = append(res.Notes, "offline mode: WordPress checksums use the local cache only")
	}

	verifyPlatformRuns(ctx, opts, found, &res)

	// Threat analysis runs over every eligible PHP file, independent of the
	// integrity outcome. A checksum-CLEAN file merely matches a reference
	// distribution; that proves nothing about the behaviour of its code —
	// upstream releases can still be vulnerable or participate in a larger
	// attack chain. CLEAN files are therefore analyzed exactly like
	// MODIFIED, UNVERIFIED, custom and contributed files. No whole-file
	// suppression and no allowlist exist at this level.
	hashes := integrity.HashFiles(ctx, walk.Files, workers)
	for i := 0; i < len(hashes); i++ {
		h := hashes[i]
		if h.Err != nil {
			res.FilesSkipped++
			res.Errors = append(res.Errors, h.Path+": "+h.Err.Error())
			continue
		}
		if !analyzer.IsPHP(h.Path) {
			continue
		}
		res.PHPFiles++
		analyzed, err := analyzer.AnalyzeFile(h.Path)
		if err != nil {
			res.FilesSkipped++
			res.Errors = append(res.Errors, h.Path+": "+err.Error())
			continue
		}
		for j := 0; j < len(analyzed); j++ {
			analyzed[j].Platform = "php"
			res.Findings = append(res.Findings, analyzed[j])
		}
	}

	if len(res.Platforms) == 0 && res.PHPFiles > 0 {
		res.Platforms = []string{"php"}
	}

	// Persistence profile: --all or --persist run the Linux persistence and
	// backdoor engine against the target treated as a root filesystem. The
	// engine visits a bounded set of fixed artifact locations, so a web-root
	// target without system directories costs one stat per location.
	if opts.All || opts.Persist {
		rep := persistence.Scan(ctx, opts.Target)
		res.Persistence = &rep
		for i := 0; i < len(rep.Findings); i++ {
			f := rep.Findings[i]
			f.Platform = "persistence"
			res.Findings = append(res.Findings, f)
		}
		for _, n := range rep.Notes {
			res.Notes = append(res.Notes, "persistence: "+n)
		}
		if rep.DeniedCount > 0 {
			res.Notes = append(res.Notes,
				fmt.Sprintf("persistence: %d artifact locations could not be read; coverage is incomplete", rep.DeniedCount))
		}
		if rep.UnverifiedCount > 0 {
			res.Notes = append(res.Notes,
				fmt.Sprintf("persistence: %d scopes could not be verified and are reported as UNVERIFIED, not CLEAN", rep.UnverifiedCount))
		}
	}

	res.Findings = filterFindings(res.Findings, opts.Platforms, requestedRoots(opts, found))
	finding.Sort(res.Findings)

	if len(res.DeniedDirs) > 0 {
		res.Notes = append(res.Notes,
			fmt.Sprintf("%d directories could not be read; coverage is incomplete", len(res.DeniedDirs)))
	}

	res.FinishedAt = time.Now()
	return res, nil
}

// normalizePath returns a cleaned absolute path for set membership checks.
func normalizePath(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return filepath.Clean(p)
	}
	return filepath.Clean(abs)
}

// verifyWordPressInstalls verifies each discovered WordPress installation,
// preserving the legacy always-on behaviour of the WordPress module.
func verifyWordPressInstalls(ctx context.Context, roots []string, opts Options) []wordpress.Result {
	out := make([]wordpress.Result, 0, len(roots))
	for i := 0; i < len(roots); i++ {
		out = append(out, wordpress.VerifyWithOptions(ctx, roots[i], wordpress.VerifyOptions{
			Locale:  opts.WPLocale,
			Offline: opts.Offline,
			Base:    opts.WPChecksumBase,
		}))
	}
	return out
}

// filterFindings keeps generic findings plus those from requested platforms.
//
// When any platform mode is requested, PHP findings whose source file lies
// inside an installation of a REQUESTED platform discovered by the same scan
// are retained as well: a platform workflow must still report PHP backdoors
// (shell execution, backticks, obfuscated eval) inside the installation it
// verifies, and integrity findings and PHP security findings must coexist in
// one result. PHP findings outside every requested installation stay excluded
// unless the generic PHP platform itself was requested, so a platform-specific
// mode never surfaces unrelated PHP code from other server directories.
// Persistence findings are system-level context and are always kept.
func filterFindings(items []finding.Finding, platforms []string, assocRoots []string) []finding.Finding {
	if len(platforms) == 0 {
		return items
	}

	want := make(map[string]bool, len(platforms))
	for i := 0; i < len(platforms); i++ {
		want[strings.ToLower(platforms[i])] = true
	}
	platformMode := want["wordpress"] || want["drupal"] || want["joomla"] || want["laravel"]

	out := make([]finding.Finding, 0, len(items))
	for i := 0; i < len(items); i++ {
		f := items[i]
		if f.Platform == "" || want[f.Platform] || f.Platform == "persistence" {
			out = append(out, f)
			continue
		}
		if platformMode && f.Platform == "php" && hasContainingRoot(assocRoots, f.Path) {
			out = append(out, f)
		}
	}
	return out
}

// wordpressRoots lists the installation roots discovered during the scan.
func wordpressRoots(installs []wordpress.Result) []string {
	roots := make([]string, 0, len(installs))
	for i := 0; i < len(installs); i++ {
		if root := strings.TrimSpace(installs[i].Root); root != "" {
			roots = append(roots, root)
		}
	}
	return roots
}

// hasContainingRoot reports whether path lies inside (or equals) any of the
// given installation roots.
func hasContainingRoot(roots []string, path string) bool {
	for i := 0; i < len(roots); i++ {
		if containsPath(roots[i], path) {
			return true
		}
	}
	return false
}

// containsPath reports whether path is root itself or lies inside root.
//
// Both sides are normalized to absolute cleaned paths and the decision is made
// with filepath.Rel instead of a string prefix, so a sibling directory
// ("/srv/site-backup") never counts as a child of an installation
// ("/srv/site"). Traversal segments collapse during normalization, so a path
// that escapes the installation via ".." is not contained. Relative inputs are
// resolved against the current working directory on both sides, which keeps
// relative and absolute paths consistent.
//
// Paths are compared lexically inside the discovery namespace: discovery
// already guarantees symlinks are never followed outside the scan root, so no
// additional symlink evaluation happens here.
func containsPath(root, path string) bool {
	if strings.TrimSpace(root) == "" || strings.TrimSpace(path) == "" {
		return false
	}
	r := normalizePath(root)
	p := normalizePath(path)
	if r == p {
		return true
	}
	rel, err := filepath.Rel(r, p)
	if err != nil {
		return false
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	return true
}
