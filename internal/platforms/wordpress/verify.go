package wordpress

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Lutfifakee-Project/ronda/internal/integrity"
)

// baseLocale is the locale of the base WordPress package, which carries no
// wp_local_package marker.
const baseLocale = "en_US"

// localeSensitiveFiles are core files whose contents legitimately differ between
// localized WordPress packages. When the locale is only inferred, a mismatch on
// one of these is reported as UNVERIFIED rather than MODIFIED to avoid a false
// positive caused by a wrong package locale assumption.
var localeSensitiveFiles = map[string]bool{
	"wp-includes/version.php": true,
	"readme.html":             true,
	"wp-config-sample.php":    true,
}

// VerifyOptions controls one verification run.
type VerifyOptions struct {
	Locale  string
	Offline bool
	// Base overrides the checksum API base URL. Empty keeps the official
	// api.wordpress.org endpoint; the override exists for deterministic
	// tests and never changes the verification logic.
	Base string
}

// Verify checks one WordPress installation against the official checksums.
func Verify(ctx context.Context, root, localeOverride string) Result {
	return VerifyWithOptions(ctx, root, VerifyOptions{Locale: localeOverride})
}

// VerifyWithOptions checks one installation with explicit options.
func VerifyWithOptions(ctx context.Context, root string, opts VerifyOptions) Result {
	base := opts.Base
	if base == "" {
		base = checksumAPI
	}
	return verifyFull(ctx, root, opts.Locale, base, opts.Offline)
}

// verifyWithBase is retained for tests: configurable base, online only.
func verifyWithBase(ctx context.Context, root, localeOverride, base string) Result {
	return verifyFull(ctx, root, localeOverride, base, false)
}

func verifyFull(ctx context.Context, root, localeOverride, base string, offline bool) Result {
	res := Result{Root: root}

	version := DetectVersion(root)
	if version == "" {
		res.Reason = "could not read WordPress version from wp-includes/version.php"
		return res
	}
	res.Version = version

	loc := resolveLocale(root, localeOverride)
	res.Locale = loc.Locale
	res.LocaleSource = loc.Source
	res.LocaleConfidence = loc.Confidence
	res.LocaleInferred = loc.Inferred
	res.RuntimeLanguage = loc.RuntimeLanguage

	if !loc.Established {
		res.Reason = "package locale could not be established confidently; supply --wp-locale"
		if loc.Detail != "" {
			res.Reason += ": " + loc.Detail
		}
		return res
	}

	client := newChecksumClientFull(base, offline)
	manifest, fromCache, err := client.fetch(ctx, version, res.Locale)
	if err != nil {
		res.Reason = "checksum manifest unavailable: " + err.Error()
		return res
	}
	if fromCache {
		res.ManifestSource = "cache"
	} else {
		res.ManifestSource = "api.wordpress.org"
	}

	res.TotalFiles = len(manifest)

	paths := make([]string, 0, len(manifest))
	for p := range manifest {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	for _, rel := range paths {
		expected := manifest[rel]
		cf := verifyFile(root, rel, expected)
		if cf.Status == Modified && res.LocaleInferred && localeSensitiveFiles[rel] {
			cf.Status = Unverified
			cf.Reason = "locale-sensitive file differs; package locale was inferred"
		}
		switch cf.Status {
		case Clean:
			res.CleanCount++
			res.CleanFiles = append(res.CleanFiles, filepath.Join(root, filepath.FromSlash(rel)))
		case Modified:
			res.ModifiedFiles = append(res.ModifiedFiles, cf)
		case Missing:
			res.MissingFiles = append(res.MissingFiles, cf)
		case Unverified:
			res.UnverifiedCount++
			res.UnverifiedFiles = append(res.UnverifiedFiles, cf)
		}
	}

	res.ExtraFiles = findExtraCoreFiles(root, manifest, coreDirs)
	res.RootExtraFiles = findRootExtraFiles(root, manifest)
	res.Verified = true
	return res
}

// verifyFile resolves one expected file safely and classifies it.
func verifyFile(root, rel, expectedMD5 string) CoreFile {
	cf := CoreFile{Path: rel, MD5: expectedMD5}

	abs, err := safeJoin(root, rel)
	if err != nil {
		cf.Status = Unverified
		cf.Reason = "unsafe manifest path: " + err.Error()
		return cf
	}

	info, err := os.Stat(abs)
	if err != nil {
		if os.IsNotExist(err) {
			cf.Status = Missing
		} else {
			cf.Status = Unverified
			cf.Reason = err.Error()
		}
		return cf
	}
	if info.IsDir() {
		cf.Status = Unverified
		cf.Reason = "expected file is a directory"
		return cf
	}

	actual, err := integrity.MD5File(abs)
	if err != nil {
		cf.Status = Unverified
		cf.Reason = err.Error()
		return cf
	}
	cf.Actual = actual
	if strings.EqualFold(actual, expectedMD5) {
		cf.Status = Clean
	} else {
		cf.Status = Modified
	}
	return cf
}

// safeJoin resolves rel against root and guarantees the result stays inside
// root, rejecting absolute paths, backslash-prefixed paths and traversal.
func safeJoin(root, rel string) (string, error) {
	if rel == "" || rel[0] == byte(47) || rel[0] == byte(92) {
		return "", errUnsafePath
	}
	cleanRel := filepath.Clean(filepath.FromSlash(rel))
	if filepath.IsAbs(cleanRel) || strings.HasPrefix(cleanRel, "..") {
		return "", errUnsafePath
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	joined := filepath.Join(rootAbs, cleanRel)
	if !withinRoot(rootAbs, joined) {
		return "", errUnsafePath
	}
	resolved, err := filepath.EvalSymlinks(joined)
	if err != nil {
		return joined, nil
	}
	if !withinRoot(rootAbs, resolved) {
		return "", errUnsafePath
	}
	return resolved, nil
}

func withinRoot(root, target string) bool {
	root = filepath.Clean(root)
	target = filepath.Clean(target)
	if target == root {
		return true
	}
	return strings.HasPrefix(target, root+string(os.PathSeparator))
}

var errUnsafePath = &unsafePathError{}

type unsafePathError struct{}

func (e *unsafePathError) Error() string { return "path escapes installation root" }

// coreDirs are directories owned by WordPress core.
var coreDirs = []string{"wp-admin", "wp-includes"}

// excludedNames are legitimate non-core files that may live in the root.
var excludedNames = map[string]bool{
	"wp-config.php":        true,
	"wp-config-sample.php": true,
	".htaccess":            true,
	".user.ini":            true,
	"php.ini":              true,
	"error_log":            true,
	".maintenance":         true,
}

// findExtraCoreFiles lists files under core-owned directories not in the manifest.
func findExtraCoreFiles(root string, manifest map[string]string, dirs []string) []string {
	var extras []string
	for _, dir := range dirs {
		base := filepath.Join(root, dir)
		filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
			if err != nil || info == nil {
				return nil
			}
			if info.IsDir() {
				if info.Name() == ".git" || info.Name() == "node_modules" {
					return filepath.SkipDir
				}
				return nil
			}
			if !info.Mode().IsRegular() {
				return nil
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return nil
			}
			relSlash := filepath.ToSlash(rel)
			if _, ok := manifest[relSlash]; ok {
				return nil
			}
			if excludedNames[info.Name()] {
				return nil
			}
			extras = append(extras, relSlash)
			return nil
		})
	}
	sort.Strings(extras)
	return extras
}

// findRootExtraFiles reports unexpected regular files directly in the WordPress
// root that are not in the manifest and not known configuration files. It is
// informational and never treats a file as malware.
func findRootExtraFiles(root string, manifest map[string]string) []string {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var extras []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if excludedNames[name] {
			continue
		}
		if _, ok := manifest[name]; ok {
			continue
		}
		// Hidden dotfiles are frequently legitimate; skip them silently.
		if strings.HasPrefix(name, ".") {
			continue
		}
		extras = append(extras, name)
	}
	sort.Strings(extras)
	return extras
}
