// Package refcheck compares an installation against a reference manifest
// derived from an authenticated official release archive.
//
// It is shared by the Drupal and Joomla platform adapters. The engine is
// deliberately policy-driven: each platform decides which areas are core-owned
// (strictly compared and scanned for unexpected files), which files are
// commonly locally configured (downgraded to UNVERIFIED instead of MODIFIED)
// and which areas are optional (MISSING downgraded to UNVERIFIED). A checksum
// mismatch is never interpreted as malware.
package refcheck

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// Integrity state values, identical in spelling to the WordPress adapter.
const (
	StatusClean      = "CLEAN"
	StatusModified   = "MODIFIED"
	StatusMissing    = "MISSING"
	StatusUnverified = "UNVERIFIED"
)

// FileState is the verification outcome for one reference manifest file.
type FileState struct {
	Path           string `json:"path"`
	Status         string `json:"status"`
	ExpectedSHA256 string `json:"expected_sha256,omitempty"`
	ActualSHA256   string `json:"actual_sha256,omitempty"`
	Reason         string `json:"reason,omitempty"`
}

// VersionSource is one static version signal with its origin, kept separate
// so conflicting signals stay visible instead of silently resolved. The
// platform adapters alias this type so findings and reports share one shape.
type VersionSource struct {
	Value  string
	Source string
}

// Result aggregates the comparison of one installation against one manifest.
type Result struct {
	TotalFiles int
	// SkippedCount is the number of manifest paths excluded from comparison
	// by the layout policy (e.g. composer-managed areas).
	SkippedCount int
	CleanCount   int
	Modified     []FileState
	Missing      []FileState
	Unverified   []FileState
	// Unexpected lists slash-relative paths inside core-owned strict
	// directories that are absent from the reference manifest. Their
	// presence is informational and never a malware claim.
	Unexpected []string
	// CleanFiles holds absolute paths of verified-authentic files.
	CleanFiles []string
}

// SharedDir is one directory area shared between core-owned and third-party
// extensions (e.g. "components" or "plugins").
type SharedDir struct {
	// Dir is the slash-relative shared root inside the installation.
	Dir string
	// Depth is the number of directory levels below Dir that form ONE
	// extension root: 1 for components/modules/templates/media/layouts
	// (components/com_content), 2 for plugins (plugins/system/cache).
	Depth int
}

// Policy defines platform ownership boundaries for the comparison.
type Policy struct {
	// ConfigurableFiles maps manifest paths (slash-relative) that are
	// commonly modified legitimately. A mismatch on these yields UNVERIFIED.
	ConfigurableFiles map[string]bool
	// OptionalPrefixes lists slash-relative prefixes under which a missing
	// reference file yields UNVERIFIED instead of MISSING.
	OptionalPrefixes []string
	// StrictDirs lists core-owned directories walked for unexpected files.
	StrictDirs []string
	// SharedDirs lists directories that contain both core-owned extension
	// directories and third-party extensions. Files inside them are walked
	// for unexpected content, but a file is reported only when the extension
	// root it belongs to (Depth levels below the shared root) demonstrably
	// owns reference manifest entries: an extra file inside an official Core
	// component directory is reported, a third-party extension directory is
	// unknown ownership and is never reported. Files at or above the
	// extension-root level are conservatively skipped.
	SharedDirs []SharedDir
	// LanguageTrees lists directory trees (e.g. "language") that hold flat
	// per-extension language files of both core and third-party extensions.
	// A file directly one level below the tree (e.g. language/en-GB) is
	// reported only when its extension token maps to a manifest-owned
	// extension directory; language overrides and unknown tokens are
	// conservatively skipped.
	LanguageTrees []string
	// IgnorePrefixes excludes subtree results from the unexpected scan.
	IgnorePrefixes []string
	// IgnoreNames excludes file names from the unexpected scan.
	IgnoreNames map[string]bool
	// RootExtra additionally reports unexpected regular files directly in
	// the installation root (informational).
	RootExtra bool
	// RootExtraExcluded lists root file names never reported.
	RootExtraExcluded map[string]bool
	// ComparePrefixes, when non-empty, restricts verification to manifest
	// paths under these prefixes. Used by composer layouts where only
	// core/ is owned by the verified archive.
	ComparePrefixes []string
	// SkipComparePrefixes lists prefixes whose manifest paths are never
	// compared (e.g. site-owned areas); they are excluded from every count.
	SkipComparePrefixes []string
}

// Compare verifies every manifest path under root and reports unexpected
// files inside the policy's strict directories. root must be a directory.
func Compare(ctx context.Context, root string, manifest map[string]string, policy Policy) (Result, error) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return Result{}, err
	}
	info, err := os.Stat(rootAbs)
	if err != nil {
		return Result{}, err
	}
	if !info.IsDir() {
		return Result{}, fmt.Errorf("%s is not a directory", root)
	}

	res := Result{TotalFiles: len(manifest)}

	paths := make([]string, 0, len(manifest))
	for p := range manifest {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	for _, rel := range paths {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		if len(policy.ComparePrefixes) > 0 {
			if _, owned := matchPrefix(rel, policy.ComparePrefixes); !owned {
				res.SkippedCount++
				continue
			}
		}
		if _, excluded := matchPrefix(rel, policy.SkipComparePrefixes); excluded {
			res.SkippedCount++
			continue
		}
		state := verifyFile(rootAbs, rel, manifest[rel], policy)
		switch state.Status {
		case StatusClean:
			res.CleanCount++
			res.CleanFiles = append(res.CleanFiles, filepath.Join(rootAbs, filepath.FromSlash(rel)))
		case StatusModified:
			res.Modified = append(res.Modified, state)
		case StatusMissing:
			res.Missing = append(res.Missing, state)
		default:
			res.Unverified = append(res.Unverified, state)
		}
	}

	ownedDirs := manifestOwnedDirs(manifest)
	res.Unexpected = findUnexpected(rootAbs, manifest, policy)
	res.Unexpected = append(res.Unexpected, findSharedUnexpected(rootAbs, manifest, policy, ownedDirs)...)
	if policy.RootExtra {
		res.Unexpected = append(res.Unexpected, findRootExtra(rootAbs, manifest, policy)...)
	}
	return res, nil
}

// verifyFile resolves one expected file safely and classifies it.
func verifyFile(root, rel, expected string, policy Policy) FileState {
	state := FileState{Path: rel, Status: StatusUnverified, ExpectedSHA256: expected}

	abs, err := safeJoin(root, rel)
	if err != nil {
		state.Reason = "unsafe reference path: " + err.Error()
		return state
	}

	info, err := os.Stat(abs)
	if err != nil {
		if os.IsNotExist(err) {
			if prefix, optional := matchPrefix(rel, policy.OptionalPrefixes); optional {
				state.Status = StatusUnverified
				state.Reason = "optional area not present locally: " + prefix + " (commonly removed; not reported missing)"
				return state
			}
			state.Status = StatusMissing
			return state
		}
		state.Reason = err.Error()
		return state
	}
	if info.IsDir() {
		state.Reason = "expected file is a directory"
		return state
	}

	actual, err := hashFile(abs)
	if err != nil {
		state.Reason = err.Error()
		return state
	}
	state.ActualSHA256 = actual
	if strings.EqualFold(actual, expected) {
		state.Status = StatusClean
		return state
	}
	state.Status = StatusModified
	if policy.ConfigurableFiles[rel] {
		state.Status = StatusUnverified
		state.Reason = "site-configurable file; excluded from strict comparison"
	}
	return state
}

// matchPrefix reports whether rel starts with (or equals) one of the prefixes.
func matchPrefix(rel string, prefixes []string) (string, bool) {
	for _, p := range prefixes {
		p = strings.TrimSuffix(p, "/")
		if rel == p || strings.HasPrefix(rel, p+"/") {
			return p, true
		}
	}
	return "", false
}

// hashFile computes the streaming SHA-256 digest of a local file.
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.CopyBuffer(h, f, make([]byte, 64*1024)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// safeJoin resolves rel against root and guarantees the result stays inside
// root, rejecting absolute paths, backslash-prefixed paths and traversal.
// Symlinks that resolve outside root are rejected.
func safeJoin(root, rel string) (string, error) {
	if rel == "" || rel[0] == '/' || rel[0] == '\\' {
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

var errUnsafePath = errors.New("path escapes installation root")

// manifestOwnedDirs returns every directory that the manifest demonstrably
// owns: all ancestor directories of all reference entries. A directory in
// this set has at least one official file under it somewhere.
func manifestOwnedDirs(manifest map[string]string) map[string]bool {
	dirs := make(map[string]bool, len(manifest))
	for p := range manifest {
		d := path.Dir(p)
		for d != "." && d != "/" && d != "" {
			dirs[d] = true
			d = path.Dir(d)
		}
	}
	return dirs
}

// findSharedUnexpected lists regular files inside shared extension
// directories that are absent from the reference manifest but belong to an
// extension root the manifest demonstrably owns (an official Core extension).
// Files under unknown or third-party extension roots stay unreported: their
// absence from the official package is expected, never a finding.
func findSharedUnexpected(root string, manifest map[string]string, policy Policy, ownedDirs map[string]bool) []string {
	if len(policy.SharedDirs) == 0 && len(policy.LanguageTrees) == 0 {
		return nil
	}
	seen := make(map[string]bool)
	var extras []string
	add := func(rel string) {
		if !seen[rel] {
			seen[rel] = true
			extras = append(extras, rel)
		}
	}

	for _, sd := range policy.SharedDirs {
		sdDir := strings.TrimSuffix(sd.Dir, "/")
		if sd.Depth < 1 {
			sd.Depth = 1
		}
		base := filepath.Join(root, filepath.FromSlash(sdDir))
		filepath.Walk(base, func(p string, info os.FileInfo, err error) error {
			if err != nil || info == nil {
				return nil // unreadable areas are skipped, never guessed about
			}
			if info.IsDir() {
				if walkSkip[info.Name()] {
					return filepath.SkipDir
				}
				return nil
			}
			if !info.Mode().IsRegular() {
				return nil
			}
			rel, err := filepath.Rel(root, p)
			if err != nil {
				return nil
			}
			relSlash := filepath.ToSlash(rel)
			if _, ok := manifest[relSlash]; ok {
				return nil
			}
			if _, ignored := matchPrefix(relSlash, policy.IgnorePrefixes); ignored {
				return nil
			}
			if policy.IgnoreNames[info.Name()] {
				return nil
			}
			if ownedSharedExtRoot(relSlash, sdDir, sd.Depth, ownedDirs) {
				add(relSlash)
			}
			return nil
		})
	}

	for _, tree := range policy.LanguageTrees {
		treeDir := strings.TrimSuffix(tree, "/")
		base := filepath.Join(root, filepath.FromSlash(treeDir))
		filepath.Walk(base, func(p string, info os.FileInfo, err error) error {
			if err != nil || info == nil {
				return nil
			}
			if info.IsDir() {
				if walkSkip[info.Name()] {
					return filepath.SkipDir
				}
				return nil
			}
			if !info.Mode().IsRegular() {
				return nil
			}
			rel, err := filepath.Rel(root, p)
			if err != nil {
				return nil
			}
			relSlash := filepath.ToSlash(rel)
			if _, ok := manifest[relSlash]; ok {
				return nil
			}
			if _, ignored := matchPrefix(relSlash, policy.IgnorePrefixes); ignored {
				return nil
			}
			if policy.IgnoreNames[info.Name()] {
				return nil
			}
			if languageFileOwned(relSlash, treeDir, ownedDirs) {
				add(relSlash)
			}
			return nil
		})
	}

	sort.Strings(extras)
	return extras
}

// ownedSharedExtRoot reports whether the extension root that would contain
// relSlash (Depth levels below the shared root dir) owns reference manifest
// entries. A file whose own path or shallower directories are the best
// candidate is never owned: the decision needs a real extension directory.
func ownedSharedExtRoot(relSlash, sharedDir string, depth int, ownedDirs map[string]bool) bool {
	if !strings.HasPrefix(relSlash, sharedDir+"/") {
		return false
	}
	rest := strings.TrimPrefix(relSlash, sharedDir+"/")
	parts := strings.Split(rest, "/")
	if len(parts) < depth {
		return false // file at or above the extension-root level: unknown ownership
	}
	extRoot := sharedDir + "/" + strings.Join(parts[:depth], "/")
	return ownedDirs[extRoot]
}

// languageFileOwned applies the Joomla language naming convention to a file
// directly one level below a language tree (e.g. language/en-GB). A name like
// "en-GB.com_content.ini" or "en-GB.com_content.sys.ini" maps the extension
// token to candidate core directories; the file is reported only when one of
// them demonstrably owns official files. Overrides, unknown tokens and
// non-language files stay unreported.
func languageFileOwned(relSlash, tree string, ownedDirs map[string]bool) bool {
	parent := path.Dir(relSlash)
	if !strings.HasPrefix(parent, tree+"/") || strings.Contains(strings.TrimPrefix(parent, tree+"/"), "/") {
		return false // only files flat in language/<tag>/ are classified
	}
	name := path.Base(relSlash)
	if !strings.HasSuffix(name, ".ini") {
		return false
	}
	name = strings.TrimSuffix(name, ".ini")
	name = strings.TrimSuffix(name, ".sys")
	parts := strings.Split(name, ".")
	if len(parts) != 2 {
		return false // not a <tag>.<token> language file
	}
	for _, dir := range languageTokenDirs(parts[1]) {
		if ownedDirs[dir] {
			return true
		}
	}
	return false
}

// languageTokenDirs maps a Joomla language extension token to the candidate
// core-owned directories that extension can live in.
func languageTokenDirs(token string) []string {
	switch {
	case strings.HasPrefix(token, "com_"):
		return []string{
			"components/" + token,
			"administrator/components/" + token,
			"api/components/" + token,
		}
	case strings.HasPrefix(token, "mod_"):
		return []string{
			"modules/" + token,
			"administrator/modules/" + token,
		}
	case strings.HasPrefix(token, "plg_"):
		rest := strings.TrimPrefix(token, "plg_")
		i := strings.Index(rest, "_")
		if i <= 0 || i == len(rest)-1 {
			return nil
		}
		return []string{"plugins/" + rest[:i] + "/" + rest[i+1:]}
	case strings.HasPrefix(token, "tpl_"):
		name := strings.TrimPrefix(token, "tpl_")
		return []string{
			"templates/" + name,
			"administrator/templates/" + name,
		}
	}
	return nil
}

// walkSkip lists directory names never descended into during unexpected scans.
var walkSkip = map[string]bool{".git": true, "node_modules": true, ".svn": true}

// findUnexpected lists regular files inside strict core-owned directories
// that are absent from the reference manifest.
func findUnexpected(root string, manifest map[string]string, policy Policy) []string {
	var extras []string
	for _, dir := range policy.StrictDirs {
		base := filepath.Join(root, filepath.FromSlash(dir))
		filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
			if err != nil || info == nil {
				return nil // unreadable areas are skipped, never guessed about
			}
			if info.IsDir() {
				if walkSkip[info.Name()] {
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
			if _, optional := matchPrefix(relSlash, policy.IgnorePrefixes); optional {
				return nil
			}
			if policy.IgnoreNames[info.Name()] {
				return nil
			}
			extras = append(extras, relSlash)
			return nil
		})
	}
	sort.Strings(extras)
	return extras
}

// findRootExtra reports unexpected regular files directly in the installation
// root. Hidden dotfiles are frequently legitimate and skipped silently.
func findRootExtra(root string, manifest map[string]string, policy Policy) []string {
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
		if strings.HasPrefix(name, ".") {
			continue
		}
		if !e.Type().IsRegular() {
			continue
		}
		if _, ok := manifest[name]; ok {
			continue
		}
		if policy.RootExtraExcluded[name] || policy.IgnoreNames[name] {
			continue
		}
		extras = append(extras, name)
	}
	sort.Strings(extras)
	return extras
}
