// Package discovery walks a target tree and returns the files RONDA should inspect.
package discovery

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Options controls a discovery walk.
// The zero value is safe to use.
type Options struct {
	// IncludeHidden keeps dotfiles; they are skipped by default.
	IncludeHidden bool
	// FollowSymlinks follows symlinks inside the scan root only.
	FollowSymlinks bool
	// MaxDepth limits recursion; 0 means unlimited.
	MaxDepth int
	// SkipDirs holds directory names skipped entirely (e.g. .git).
	SkipDirs []string
}

// Result is the outcome of a discovery walk.
//
// Denied lists paths the user could not read; scanning continues
// elsewhere but RONDA must never claim full coverage when Denied is non-empty.
type Result struct {
	Root   string
	Files  []string
	Denied []string
	// Truncated is true when cancellation stopped the walk early.
	Truncated bool
}

// DefaultSkipDirs are directories that rarely contain deployable code
// and dominate scan time when traversed.
var DefaultSkipDirs = []string{".git", ".svn", ".hg", "node_modules", "vendor/cache"}

// Walk enumerates regular files under root.
//
// Symlinks are never followed outside root. Broken links and symlink loops
// are skipped silently and recorded as denied only when they block a read.
func Walk(ctx context.Context, root string, opts Options) (*Result, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(absRoot)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, &os.PathError{Op: "walk", Path: absRoot, Err: os.ErrInvalid}
	}

	res := &Result{Root: absRoot}
	seen := make(map[string]bool)
	skip := make(map[string]bool, len(DefaultSkipDirs)+len(opts.SkipDirs))
	for _, d := range DefaultSkipDirs {
		skip[d] = true
	}
	for _, d := range opts.SkipDirs {
		skip[d] = true
	}

	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		if ctx.Err() != nil {
			res.Truncated = true
			return
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			res.Denied = append(res.Denied, dir)
			return
		}
		for _, entry := range entries {
			if ctx.Err() != nil {
				res.Truncated = true
				return
			}
			name := entry.Name()
			if !opts.IncludeHidden && strings.HasPrefix(name, ".") && name != ".htaccess" {
				continue
			}
			full := filepath.Join(dir, name)
			mode := entry.Type()

			if mode&fs.ModeSymlink != 0 {
				if !opts.FollowSymlinks {
					continue
				}
				if seen[full] {
					continue
				}
				seen[full] = true
				target, err := filepath.EvalSymlinks(full)
				if err != nil {
					continue
				}
				if !strings.HasPrefix(target, absRoot+string(os.PathSeparator)) && target != absRoot {
					// Symlink escapes the scan scope; do not follow it.
					continue
				}
				tinfo, err := os.Stat(full)
				if err != nil {
					continue
				}
				if tinfo.IsDir() {
					if opts.MaxDepth > 0 && depth+1 > opts.MaxDepth {
						continue
					}
					walk(full, depth+1)
				} else if tinfo.Mode().IsRegular() {
					res.Files = append(res.Files, full)
				}
				continue
			}

			if entry.IsDir() {
				if skip[name] {
					continue
				}
				if opts.MaxDepth > 0 && depth+1 > opts.MaxDepth {
					continue
				}
				walk(full, depth+1)
				continue
			}
			if entry.Type().IsRegular() {
				res.Files = append(res.Files, full)
			}
		}
	}

	walk(absRoot, 0)
	sort.Strings(res.Files)
	sort.Strings(res.Denied)
	return res, nil
}
