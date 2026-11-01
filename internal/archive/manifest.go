// Package archive safely builds per-file SHA-256 manifests from official
// release archives (tar, tar.gz and zip) without extracting them to disk.
//
// The reader is hardened against archive bombs and hostile entry names:
// entry paths are sanitized (absolute paths, traversal and backslashes are
// rejected), non-regular entries (symlinks, hardlinks, devices) are skipped,
// and entry count, per-entry size and total decompressed size are capped.
// Nothing is ever written into a scanned installation.
package archive

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
)

// Safety limits. They comfortably cover real Drupal (26k entries, ~20 MB) and
// Joomla (13k entries, ~24 MB) core archives while bounding hostile input.
const (
	DefaultMaxEntries    = 200000
	DefaultMaxFileBytes  = 64 << 20 // 64 MiB per entry
	DefaultMaxTotalBytes = 2 << 30  // 2 GiB decompressed total
	magicLen             = 4
)

// Options controls one manifest build.
type Options struct {
	MaxEntries    int
	MaxFileBytes  int64
	MaxTotalBytes int64
	// SkipPrefixes lists slash-relative prefixes (e.g. "sites/") whose
	// entries are ignored entirely, after top-prefix stripping.
	SkipPrefixes []string
}

// DefaultOptions returns the built-in safety limits.
func DefaultOptions() Options {
	return Options{
		MaxEntries:    DefaultMaxEntries,
		MaxFileBytes:  DefaultMaxFileBytes,
		MaxTotalBytes: DefaultMaxTotalBytes,
	}
}

// Info describes what the reader saw.
type Info struct {
	Entries           int    // all entries encountered
	Files             int    // regular files hashed
	SkippedNonRegular int    // symlinks, hardlinks, devices, fifos
	TotalBytes        int64  // decompressed bytes hashed
	TopDir            string // common top-level prefix that was stripped, if any
}

var (
	errUnsafePath   = errors.New("unsafe archive entry path")
	errNoFiles      = errors.New("archive contains no regular files")
	errLimitReached = errors.New("archive exceeds safety limits")
)

// ManifestSHA256 reads an archive (detected by magic bytes, filename only used
// for error messages) positioned at f and returns a manifest of sanitized
// slash paths to lowercase hex SHA-256 digests of every regular file entry.
func ManifestSHA256(ctx context.Context, filename string, f *os.File, opts Options) (map[string]string, Info, error) {
	if opts.MaxEntries <= 0 {
		opts.MaxEntries = DefaultMaxEntries
	}
	if opts.MaxFileBytes <= 0 {
		opts.MaxFileBytes = DefaultMaxFileBytes
	}
	if opts.MaxTotalBytes <= 0 {
		opts.MaxTotalBytes = DefaultMaxTotalBytes
	}

	head := make([]byte, magicLen)
	if _, err := io.ReadFull(f, head); err != nil {
		return nil, Info{}, fmt.Errorf("cannot read archive %s: %w", filename, err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, Info{}, err
	}

	switch {
	case head[0] == 'P' && head[1] == 'K':
		return manifestZIP(ctx, filename, f, opts)
	case head[0] == 0x1f && head[1] == 0x8b:
		return manifestTARGZ(ctx, filename, f, opts)
	default:
		return nil, Info{}, fmt.Errorf("unsupported archive format for %s (expected zip or tar.gz)", filename)
	}
}

func manifestTARGZ(ctx context.Context, filename string, f *os.File, opts Options) (map[string]string, Info, error) {
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, Info{}, fmt.Errorf("archive %s is not valid gzip: %w", filename, err)
	}
	defer gz.Close()
	return walkTar(ctx, filename, tar.NewReader(gz), opts)
}

func manifestZIP(ctx context.Context, filename string, f *os.File, opts Options) (map[string]string, Info, error) {
	st, err := f.Stat()
	if err != nil {
		return nil, Info{}, err
	}
	zr, err := zip.NewReader(f, st.Size())
	if err != nil {
		return nil, Info{}, fmt.Errorf("archive %s is not a valid zip: %w", filename, err)
	}

	info := Info{}
	manifest := make(map[string]string)

	for _, zf := range zr.File {
		if ctx.Err() != nil {
			return nil, info, ctx.Err()
		}
		info.Entries++
		if info.Entries > opts.MaxEntries {
			return nil, info, fmt.Errorf("%w: more than %d entries", errLimitReached, opts.MaxEntries)
		}
		name, err := cleanEntry(zf.Name)
		if err != nil {
			return nil, info, fmt.Errorf("%w: %q", errUnsafePath, zf.Name)
		}
		mode := zf.FileInfo()
		if mode.IsDir() {
			continue
		}
		if !mode.Mode().IsRegular() {
			info.SkippedNonRegular++
			continue
		}
		sum, n, err := hashLimited(ctx, func() (io.Reader, error) { return zf.Open() }, opts.MaxFileBytes)
		if err != nil {
			return nil, info, fmt.Errorf("entry %s: %w", name, err)
		}
		info.Files++
		info.TotalBytes += n
		if info.TotalBytes > opts.MaxTotalBytes {
			return nil, info, fmt.Errorf("%w: decompressed size over %d bytes", errLimitReached, opts.MaxTotalBytes)
		}
		manifest[name] = sum
	}
	return finalize(ctx, manifest, info, opts)
}

func walkTar(ctx context.Context, filename string, tr *tar.Reader, opts Options) (map[string]string, Info, error) {
	info := Info{}
	manifest := make(map[string]string)

	for {
		if ctx.Err() != nil {
			return nil, info, ctx.Err()
		}
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, info, fmt.Errorf("archive %s is not a valid tar: %w", filename, err)
		}
		info.Entries++
		if info.Entries > opts.MaxEntries {
			return nil, info, fmt.Errorf("%w: more than %d entries", errLimitReached, opts.MaxEntries)
		}
		name, err := cleanEntry(hdr.Name)
		if err != nil {
			return nil, info, fmt.Errorf("%w: %q", errUnsafePath, hdr.Name)
		}
		if hdr.Typeflag == tar.TypeDir {
			continue
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			info.SkippedNonRegular++
			continue
		}
		sum, n, err := hashLimited(ctx, func() (io.Reader, error) { return tr, nil }, opts.MaxFileBytes)
		if err != nil {
			return nil, info, fmt.Errorf("entry %s: %w", name, err)
		}
		info.Files++
		info.TotalBytes += n
		if info.TotalBytes > opts.MaxTotalBytes {
			return nil, info, fmt.Errorf("%w: decompressed size over %d bytes", errLimitReached, opts.MaxTotalBytes)
		}
		manifest[name] = sum
	}
	return finalize(ctx, manifest, info, opts)
}

// hashLimited hashes a freshly opened reader, enforcing the per-entry cap.
func hashLimited(ctx context.Context, open func() (io.Reader, error), maxFileBytes int64) (string, int64, error) {
	r, err := open()
	if err != nil {
		return "", 0, err
	}
	defer func() {
		if closer, ok := r.(io.Closer); ok {
			closer.Close()
		}
	}()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(r, maxFileBytes+1))
	if err != nil && err != io.EOF {
		return "", n, err
	}
	if n > maxFileBytes {
		return "", n, fmt.Errorf("%w: entry larger than %d bytes", errLimitReached, maxFileBytes)
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// cleanEntry sanitizes one archive entry name to a safe slash path.
func cleanEntry(name string) (string, error) {
	if name == "" {
		return "", errUnsafePath
	}
	if strings.Contains(name, "\\") {
		return "", errUnsafePath
	}
	if name[0] == '/' {
		return "", errUnsafePath
	}
	if len(name) >= 2 && name[1] == ':' {
		return "", errUnsafePath
	}
	cleaned := path.Clean(name)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", errUnsafePath
	}
	return cleaned, nil
}

// finalize resolves the common top-level prefix over the manifest keys,
// strips it, applies skip prefixes and enforces the non-empty rule.
//
// The prefix decision is order-independent: an archive whose files all share
// one first path segment (e.g. "drupal-10.3.5/") is stripped; archives mixing
// several top-level segments or root files (e.g. Joomla full packages) stay
// flat. This cannot be decided from the first entry, because directory and
// file entries arrive in arbitrary order.
func finalize(ctx context.Context, manifest map[string]string, info Info, opts Options) (map[string]string, Info, error) {
	if ctx.Err() != nil {
		return nil, info, ctx.Err()
	}
	if len(manifest) == 0 {
		return nil, info, errNoFiles
	}

	top := ""
	for key := range manifest {
		slash := strings.IndexByte(key, '/')
		if slash < 0 {
			top = "" // a root-level file exists: flat archive
			break
		}
		top = key[:slash]
		break
	}
	if top != "" {
		for key := range manifest {
			if !strings.HasPrefix(key, top+"/") {
				top = "" // mixed top-level segments: flat archive
				break
			}
		}
	}

	out := make(map[string]string, len(manifest))
	for key, sum := range manifest {
		rel := key
		if top != "" {
			rel = key[len(top)+1:]
		}
		if skipped(rel, opts.SkipPrefixes) {
			continue
		}
		out[rel] = sum
	}
	if len(out) == 0 {
		return nil, info, errNoFiles
	}
	info.TopDir = top
	return out, info, nil
}

func skipped(rel string, prefixes []string) bool {
	for _, p := range prefixes {
		if rel == p {
			return true
		}
		if strings.HasPrefix(rel, strings.TrimSuffix(p, "/")+"/") {
			return true
		}
	}
	return false
}
