package update

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Lutfifakee-Project/ronda/internal/release"
)

// Size caps for downloads. Artifacts are small Go binaries; the caps bound
// memory and disk damage from a hostile or broken source.
const (
	defaultMaxArtifactBytes = 128 << 20 // 128 MiB
	defaultMaxSumsBytes     = 4 << 20   // 4 MiB
	defaultMaxSigBytes      = 4 << 10   // 4 KiB
	versionProbeTimeout     = 20 * time.Second
	tmpPattern              = ".ronda-update-*.tmp"
)

// Endpoints pins the three official URLs a self-update needs.
type Endpoints struct {
	ArtifactURL  string
	ChecksumsURL string
	SignatureURL string
}

// AssetName returns the release artifact filename for arch.
func AssetName(arch string) string {
	return "ronda-linux-" + arch
}

// EndpointsFor builds the official endpoint set for a release version and
// architecture, using the canonical download layout of the project.
func EndpointsFor(version, arch string) Endpoints {
	base := release.ReleasesBaseURL + "/download/v" + version
	asset := AssetName(arch)
	return Endpoints{
		ArtifactURL:  base + "/" + asset,
		ChecksumsURL: base + "/SHA256SUMS",
		SignatureURL: base + "/SHA256SUMS.sig",
	}
}

// Options configures one self-update run.
type Options struct {
	// DestPath is the installed RONDA executable to replace (the running
	// binary resolved through os.Executable).
	DestPath string

	// CurrentVersion is the running version; TargetVersion the requested one.
	CurrentVersion string
	TargetVersion  string

	// Arch is the target architecture ("amd64" or "arm64"). On a real
	// self-update this is runtime.GOARCH.
	Arch string

	// Client is the hardened HTTP client; nil uses the official one.
	Client *http.Client

	// Endpoints overrides the official download URLs (tests only). nil uses
	// EndpointsFor(TargetVersion, Arch); every URL still goes through
	// Validate.
	Endpoints *Endpoints

	// Validate gates every URL before any request. nil uses
	// release.IsOfficialURL. It exists so tests can point the pipeline at a
	// local server; production code must keep it nil.
	Validate func(string) error

	// MaxArtifactBytes overrides the artifact size cap (tests only).
	MaxArtifactBytes int64

	// VersionProbe overrides the post-download executable probe. nil runs
	// the real probe (executes the verified candidate with the read-only
	// "version" command). Tests inject a static check so no binary has to
	// be built inside the test suite.
	VersionProbe func(path, wantVersion string) error
}

// Result reports a completed, verified self-update.
type Result struct {
	From           string
	To             string
	DestPath       string
	BackupPath     string
	ArtifactSHA256 string
	SizeBytes      int64
}

// Perform runs the full verification pipeline and atomically replaces the
// RONDA executable. See the package documentation for the step order.
//
// Perform refuses to run when signature verification is NOT_CONFIGURED,
// when the target is not newer than the installed version, or when any
// verification step fails. On any failure the installed executable is left
// untouched (or restored), and temporary files are removed.
func Perform(ctx context.Context, opts Options) (*Result, error) {
	// Step 0: trust gate. Without an embedded trusted key RONDA must never
	// replace its own binary; checksums alone cannot authenticate a release.
	if !release.HasTrustedKey() {
		return nil, ErrTrustNotConfigured
	}
	if opts.DestPath == "" {
		return nil, errors.New("no destination executable configured")
	}
	if opts.TargetVersion == "" {
		return nil, errors.New("no target version configured")
	}
	if opts.Arch == "" {
		return nil, errors.New("no target architecture configured")
	}

	// Step 1: refuse no-ops and downgrades before downloading anything.
	switch cmp := CompareVersions(opts.TargetVersion, opts.CurrentVersion); {
	case cmp == 0:
		return nil, ErrAlreadyUpToDate
	case cmp < 0:
		return nil, fmt.Errorf("%w: %s -> %s", ErrDowngrade, opts.CurrentVersion, opts.TargetVersion)
	}

	// Resolve the destination and recover from any interrupted earlier run.
	dest, err := filepath.EvalSymlinks(opts.DestPath)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve the installed executable: %w", err)
	}
	// Never follow a symlinked destination: the replacement must land on the
	// real installation path, not on whatever the link points at today.
	if fi, err := os.Lstat(opts.DestPath); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s is a symlink; refusing to update through it", opts.DestPath)
	}
	if err := recoverInterrupted(dest); err != nil {
		return nil, err
	}

	eps := EndpointsFor(opts.TargetVersion, opts.Arch)
	if opts.Endpoints != nil {
		eps = *opts.Endpoints
	}
	validate := opts.Validate
	if validate == nil {
		validate = release.IsOfficialURL
	}
	for _, u := range []string{eps.ArtifactURL, eps.ChecksumsURL, eps.SignatureURL} {
		if err := validate(u); err != nil {
			return nil, err
		}
	}
	client := opts.Client
	if client == nil {
		client = release.OfficialHTTPClient()
	}

	// Step 2: download SHA256SUMS and its detached signature, verify the
	// signature against the embedded trusted key.
	sums, err := fetchLimited(ctx, client, validate, eps.ChecksumsURL, defaultMaxSumsBytes)
	if err != nil {
		return nil, err
	}
	sig, err := fetchLimited(ctx, client, validate, eps.SignatureURL, defaultMaxSigBytes)
	if err != nil {
		return nil, err
	}
	if err := release.VerifyDetachedSignature(sums, string(sig)); err != nil {
		return nil, err
	}

	// Step 3: extract the signed digest for this artifact.
	expected, err := lookupChecksum(string(sums), AssetName(opts.Arch))
	if err != nil {
		return nil, err
	}

	// Step 4: stream the artifact into the destination directory while
	// hashing it, then verify every property in order.
	tmp, err := os.CreateTemp(filepath.Dir(dest), tmpPattern)
	if err != nil {
		return nil, fmt.Errorf("cannot create temporary file next to the installation: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		if tmpName != "" {
			os.Remove(tmpName)
		}
	}()
	maxArtifact := opts.MaxArtifactBytes
	if maxArtifact == 0 {
		maxArtifact = defaultMaxArtifactBytes
	}
	got, size, err := streamToFile(ctx, client, validate, eps.ArtifactURL, tmp, maxArtifact)
	if err != nil {
		return nil, err
	}
	if got != expected {
		return nil, fmt.Errorf("SHA-256 mismatch: want %s got %s", expected, got)
	}
	if err := checkELFArch(tmpName, opts.Arch); err != nil {
		return nil, err
	}
	probe := opts.VersionProbe
	if probe == nil {
		probe = probeVersion
	}
	if err := probe(tmpName, opts.TargetVersion); err != nil {
		return nil, err
	}
	if err := os.Chmod(tmpName, 0o755); err != nil {
		return nil, err
	}

	// Step 5: atomic replacement with rollback. Rename the installed binary
	// to <dest>.old first, then rename the verified candidate into place.
	backup := dest + ".old"
	_, statErr := os.Lstat(dest)
	destExists := statErr == nil
	if destExists {
		if err := os.Rename(dest, backup); err != nil {
			return nil, fmt.Errorf("cannot preserve the current executable: %w", err)
		}
	}
	if err := os.Rename(tmpName, dest); err != nil {
		if destExists {
			// Best-effort rollback; report the original failure either way.
			_ = os.Rename(backup, dest)
		}
		return nil, fmt.Errorf("cannot install the new executable: %w", err)
	}
	tmpName = "" // installed: the deferred cleanup must not remove it.

	// Step 6: post-installation sanity check with automatic rollback.
	if err := probe(dest, opts.TargetVersion); err != nil {
		if destExists {
			_ = os.Rename(backup, dest)
		}
		return nil, fmt.Errorf("post-installation check failed (%v); the previous executable was restored", err)
	}

	res := &Result{
		From:           opts.CurrentVersion,
		To:             opts.TargetVersion,
		DestPath:       dest,
		ArtifactSHA256: got,
		SizeBytes:      size,
	}
	if destExists {
		res.BackupPath = backup
	}
	return res, nil
}

// ErrTrustNotConfigured is re-exported so callers do not need the release
// package for the common check.
var ErrTrustNotConfigured = release.ErrTrustNotConfigured

// recoverInterrupted cleans temporary files left by a killed update and
// restores the backup when a previous run died between the two renames.
func recoverInterrupted(dest string) error {
	matches, _ := filepath.Glob(filepath.Join(filepath.Dir(dest), tmpPattern))
	for _, m := range matches {
		os.Remove(m)
	}
	backup := dest + ".old"
	if _, err := os.Lstat(dest); errors.Is(err, os.ErrNotExist) {
		if _, err2 := os.Lstat(backup); err2 == nil {
			if err3 := os.Rename(backup, dest); err3 != nil {
				return fmt.Errorf("found a backup of the previous executable but could not restore it: %w", err3)
			}
		}
	}
	return nil
}

// fetchLimited downloads a small file entirely, enforcing the URL gate and a
// hard size cap.
func fetchLimited(ctx context.Context, client *http.Client, validate func(string) error, url string, max int64) ([]byte, error) {
	if err := validate(url); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download of %s failed: %w", urlLabel(url), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download of %s returned %s", urlLabel(url), resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, fmt.Errorf("download of %s failed: %w", urlLabel(url), err)
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("download of %s exceeds the %d byte safety limit", urlLabel(url), max)
	}
	return data, nil
}

// streamToFile downloads url into f while computing the SHA-256 digest,
// enforcing the size cap.
func streamToFile(ctx context.Context, client *http.Client, validate func(string) error, url string, f *os.File, max int64) (string, int64, error) {
	if err := validate(url); err != nil {
		return "", 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("artifact download failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("artifact download returned %s", resp.Status)
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, max+1))
	if err != nil {
		return "", 0, fmt.Errorf("artifact download failed: %w", err)
	}
	if n > max {
		return "", 0, fmt.Errorf("artifact exceeds the %d byte safety limit", max)
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// lookupChecksum parses sha256sum(1) style content ("<digest>  <name>" or
// "<digest> *<name>") and returns the digest recorded for name. Asset names
// are controlled by the project and never contain spaces, so the second
// whitespace-separated field is always the name.
func lookupChecksum(content, name string) (string, error) {
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		digest := strings.ToLower(fields[0])
		file := strings.TrimPrefix(fields[1], "*")
		if file != name {
			continue
		}
		if !isHex64(digest) {
			return "", fmt.Errorf("checksum entry for %s is not a valid SHA-256 digest", name)
		}
		return digest, nil
	}
	return "", fmt.Errorf("no checksum entry for %s in the signed SHA256SUMS", name)
}

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

func isHex64(s string) bool { return hex64.MatchString(s) }

// probeVersion executes candidate with the read-only "version" command and
// requires it to report the expected version. At this point the artifact has
// already been authenticated by signature and checksum, so running its
// version probe is safe: it is, by construction, the publisher's content.
func probeVersion(candidate, want string) error {
	ctx, cancel := context.WithTimeout(context.Background(), versionProbeTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, candidate, "version").Output()
	if err != nil {
		return fmt.Errorf("version probe of %s failed: %w", filepath.Base(candidate), err)
	}
	first := firstLine(string(out))
	if first != "RONDA "+want {
		return fmt.Errorf("version probe reported %q, want %q", first, "RONDA "+want)
	}
	return nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimRight(s, "\r")
}

// urlLabel shortens a URL for error messages without printing query strings
// (GitHub CDN URLs carry signed query parameters).
func urlLabel(u string) string {
	if i := strings.IndexByte(u, '?'); i >= 0 {
		u = u[:i]
	}
	if len(u) > 96 {
		return u[:96] + "..."
	}
	return u
}
