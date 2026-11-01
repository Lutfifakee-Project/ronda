package drupal

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Lutfifakee-Project/ronda/internal/archive"
	"github.com/Lutfifakee-Project/ronda/internal/official"
	"github.com/Lutfifakee-Project/ronda/internal/platforms/refcheck"
)

// DefaultMaxArchiveBytes bounds the official archive download.
const DefaultMaxArchiveBytes = 512 << 20

// platformName is the cache/finding platform identifier.
const platformName = "drupal"

// VerifyOptions controls one verification run.
type VerifyOptions struct {
	Offline bool
	// MaxArchiveBytes overrides the archive download cap when positive.
	MaxArchiveBytes int64
	// Store overrides the reference manifest store (used by tests).
	Store *refcheck.Store
	// Client overrides the official HTTP client (used by tests that serve
	// references from a local TLS server).
	Client *official.Client
}

// Verify checks one Drupal document root against the official release.
//
// Flow: static version detection -> official release page SHA-256 ->
// archive download (allowlisted hosts) -> digest authentication ->
// per-file manifest -> policy-driven comparison. Any failure along the way
// yields UNVERIFIED with a reason; nothing is ever guessed.
func Verify(ctx context.Context, root string, opts VerifyOptions) Result {
	res := Result{Root: root}

	if !IsDrupal(root) {
		res.Reason = "not a Drupal document root (missing " + MarkerCoreLib + ")"
		return res
	}

	// A composer.lock pinning drupal/core above the document root marks a
	// Composer-based project; without one the tree is treated as a tarball
	// extraction (both layouts carry identical core/ content).
	projectRoot := FindComposerProjectRoot(root)

	sources := DetectVersion(root, projectRoot)
	res.VersionSources = sources
	version, why := EstablishVersion(sources)
	if version == "" {
		res.Reason = why
		return res
	}
	res.Version = version

	// A parent composer.lock that pins a different drupal/core version does
	// not describe this installation: fall back to the tarball layout.
	if projectRoot != "" {
		if v, err := composerCoreVersion(projectRoot); err != nil || v != version {
			res.SkippedAreas = append(res.SkippedAreas,
				"a parent composer.lock pins a different drupal/core version; layout treated as tarball extraction")
			projectRoot = ""
		}
	}

	layout := LayoutTarball
	if projectRoot != "" && projectRoot != root {
		layout = LayoutComposer
	}
	res.ProjectRoot = projectRoot
	res.Layout = layout

	client := opts.Client
	if client == nil {
		client = official.NewClient(drupalAllowlist(), official.DefaultMaxResponseBytes)
	}
	store := refcheck.NewStore()
	if opts.Store != nil {
		store = opts.Store
	}

	// 1. Resolve the authenticated reference (release page SHA-256).
	pageURL := releasePageURL(version)
	archURL := archiveURL(version)
	digest := ""
	if opts.Offline {
		res.Reason = "offline mode"
	} else {
		page, err := client.Get(ctx, pageURL)
		if err != nil {
			res.Reason = "official release page unavailable: " + err.Error()
			return res
		}
		digest, err = parseReleasePage(page, version)
		if err != nil {
			res.Reason = "release page could not be authenticated: " + err.Error()
			return res
		}
	}

	// 2. Manifest from cache, or from the authenticated archive.
	var manifest refcheck.Manifest
	var ref refcheck.Reference
	ok := false
	if opts.Offline {
		// Offline mode cannot re-read the published digest; any validated
		// cached reference for this exact platform+version is used as-is.
		ref, ok = store.GetForVersion(platformName, version)
	} else {
		ref, ok = store.Get(platformName, version, archURL, strings.ToLower(digest))
	}
	if ok {
		res.Reference = referenceFrom(ref, true)
		manifest = ref.Manifest
	} else {
		if opts.Offline {
			res.Reason = "offline mode and no cached reference manifest for Drupal " + version
			return res
		}
		newRef, err := buildReference(ctx, client, version, archURL, digest, opts)
		if err != nil {
			res.Reason = err.Error()
			return res
		}
		store.Put(newRef)
		res.Reference = referenceFrom(newRef, false)
		manifest = newRef.Manifest
	}

	res.VerificationMethod = "official release archive (" + res.Reference.Algorithm + "-authenticated) per-file manifest"
	if res.Reference.Cached {
		res.VerificationMethod += " [cached]"
	}

	// 3. Compare with layout-aware ownership boundaries.
	policy, skipped := comparisonInputs(layout)
	if layout == LayoutTarball {
		// The official archive's vendor tree is core-owned only when the
		// installation is an extraction; composer-managed vendor trees are
		// dependency-resolved and must not be compared.
		policy.StrictDirs = []string{"core", "vendor"}
	} else {
		policy.StrictDirs = []string{"core"}
		// Composer installs own everything outside core/ differently:
		// scaffold files, vendor and project areas are managed by Composer
		// and are not part of the verified core archive comparison.
		policy.ComparePrefixes = []string{"core"}
		skipped = append(skipped,
			"vendor (composer-managed; not compared against the core archive)",
			"root scaffold files (managed by drupal/core-composer-scaffold)",
			"sites template files (composer layout: project-owned)")
	}
	res.SkippedAreas = append(res.SkippedAreas, skipped...)

	result, err := refcheck.Compare(ctx, root, manifest, policy)
	if err != nil {
		res.Reason = "integrity comparison failed: " + err.Error()
		return res
	}
	res.TotalFiles = result.TotalFiles
	res.SkippedCount = result.SkippedCount
	res.CleanCount = result.CleanCount
	res.Modified = result.Modified
	res.Missing = result.Missing
	res.Unverified = result.Unverified
	res.Unexpected = result.Unexpected
	res.CleanFiles = result.CleanFiles
	res.Verified = true
	return res
}

func drupalAllowlist() []official.Host {
	return officialHosts(releasePageBase, archiveBase)
}

// buildReference downloads the official archive, authenticates it against the
// published SHA-256 and only then derives the per-file manifest.
func buildReference(ctx context.Context, client *official.Client, version, archURL, sha256Hex string, opts VerifyOptions) (refcheck.Reference, error) {
	if sha256Hex == "" {
		return refcheck.Reference{}, errors.New("no published SHA-256 available")
	}
	arch, err := refcheck.FetchArchive(ctx, client, archURL, opts.MaxArchiveBytes)
	if err != nil {
		return refcheck.Reference{}, fmt.Errorf("official archive unavailable: %w", err)
	}
	defer arch.Cleanup()

	if err := arch.VerifyDigests([]refcheck.Digest{{Algorithm: "sha256", Hex: sha256Hex}}); err != nil {
		return refcheck.Reference{}, fmt.Errorf("archive authentication failed: %w", err)
	}

	f, err := os.Open(arch.Path)
	if err != nil {
		return refcheck.Reference{}, err
	}
	defer f.Close()

	manifest, info, err := archive.ManifestSHA256(ctx, filepath.Base(archURL), f, archive.DefaultOptions())
	if err != nil {
		return refcheck.Reference{}, fmt.Errorf("authenticated archive could not be read: %w", err)
	}

	// Layout invariant: a Drupal core archive carries exactly one top-level
	// directory named after the release. Anything else is not trusted.
	wantTop := "drupal-" + version
	if info.TopDir != wantTop {
		return refcheck.Reference{}, fmt.Errorf("authenticated archive has unexpected layout (top dir %q, want %q)", info.TopDir, wantTop)
	}

	return refcheck.Reference{
		Platform:    platformName,
		Version:     version,
		Algorithm:   "sha256",
		Digest:      strings.ToLower(sha256Hex),
		SourcePage:  releasePageURL(version),
		ArchiveURL:  archURL,
		ArchiveSize: arch.Size,
		TopDir:      info.TopDir,
		Manifest:    manifest,
		Trust: refcheck.Trust{
			Category:             refcheck.StrengthSHA256Authenticated,
			DigestAlgorithm:      "sha256",
			AuthenticationMethod: "SHA-256 digest published on the official Drupal release page, compared against the downloaded archive",
			ArchiveSHA256:        strings.ToLower(sha256Hex),
			Confidence:           "the exact archive was verified against the SHA-256 digest published with the official release before the per-file manifest was derived",
		},
		Created: time.Now().UTC(),
	}, nil
}

// comparisonInputs returns the ownership policy for the layout and the areas
// explicitly excluded from verification.
func comparisonInputs(layout string) (refcheck.Policy, []string) {
	policy := refcheck.Policy{
		ConfigurableFiles: map[string]bool{
			".htaccess":                        true,
			"web.config":                       true,
			"robots.txt":                       true,
			"composer.json":                    true,
			"composer.lock":                    true,
			"sites/development.services.yml":   true,
			"sites/example.settings.local.php": true,
			"sites/example.sites.php":          true,
		},
		IgnoreNames: map[string]bool{"error_log": true},
		RootExtraExcluded: map[string]bool{
			"error_log": true,
			"php.ini":   true,
		},
		RootExtra: layout == LayoutTarball,
	}
	skipped := []string{
		"sites (site-owned configuration, uploads and private files)",
		"modules, profiles and themes beyond the core archive skeletons (contributed and custom code)",
	}
	return policy, skipped
}

// referenceFrom converts a cache reference into the reported shape.
func referenceFrom(ref refcheck.Reference, cached bool) Reference {
	return Reference{
		SourcePage:  ref.SourcePage,
		ArchiveURL:  ref.ArchiveURL,
		Algorithm:   ref.Algorithm,
		Digest:      ref.Digest,
		ArchiveSize: ref.ArchiveSize,
		Cached:      cached,
		Created:     ref.Created.Format(time.RFC3339),
		Trust:       ref.EffectiveTrust(),
	}
}
