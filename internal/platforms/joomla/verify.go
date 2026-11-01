package joomla

import (
	"context"
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
const platformName = "joomla"

// refDigest aliases the shared digest type.
type refDigest = refcheck.Digest

// VerifyOptions controls one verification run.
type VerifyOptions struct {
	Offline bool
	// MaxArchiveBytes overrides the archive download cap when positive.
	MaxArchiveBytes int64
	// Store overrides the reference manifest store (used by tests).
	Store *refcheck.Store
	// Client overrides the official HTTP client (used by tests).
	Client *official.Client
}

// Verify checks one Joomla installation root against the official full
// package release for its exact version.
func Verify(ctx context.Context, root string, opts VerifyOptions) Result {
	res := Result{Root: root}

	if !IsJoomla(root) {
		res.Reason = "not a Joomla installation root (missing " + MarkerManifest + " and version marker)"
		return res
	}

	sources := DetectVersion(root)
	res.VersionSources = sources
	version, why := EstablishVersion(sources)
	if version == "" {
		res.Reason = why
		return res
	}
	res.Version = version

	client := opts.Client
	if client == nil {
		client = official.NewClient(officialHosts(), official.DefaultMaxResponseBytes)
	}
	store := refcheck.NewStore()
	if opts.Store != nil {
		store = opts.Store
	}

	// 1. Resolve the published digests from the official downloads page.
	var pub publishedDigests
	if opts.Offline {
		res.Reason = "offline mode"
	} else {
		page, err := client.Get(ctx, releasePageURL(version))
		if err != nil {
			res.Reason = "official downloads page unavailable: " + err.Error()
			return res
		}
		pub, err = parseDownloadsPage(page, version)
		if err != nil {
			res.Reason = "downloads page could not be authenticated: " + err.Error()
			return res
		}
	}

	// 2. Manifest from cache, or from the authenticated archive.
	var manifest refcheck.Manifest
	var ref refcheck.Reference
	var warnings []string
	ok := false
	if opts.Offline {
		ref, ok = store.GetForVersion(platformName, version)
	} else {
		ref, ok = store.Get(platformName, version, pub.ArchiveURL, pub.key())
	}
	if ok {
		res.Reference = referenceFrom(ref, true)
		manifest = ref.Manifest
		// The weak-digest caveat is not persisted with the cache entry, so
		// every run that surfaces a legacy-authenticated reference re-attaches
		// the warning: honesty must survive the cache.
		if res.Reference.Trust.Category == refcheck.StrengthLegacyDigestMatch {
			warnings = append(warnings,
				"reference strength: LEGACY_DIGEST_MATCH — the cached reference for Joomla "+version+" was authenticated with the published MD5+SHA-1 pair only (no strong digest was available when it was built); treat it as legacy-digest evidence, not strong authentication")
		}
	} else {
		if opts.Offline {
			res.Reason = "offline mode and no cached reference manifest for Joomla " + version
			return res
		}
		newRef, buildWarnings, err := buildReference(ctx, client, version, pub, opts)
		if err != nil {
			res.Reason = err.Error()
			return res
		}
		store.Put(newRef)
		res.Reference = referenceFrom(newRef, false)
		manifest = newRef.Manifest
		warnings = buildWarnings
	}
	res.Warnings = append(res.Warnings, warnings...)

	// The verification method states the strongest authentication evidence
	// honestly instead of collapsing every match into "authenticated".
	if res.Reference.Trust.Category == refcheck.StrengthSHA256Authenticated {
		res.VerificationMethod = "official full-package archive (downloads-page MD5+SHA-1 plus GitHub-release SHA-256 authenticated) per-file manifest"
	} else {
		res.VerificationMethod = "official full-package archive (downloads-page MD5+SHA-1 authenticated; legacy digests only) per-file manifest"
	}
	if res.Reference.Cached {
		res.VerificationMethod += " [cached]"
	}

	// 3. Compare with ownership boundaries.
	policy, skipped := comparisonInputs()
	res.SkippedAreas = skipped

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

// buildReference downloads the official full package, authenticates it
// against the published MD5+SHA1 pair, cross-checks the GitHub-release
// SHA-256 for the identical package and only then derives the manifest.
// The returned warnings describe trust-model caveats that every report
// format must surface (currently: strong digest unavailable -> the
// reference stays legacy-digest evidence).
func buildReference(ctx context.Context, client *official.Client, version string, pub publishedDigests, opts VerifyOptions) (refcheck.Reference, []string, error) {
	pair := pub.digests()
	if len(pair) == 0 {
		return refcheck.Reference{}, nil, fmt.Errorf("no published digest available for %s", version)
	}
	arch, err := refcheck.FetchArchive(ctx, client, pub.ArchiveURL, opts.MaxArchiveBytes)
	if err != nil {
		return refcheck.Reference{}, nil, fmt.Errorf("official archive unavailable: %w", err)
	}
	defer arch.Cleanup()

	// The published MD5+SHA-1 pair is mandatory and must always match.
	if err := arch.VerifyDigests(pair); err != nil {
		return refcheck.Reference{}, nil, fmt.Errorf("archive authentication failed: %w", err)
	}

	// Trust evaluation: the pair matched, so the floor is legacy-digest
	// evidence. When the GitHub release publishes a SHA-256 for this exact
	// package, it must match too — a mismatch between official sources is a
	// hard refusal, never a downgrade. Unavailability is not a failure: it
	// degrades the trust label honestly instead of weakening the check.
	trust := refcheck.Trust{
		Category:             refcheck.StrengthLegacyDigestMatch,
		DigestAlgorithm:      "md5+sha1",
		AuthenticationMethod: "MD5 and SHA-1 digests published on the official downloads page, compared against the downloaded archive",
		ArchiveSHA256:        arch.SHA256,
		Confidence:           "the archive matched only collision-broken legacy digests (MD5, SHA-1); this is weaker evidence than a SHA-256 or signature match",
	}
	var warnings []string
	gh, err := fetchGitHubSHA256(ctx, client, version)
	switch {
	case err != nil:
		warnings = append(warnings,
			"reference strength: LEGACY_DIGEST_MATCH — Joomla publishes only MD5 and SHA-1 for this package and the GitHub release SHA-256 was unavailable ("+err.Error()+"); treat the reference as legacy-digest evidence, not strong authentication")
	case !strings.EqualFold(gh, arch.SHA256):
		return refcheck.Reference{}, nil, fmt.Errorf(
			"official sources disagree: GitHub release SHA-256 %s does not match the downloaded archive SHA-256 %s; refusing to derive a manifest",
			strings.ToLower(gh), arch.SHA256)
	default:
		trust.Category = refcheck.StrengthSHA256Authenticated
		trust.DigestAlgorithm = "sha256"
		trust.AuthenticationMethod = "downloads-page MD5+SHA-1 pair plus the SHA-256 published with the official GitHub release (api.github.com/repos/joomla/joomla-cms), both compared against the exact downloaded archive"
		trust.Confidence = "the exact archive was verified against an independently published SHA-256 before the per-file manifest was derived"
	}

	f, err := os.Open(arch.Path)
	if err != nil {
		return refcheck.Reference{}, nil, err
	}
	defer f.Close()

	manifest, info, err := archive.ManifestSHA256(ctx, filepath.Base(pub.ArchiveURL), f, archive.DefaultOptions())
	if err != nil {
		return refcheck.Reference{}, nil, fmt.Errorf("authenticated archive could not be read: %w", err)
	}
	// Layout invariant: Joomla full packages are flat; a stray common top
	// directory would mean this is not a full package.
	if info.TopDir != "" {
		return refcheck.Reference{}, nil, fmt.Errorf("authenticated archive has unexpected layout (top dir %q, want flat)", info.TopDir)
	}

	algo, _ := pub.describe()
	return refcheck.Reference{
		Platform:  platformName,
		Version:   version,
		Algorithm: algo,
		// Digest is the raw concatenated published pair; it is part of the
		// cache key and validated on load. The display form is derived in
		// referenceFrom.
		Digest:      pub.key(),
		SourcePage:  pub.PageURL,
		ArchiveURL:  pub.ArchiveURL,
		ArchiveSize: arch.Size,
		Manifest:    manifest,
		Trust:       trust,
		Created:     time.Now().UTC(),
	}, warnings, nil
}

// comparisonInputs returns the ownership policy and the documented
// exclusions. The unexpected-file scan covers every directory the official
// package demonstrably owns: strict core-only directories, plus shared
// extension areas where a file is reported only when the extension root it
// belongs to carries official manifest entries. Third-party extensions,
// custom templates and language overrides are unknown ownership and stay
// unreported — absence from the official package is never a malware claim.
func comparisonInputs() (refcheck.Policy, []string) {
	policy := refcheck.Policy{
		// Joomla ships no site-configurable files in the archive;
		// configuration.php is created at install time and absent.
		// installation/, cache/ and tmp/ are commonly removed or emptied
		// in normal operation, so missing files there are not MISSING.
		OptionalPrefixes: []string{"installation", "cache", "tmp"},
		StrictDirs: []string{
			"libraries",
			"includes",
			"administrator/manifests",
			"administrator/includes",
			"api/includes",
			"cli",
		},
		// Shared extension areas: core and third-party extensions live side
		// by side. Depth is the number of levels forming one extension root
		// (plugins nest as plugins/<group>/<name>).
		SharedDirs: []refcheck.SharedDir{
			{Dir: "components", Depth: 1},
			{Dir: "modules", Depth: 1},
			{Dir: "plugins", Depth: 2},
			{Dir: "templates", Depth: 1},
			{Dir: "layouts", Depth: 1},
			{Dir: "media", Depth: 1},
			{Dir: "administrator/components", Depth: 1},
			{Dir: "administrator/modules", Depth: 1},
			{Dir: "administrator/templates", Depth: 1},
			{Dir: "api/components", Depth: 1},
		},
		LanguageTrees: []string{"language", "administrator/language", "api/language"},
		IgnoreNames:   map[string]bool{"error_log": true},
		RootExtra:     true,
		RootExtraExcluded: map[string]bool{
			"configuration.php": true,
			".htaccess":         true,
			"robots.txt":        true,
			"web.config":        true,
			"error_log":         true,
			"php.ini":           true,
		},
	}
	skipped := []string{
		"files in directories the official package does not demonstrably own stay unreported: third-party and custom extensions (new component, module, plugin, template, layout or media directories), language overrides and unknown language tokens, images and logs (runtime and user content), and files placed directly in shared area roots",
		"configuration.php and .htaccess (site-created configuration, never shipped in the archive)",
	}
	return policy, skipped
}

// referenceFrom converts a cache reference into the reported shape.
func referenceFrom(ref refcheck.Reference, cached bool) Reference {
	return Reference{
		SourcePage:  ref.SourcePage,
		ArchiveURL:  ref.ArchiveURL,
		Algorithm:   ref.Algorithm,
		Digest:      digestDisplay(ref.Algorithm, ref.Digest),
		ArchiveSize: ref.ArchiveSize,
		Cached:      cached,
		Created:     ref.Created.Format(time.RFC3339),
		Trust:       ref.EffectiveTrust(),
	}
}

// digestDisplay renders the raw concatenated digest pair for reports.
func digestDisplay(algorithm, digest string) string {
	if algorithm == "md5+sha1" && len(digest) == 72 {
		return "md5:" + digest[:32] + " sha1:" + digest[32:]
	}
	return digest
}
