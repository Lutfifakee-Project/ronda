package kernelintel

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/Lutfifakee-Project/ronda/internal/official"
)

// LoadFunc parses one feed format from a reader and returns the
// kernel-relevant advisory subset plus the feed-declared timestamp (empty
// when the feed does not declare one).
type LoadFunc func(r *bufio.Reader) ([]Advisory, string, error)

// Loaders registers the feed parsers by format name.
var Loaders = map[string]LoadFunc{
	"debian-tracker": loadDebianTracker,
	"alpine-secdb":   loadAlpineSecdb,
	"arch-avg":       loadArchAVG,
	"redhat-cves":    loadRedHatCVEListing,
	"almalinux-osv":  loadAlmaOSV,
	"osv-response":   loadOSVResponse,
	"nvd-upstream":   loadNVDUpstream,
}

// FeedClient bundles the fetch dependencies so tests can retarget them.
type FeedClient struct {
	HTTP  *official.Client
	Cache *Cache
	// Offline restricts everything to cached data.
	Offline bool
	// Refresh forces re-download even when a fresh cache entry exists.
	Refresh bool
	// maxBodyBytes bounds in-memory responses (JSON APIs); bulk feeds
	// stream to disk instead.
	maxBodyBytes int64
}

// NewFeedClient wires the hardened official client to a cache. The allowlist
// covers exactly the official vendor security hosts this package uses.
func NewFeedClient(cache *Cache, offline bool) *FeedClient {
	allow := []official.Host{
		{Host: "security-tracker.debian.org", PathPrefix: "/tracker/data/"},
		{Host: "security-metadata.canonical.com"},
		{Host: "api.osv.dev", PathPrefix: "/v1/"},
		{Host: "secdb.alpinelinux.org"},
		{Host: "security.archlinux.org", PathPrefix: "/"},
		{Host: "access.redhat.com", PathPrefix: "/hydra/rest/securitydata/"},
		{Host: "security.almalinux.org"},
		{Host: "services.nvd.nist.gov", PathPrefix: "/rest/json/"},
	}
	max := int64(64 << 20) // in-memory cap for JSON APIs
	if offline {
		return &FeedClient{HTTP: official.NewClient(allow, max), Cache: cache, Offline: true, maxBodyBytes: max}
	}
	return &FeedClient{HTTP: official.NewClient(allow, max), Cache: cache, maxBodyBytes: max}
}

// tempDir returns the scratch directory for streamed downloads, outside any
// scanned RootFS.
func (fc *FeedClient) tempDir() string {
	base := os.TempDir()
	dir := filepath.Join(base, "ronda-feeds")
	_ = os.MkdirAll(dir, 0o700)
	return dir
}

// LoadFeed returns the advisory set for one feed source, using the cache
// first and downloading only when needed. Online mode refreshes stale
// entries; when the refresh fails, a cached entry is used with an explicit
// stale warning. Offline mode never touches the network: a miss is
// UNVERIFIED, never silently stale-as-current.
func (fc *FeedClient) LoadFeed(ctx context.Context, src FeedSource) (FeedResult, error) {
	load := Loaders[src.Format]
	if load == nil {
		return FeedResult{Miss: true, State: TrustNone, Note: "unknown feed format " + src.Format},
			fmt.Errorf("unknown feed format %q", src.Format)
	}
	if src.Format == "osv-response" && (src.MatchEcosystem != "" || src.MatchPackage != "") {
		eco, pkg := src.MatchEcosystem, src.MatchPackage
		load = func(r *bufio.Reader) ([]Advisory, string, error) {
			return loadOSVResponseFiltered(r, eco, pkg)
		}
	}
	if src.Format == "debian-tracker" && src.Release != "" {
		// The tracker JSON carries every Debian release at once, but this
		// feed identity is release-scoped (the cache key includes the
		// release) and matching consumes only same-release records, so
		// parse directly into the release subset. This bounds the parse
		// and cache memory to the records that can ever match, without
		// dropping any advisory that could change a verdict.
		load = debianTrackerLoader(src.Release)
	}
	if fc.Cache != nil && !fc.Refresh {
		if entry, ok := fc.Cache.Get(src.Provider, src.Distro, src.Release, src.URL); ok {
			state := trustFor(ageOf(entry.FetchedAt), src.Freshness)
			if fc.Offline {
				state = TrustOffline
			}
			res := FeedResult{
				Entry: entry,
				State: state,
				Age:   ageOf(entry.FetchedAt),
			}
			if state == TrustStale {
				res.Note = "cached data is stale; it is used only because a refresh was unavailable, and is never presented as current"
			} else if fc.Offline {
				res.Note = "offline mode: data comes from the local cache fetched " + entry.FetchedAt.UTC().Format(time.RFC3339)
			}
			if state == TrustFresh || fc.Offline || state == TrustCached || state == TrustStale {
				// Cached data is usable; online mode with fresh-or-cached
				// data skips the download (no unnecessary API calls).
				if state != TrustStale || fc.Offline {
					return res, nil
				}
				// Stale in online mode: try to refresh below.
				res.Note = "cached data is stale; attempting refresh"
			}
			// Attempt refresh; on failure keep the cached copy with the
			// stale warning attached.
			fresh, err := fc.download(ctx, src, load)
			if err != nil {
				res.Note = "refresh failed (" + err.Error() + "); using cached data fetched " +
					entry.FetchedAt.UTC().Format(time.RFC3339) + " which is stale and not presented as current"
				return res, nil
			}
			return fresh, nil
		}
	}
	if fc.Offline {
		return FeedResult{Miss: true, State: TrustNone,
			Note: "offline cache miss: no trusted vulnerability data for this feed; results are UNVERIFIED",
		}, nil
	}
	res, err := fc.download(ctx, src, load)
	if err != nil {
		return FeedResult{Miss: true, State: TrustNone,
			Note: "feed unavailable (" + err.Error() + "); matching for this source is UNVERIFIED",
		}, err
	}
	return res, nil
}

func ageOf(t time.Time) time.Duration {
	if t.IsZero() {
		return time.Duration(1 << 62)
	}
	d := time.Since(t)
	if d < 0 {
		return 0
	}
	return d
}

// download streams the feed to a temporary file (bounded by MaxBytes),
// parses it and stores the filtered subset in the cache.
func (fc *FeedClient) download(ctx context.Context, src FeedSource, load LoadFunc) (FeedResult, error) {
	if src.MaxBytes <= 0 {
		src.MaxBytes = 256 << 20
	}
	tmp, err := os.CreateTemp(fc.tempDir(), "feed-")
	if err != nil {
		return FeedResult{}, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if src.Method == "POST" {
		data, err := fc.HTTP.Post(ctx, src.URL, "application/json", []byte(src.Body))
		if err != nil {
			tmp.Close()
			return FeedResult{}, err
		}
		if int64(len(data)) > src.MaxBytes {
			tmp.Close()
			return FeedResult{}, fmt.Errorf("response exceeds the %d byte limit", src.MaxBytes)
		}
		if _, err := tmp.Write(data); err != nil {
			tmp.Close()
			return FeedResult{}, err
		}
	} else {
		if _, err := fc.HTTP.Download(ctx, src.URL, tmp, src.MaxBytes); err != nil {
			tmp.Close()
			return FeedResult{}, err
		}
	}
	if _, err := tmp.Seek(0, 0); err != nil {
		tmp.Close()
		return FeedResult{}, err
	}
	buf := bufio.NewReaderSize(tmp, 1<<16)
	advisories, feedUpdated, err := load(buf)
	if err != nil {
		tmp.Close()
		return FeedResult{}, fmt.Errorf("feed parse failed: %w", err)
	}
	tmp.Close()
	// Hash the raw response exactly as downloaded so feed provenance stays
	// auditable.
	rawDigest := ""
	if f, err := os.Open(tmpName); err == nil {
		h := sha256.New()
		_, errC := io.Copy(h, f)
		rawDigest = hex.EncodeToString(h.Sum(nil))
		f.Close()
		if errC != nil {
			return FeedResult{}, errC
		}
	}

	entry := CacheEntry{
		Provider:    src.Provider,
		Distro:      src.Distro,
		Release:     src.Release,
		URL:         src.URL,
		FetchedAt:   time.Now().UTC(),
		FeedUpdated: feedUpdated,
		RawDigest:   rawDigest,
		Advisories:  advisories,
		Format:      src.Format,
	}
	if fc.Cache != nil {
		fc.Cache.Put(entry)
	}
	return FeedResult{Entry: entry, State: TrustFresh}, nil
}

// decodeJSONResponse parses a small JSON API response body (already in
// memory) into the loader pipeline. Used by POST-based feeds.
func decodeJSONResponse(data []byte, target interface{}) error {
	if err := json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("invalid JSON response: %w", err)
	}
	return nil
}
