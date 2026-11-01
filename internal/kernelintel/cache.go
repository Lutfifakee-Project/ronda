package kernelintel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Cache stores vulnerability feed snapshots under the user cache dir
// (~/.cache/ronda/kernel-feeds). Entries are keyed by the feed identity
// (provider, distribution, release, feed URL) and carry the parsed,
// kernel-filtered advisory subset, the feed-declared timestamp and the
// digest of the raw response. Writes are atomic with 0600 permissions;
// corrupted entries are treated as misses and never trusted.
type Cache struct {
	dir string
}

// NewCache returns the default user-level cache. It may return a cache with
// an empty directory when the user cache dir is unavailable; lookups then
// always miss and writes are skipped.
func NewCache() *Cache {
	base, err := os.UserCacheDir()
	if err != nil || base == "" {
		return &Cache{}
	}
	return &Cache{dir: filepath.Join(base, "ronda", "kernel-feeds")}
}

// NewCacheAt returns a cache rooted at dir (used by tests).
func NewCacheAt(dir string) *Cache {
	return &Cache{dir: dir}
}

// CacheKey derives the stable key for one feed identity. The architecture is
// part of the identity only for feeds whose data differs per architecture.
func CacheKey(provider, distro, release, feedURL string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		provider, distro, release, strings.ToLower(feedURL),
	}, "|")))
	return hex.EncodeToString(sum[:])
}

func (c *Cache) path(key string) string {
	if c == nil || c.dir == "" {
		return ""
	}
	return filepath.Join(c.dir, key+".json")
}

// Get loads one cached feed snapshot. The identity fields must match the
// request; a digest mismatch or parse failure is a miss.
func (c *Cache) Get(provider, distro, release, feedURL string) (CacheEntry, bool) {
	path := c.path(CacheKey(provider, distro, release, feedURL))
	if path == "" {
		return CacheEntry{}, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return CacheEntry{}, false
	}
	var entry CacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return CacheEntry{}, false
	}
	if entry.Provider != provider || entry.Distro != distro ||
		entry.Release != release || !strings.EqualFold(entry.URL, feedURL) {
		return CacheEntry{}, false
	}
	if err := entry.validate(); err != nil {
		return CacheEntry{}, false
	}
	return entry, true
}

// advisoryDigest computes the tamper-evidence digest of the advisory subset.
func advisoryDigest(as []Advisory) string {
	data, err := json.Marshal(as)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// validate guards against tampered or corrupted cache content.
func (e *CacheEntry) validate() error {
	if len(e.Advisories) == 0 && e.RawDigest == "" {
		return fmt.Errorf("cached feed entry is empty")
	}
	if e.RawDigest != "" && (len(e.RawDigest) != 64 || !isHex(e.RawDigest)) {
		return fmt.Errorf("cached raw digest is malformed")
	}
	if e.Digest == "" || e.Digest != advisoryDigest(e.Advisories) {
		return fmt.Errorf("cached advisory digest mismatch: content tampered or corrupted")
	}
	seen := make(map[string]bool, len(e.Advisories))
	for i := range e.Advisories {
		a := &e.Advisories[i]
		if a.CVE == "" || a.Package == "" || a.Provider == "" {
			return fmt.Errorf("cached advisory #%d is missing identity fields", i)
		}
		// Reference URLs from feeds are recorded but never fetched by
		// RONDA; validate their shape so a corrupted entry cannot smuggle
		// anything actionable.
		for _, ref := range a.References {
			if !strings.HasPrefix(ref, "https://") {
				return fmt.Errorf("cached reference is not https")
			}
		}
		seen[a.CVE+"\x00"+a.Package] = true
	}
	_ = seen
	return nil
}

// Put atomically stores a feed snapshot. Failures are silent: the cache is
// an optimization, never a source of truth.
func (c *Cache) Put(entry CacheEntry) {
	path := c.path(CacheKey(entry.Provider, entry.Distro, entry.Release, entry.URL))
	if path == "" {
		return
	}
	if err := os.MkdirAll(c.dir, 0o700); err != nil {
		return
	}
	if entry.FetchedAt.IsZero() {
		entry.FetchedAt = time.Now().UTC()
	}
	// Keep the advisory subset deterministic so cache files are comparable
	// and the digest is stable.
	sort.SliceStable(entry.Advisories, func(i, j int) bool {
		a, b := &entry.Advisories[i], &entry.Advisories[j]
		if a.CVE != b.CVE {
			return a.CVE < b.CVE
		}
		if a.Package != b.Package {
			return a.Package < b.Package
		}
		return a.FixedVersion < b.FixedVersion
	})
	entry.Digest = advisoryDigest(entry.Advisories)
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	tmp, err := os.CreateTemp(c.dir, "tmp-")
	if err != nil {
		return
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return
	}
	if err := tmp.Close(); err != nil {
		return
	}
	os.Chmod(tmpName, 0o600)
	os.Rename(tmpName, path)
}

// staleAfter bounds how long a cached feed stays usable as "cached"; past
// it the data is stale and online mode attempts a refresh.
var staleAfter = 30 * 24 * time.Hour

// trustFor maps a cache age and freshness window to a trust level.
func trustFor(age time.Duration, fresh time.Duration) string {
	switch {
	case age <= fresh:
		return TrustFresh
	case age <= staleAfter:
		return TrustCached
	default:
		return TrustStale
	}
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return false
		}
	}
	return true
}

// digestBytes is the hex SHA-256 of a raw response, recorded in cache
// entries so feed provenance stays auditable.
func digestBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
