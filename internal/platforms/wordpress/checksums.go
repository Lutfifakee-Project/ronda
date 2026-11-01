package wordpress

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	checksumAPI      = "https://api.wordpress.org/core/checksums/1.0/"
	maxManifestBytes = 8 * 1024 * 1024
	cacheDirName     = "ronda"
	cacheSubdirName  = "checksums"
)

type manifestCache struct {
	mu    sync.Mutex
	items map[string]map[string]string
}

func newManifestCache() *manifestCache {
	return &manifestCache{items: make(map[string]map[string]string)}
}

func cacheKey(base, version, locale string) string {
	return base + "|" + version + "|" + locale
}

func (c *manifestCache) get(base, version, locale string) (map[string]string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	m, ok := c.items[cacheKey(base, version, locale)]
	return m, ok
}

func (c *manifestCache) put(base, version, locale string, m map[string]string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[cacheKey(base, version, locale)] = m
}

var sharedCache = newManifestCache()

type checksumClient struct {
	http     *http.Client
	cache    *manifestCache
	base     string
	offline  bool
	cacheDir string
}

func newChecksumClient() *checksumClient {
	return newChecksumClientFull(checksumAPI, false)
}

func newChecksumClientWithBase(base string) *checksumClient {
	return newChecksumClientFull(base, false)
}

func newChecksumClientFull(base string, offline bool) *checksumClient {
	return &checksumClient{
		http:     &http.Client{Timeout: 30 * time.Second},
		cache:    sharedCache,
		base:     base,
		offline:  offline,
		cacheDir: diskCacheDir(),
	}
}

func diskCacheDir() string {
	// RONDA_CACHE_DIR overrides the persistent cache location. Tests use
	// it to isolate runs: httptest base URLs are ephemeral and can be
	// recycled by the OS across runs, so a persistent entry keyed by a
	// recycled port could otherwise leak between runs.
	if env := os.Getenv("RONDA_CACHE_DIR"); env != "" {
		return env
	}
	base, err := os.UserCacheDir()
	if err != nil || base == "" {
		return ""
	}
	return filepath.Join(base, cacheDirName, cacheSubdirName)
}

func cacheFileName(base, version, locale string) string {
	sum := sha256.Sum256([]byte(cacheKey(base, version, locale)))
	return hex.EncodeToString(sum[:]) + ".json"
}

func (c *checksumClient) cachePath(base, version, locale string) string {
	if c.cacheDir == "" {
		return ""
	}
	return filepath.Join(c.cacheDir, cacheFileName(base, version, locale))
}

type diskEntry struct {
	Base      string
	Version   string
	Locale    string
	Checksums map[string]string
}

func parseDiskEntry(m map[string]interface{}) (diskEntry, bool) {
	var e diskEntry
	base, ok1 := m["base"].(string)
	version, ok2 := m["version"].(string)
	locale, ok3 := m["locale"].(string)
	cs, ok4 := m["checksums"].(map[string]interface{})
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return e, false
	}
	sums := make(map[string]string, len(cs))
	for k, v := range cs {
		s, ok := v.(string)
		if !ok {
			return e, false
		}
		sums[k] = s
	}
	e.Base = base
	e.Version = version
	e.Locale = locale
	e.Checksums = sums
	return e, true
}

func (c *checksumClient) readDisk(version, locale string) (map[string]string, bool) {
	path := c.cachePath(c.base, version, locale)
	if path == "" {
		return nil, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, false
	}
	entry, ok := parseDiskEntry(m)
	if !ok || entry.Base != c.base || entry.Version != version || entry.Locale != locale {
		return nil, false
	}
	manifest, err := validateChecksumMap(entry.Checksums)
	if err != nil {
		return nil, false
	}
	return manifest, true
}

func (c checksumClient) writeDisk(version, locale string, manifest map[string]string) {
	path := c.cachePath(c.base, version, locale)
	if path == "" {
		return
	}
	if err := os.MkdirAll(c.cacheDir, 0o700); err != nil {
		return
	}
	payload := map[string]interface{}{
		"base":      c.base,
		"version":   version,
		"locale":    locale,
		"checksums": manifest,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}
	tmp, err := os.CreateTemp(c.cacheDir, "tmp-")
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

func (c *checksumClient) fetch(ctx context.Context, version, locale string) (map[string]string, bool, error) {
	if m, ok := c.cache.get(c.base, version, locale); ok {
		return m, true, nil
	}

	if m, ok := c.readDisk(version, locale); ok {
		c.cache.put(c.base, version, locale, m)
		return m, true, nil
	}

	if c.offline {
		return nil, false, errors.New("offline mode and no cached manifest for version " + version + " locale " + locale)
	}

	q := url.Values{}
	q.Set("version", version)
	q.Set("locale", locale)
	endpoint := c.base + "?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "ronda-security-scanner")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, false, errors.New("checksum API rate limited the request")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("checksum API returned status %s", resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxManifestBytes))
	if err != nil {
		return nil, false, err
	}

	manifest, err := parseManifest(body, version)
	if err != nil {
		return nil, false, err
	}

	c.cache.put(c.base, version, locale, manifest)
	c.writeDisk(version, locale, manifest)
	return manifest, false, nil
}

func validateChecksumMap(in map[string]string) (map[string]string, error) {
	if len(in) == 0 {
		return nil, errors.New("empty checksum map")
	}
	out := make(map[string]string, len(in))
	for path, sum := range in {
		if path == "" || strings.Contains(path, "..") {
			return nil, fmt.Errorf("unsafe cached path %q", path)
		}
		if !isMD5Hex(sum) {
			return nil, fmt.Errorf("invalid cached checksum for %s", path)
		}
		out[path] = strings.ToLower(sum)
	}
	return out, nil
}

func parseManifest(body []byte, version string) (map[string]string, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("invalid checksum manifest JSON: %w", err)
	}
	if e, ok := raw["error"].(string); ok && e != "" {
		return nil, fmt.Errorf("checksum API error: %s", e)
	}
	checksums, ok := raw["checksums"].(map[string]interface{})
	if !ok || len(checksums) == 0 {
		return nil, errors.New("checksum manifest contains no entries")
	}

	flat := true
	for _, v := range checksums {
		if _, isStr := v.(string); !isStr {
			flat = false
			break
		}
	}

	var obj map[string]interface{}
	if flat {
		obj = checksums
	} else {
		var inner interface{}
		found := false
		for k, v := range checksums {
			if strings.EqualFold(k, version) {
				inner = v
				found = true
				break
			}
		}
		if !found {
			if len(checksums) == 1 {
				for _, v := range checksums {
					inner = v
				}
			} else {
				return nil, fmt.Errorf("manifest has no entry for version %s", version)
			}
		}
		m, ok := inner.(map[string]interface{})
		if !ok {
			return nil, errors.New("manifest version entry is not an object")
		}
		obj = m
	}

	out := make(map[string]string, len(obj))
	for path, sum := range obj {
		s, ok := sum.(string)
		if !ok {
			return nil, fmt.Errorf("checksum for %s is not a string", path)
		}
		if !isMD5Hex(s) {
			return nil, fmt.Errorf("checksum for %s is not a valid MD5", path)
		}
		out[path] = strings.ToLower(s)
	}
	return out, nil
}

func isMD5Hex(s string) bool {
	if len(s) != 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		isDigit := c >= 48 && c <= 57
		isLower := c >= 97 && c <= 102
		isUpper := c >= 65 && c <= 70
		if !isDigit && !isLower && !isUpper {
			return false
		}
	}
	return true
}
