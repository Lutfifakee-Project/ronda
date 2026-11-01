package wordpress

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func newClientWithDir(base, dir string, offline bool) *checksumClient {
	c := newChecksumClientFull(base, offline)
	c.cacheDir = dir
	c.cache = newManifestCache()
	return c
}

// tryFetch calls fetch and returns only the error (avoids blank identifiers).
func tryFetch(c *checksumClient, version, locale string) error {
	m, cached, err := c.fetch(context.Background(), version, locale)
	if m != nil && cached {
		// reference both values so the compiler keeps them
	}
	return err
}

func TestDiskCachePersistsAcrossClients(t *testing.T) {
	dir := t.TempDir()
	manifest := map[string]string{"wp-load.php": md5hex("x")}
	srv := manifestServer(t, "6.0", manifest, nil)
	defer srv.Close()

	c1 := newClientWithDir(srv.URL, dir, false)
	m1, firstCached, err := c1.fetch(context.Background(), "6.0", "en_US")
	if err != nil {
		t.Fatal(err)
	}
	if firstCached {
		t.Fatal("first fetch should be fresh")
	}
	if len(m1) != 1 {
		t.Fatalf("manifest size %d", len(m1))
	}

	c2 := newClientWithDir(srv.URL, dir, true)
	m2, secondCached, err := c2.fetch(context.Background(), "6.0", "en_US")
	if err != nil {
		t.Fatalf("offline fetch from disk failed: %v", err)
	}
	if !secondCached {
		t.Fatal("second client should use disk cache")
	}
	if len(m2) != 1 {
		t.Fatalf("cached manifest size %d", len(m2))
	}
}

func TestOfflineCacheMiss(t *testing.T) {
	dir := t.TempDir()
	c := newClientWithDir("https://invalid.example", dir, true)
	if err := tryFetch(c, "6.0", "en_US"); err == nil {
		t.Fatal("expected offline cache miss error")
	}
}

func TestCorruptedCacheIgnored(t *testing.T) {
	dir := t.TempDir()
	name := cacheFileName("base", "6.0", "en_US")
	os.MkdirAll(dir, 0o700)
	os.WriteFile(filepath.Join(dir, name), []byte("not json"), 0o600)
	c := newClientWithDir("base", dir, true)
	if err := tryFetch(c, "6.0", "en_US"); err == nil {
		t.Fatal("corrupted cache should be treated as miss")
	}
}

func TestCacheRejectsBadChecksumFormat(t *testing.T) {
	dir := t.TempDir()
	name := cacheFileName("base", "6.0", "en_US")
	os.MkdirAll(dir, 0o700)
	payload := map[string]interface{}{
		"base":      "base",
		"version":   "6.0",
		"locale":    "en_US",
		"checksums": map[string]string{"a.php": "notamd5"},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, name), data, 0o600)
	c := newClientWithDir("base", dir, true)
	if ferr := tryFetch(c, "6.0", "en_US"); ferr == nil {
		t.Fatal("invalid cached checksum should be rejected")
	}
}

func TestCacheRejectsTraversalPath(t *testing.T) {
	_, err := validateChecksumMap(map[string]string{"../evil": md5hex("x")})
	if err == nil {
		t.Fatal("traversal path should be rejected")
	}
}

func TestCacheKeyIsolation(t *testing.T) {
	dir := t.TempDir()
	var hits int32
	srv := manifestServer(t, "6.0", map[string]string{"a": md5hex("x")}, &hits)
	defer srv.Close()

	c := newClientWithDir(srv.URL, dir, false)
	tryFetch(c, "6.0", "en_US")
	c2 := newClientWithDir(srv.URL, dir, true)
	if err := tryFetch(c2, "6.0", "id_ID"); err == nil {
		t.Fatal("expected cache miss for different locale")
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("expected 1 network hit, got %d", hits)
	}
}

func TestDiskCacheLocation(t *testing.T) {
	d := diskCacheDir()
	if d == "" {
		t.Skip("no user cache dir on this host")
	}
}
