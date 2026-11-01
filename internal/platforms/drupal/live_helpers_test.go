package drupal

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/Lutfifakee-Project/ronda/internal/official"
	"github.com/Lutfifakee-Project/ronda/internal/platforms/refcheck"
)

// Live test helpers: they talk to the REAL official hosts, with no test
// overrides of endpoints, allowlists or verification logic.

func officialLiveClient() *official.Client {
	return official.NewClient(drupalAllowlist(), official.DefaultMaxResponseBytes)
}

func fetchLiveArchive(ctx context.Context, url, sha256Hex string) (refcheck.Archive, error) {
	arch, err := refcheck.FetchArchive(ctx, officialLiveClient(), url, DefaultMaxArchiveBytes)
	if err != nil {
		return refcheck.Archive{}, err
	}
	if err := arch.VerifyDigests([]refcheck.Digest{{Algorithm: "sha256", Hex: sha256Hex}}); err != nil {
		arch.Cleanup()
		return refcheck.Archive{}, fmt.Errorf("live archive authentication failed: %w", err)
	}
	return arch, nil
}

// refcheckLiveStore returns a fresh persistent store for one live test. A
// new directory per test keeps the run deterministic: a cache left over from
// an earlier live run must never make the "first verify is derived online"
// assertion fail (cross-process persistence itself is covered by the
// refcheck store unit tests, not here).
func refcheckLiveStore(t *testing.T) *refcheck.Store {
	t.Helper()
	dir, err := os.MkdirTemp("", "ronda-live-refs-drupal-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return refcheck.NewStoreAt(dir)
}
