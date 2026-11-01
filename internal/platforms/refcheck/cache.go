package refcheck

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Trust strength categories for archive references. They make the strength
// of the cryptographic evidence behind a manifest explicit instead of
// collapsing every match into one ambiguous notion of "authenticated".
const (
	// StrengthSHA256Authenticated means the exact archive was verified against
	// an independently published SHA-256 (or stronger) digest before the
	// per-file manifest was derived.
	StrengthSHA256Authenticated = "SHA256_AUTHENTICATED"
	// StrengthSignatureVerified means the archive was verified against a
	// cryptographic signature from the vendor. No platform in RONDA currently
	// has a producer for this category; it is defined so trust reporting
	// never has to shoehorn a future signature flow into another bucket.
	StrengthSignatureVerified = "SIGNATURE_VERIFIED"
	// StrengthLegacyDigestMatch means the archive matched only legacy
	// digests (MD5 and/or SHA-1) published by the vendor. The match is real,
	// but these algorithms are collision-broken, so this is not strong
	// cryptographic authentication and must be labelled as such.
	StrengthLegacyDigestMatch = "LEGACY_DIGEST_MATCH"
	// StrengthUnverified means no trustworthy reference was established.
	StrengthUnverified = "UNVERIFIED"
)

// Trust records how strongly the archive behind a reference manifest was
// authenticated. It travels with the cached reference so offline runs and
// reports keep showing the original trust level.
type Trust struct {
	// Category is one of the Strength* constants.
	Category string `json:"category"`
	// DigestAlgorithm names the strongest digest the trust decision relied
	// on, e.g. "sha256" or "md5+sha1".
	DigestAlgorithm string `json:"digest_algorithm"`
	// AuthenticationMethod describes where the digest came from and how it
	// was compared.
	AuthenticationMethod string `json:"authentication_method"`
	// ArchiveSHA256 is the SHA-256 of the authenticated archive when known.
	ArchiveSHA256 string `json:"archive_sha256,omitempty"`
	// Confidence is a short human-readable explanation of the trust level.
	Confidence string `json:"confidence"`
}

// TrustCategoryForAlgorithm derives the honest trust category for an archive
// authenticated only through its published digest algorithm. It backs old
// cache entries that predate the Trust block.
func TrustCategoryForAlgorithm(algorithm string) string {
	switch strings.ToLower(algorithm) {
	case "sha256":
		return StrengthSHA256Authenticated
	case "md5", "sha1", "md5+sha1", "sha1+md5":
		return StrengthLegacyDigestMatch
	default:
		return StrengthUnverified
	}
}

// Manifest is a per-file digest map (slash-relative path -> hex sha256).
type Manifest map[string]string

// Reference is a cached, authenticated per-file manifest.
type Reference struct {
	Platform    string `json:"platform"`
	Version     string `json:"version"`
	Algorithm   string `json:"algorithm"`   // digest used to authenticate the archive
	Digest      string `json:"digest"`      // lowercase hex of that digest
	SourcePage  string `json:"source_page"` // official page the digest was read from
	ArchiveURL  string `json:"archive_url"`
	ArchiveSize int64  `json:"archive_size"`
	TopDir      string `json:"top_dir,omitempty"`
	// Trust records the strength of the authentication evidence. Older cache
	// entries have an empty Trust; readers then derive the category from
	// Algorithm instead of inventing one.
	Trust    Trust     `json:"trust,omitempty"`
	Manifest Manifest  `json:"manifest"`
	Created  time.Time `json:"created"`
}

// EffectiveTrust returns the recorded trust block or derives a conservative
// one from the algorithm when the reference predates trust recording. It lets
// the platform adapters and reporters show one honest trust level for every
// cached reference, old or new.
func (r Reference) EffectiveTrust() Trust {
	return r.trustOrDerived()
}

// trustOrDerived returns the recorded trust block, deriving a conservative
// one from the algorithm when the reference predates trust recording.
func (r Reference) trustOrDerived() Trust {
	if r.Trust.Category != "" {
		return r.Trust
	}
	return Trust{
		Category:        TrustCategoryForAlgorithm(r.Algorithm),
		DigestAlgorithm: r.Algorithm,
	}
}

// CacheKey builds the cache key from the identity of the authenticated
// archive: platform, exact version, archive URL and archive digest.
func CacheKey(platform, version, archiveURL, digest string) string {
	sum := sha256.Sum256([]byte(platform + "|" + version + "|" + archiveURL + "|" + strings.ToLower(digest)))
	return hex.EncodeToString(sum[:])
}

// Store persists reference manifests under ~/.cache/ronda/references.
// Writes are atomic with 0600 permissions; corrupted entries are treated as
// cache misses and are never trusted.
type Store struct {
	dir string
}

// NewStore returns the default user-level store. It may return a store with
// an empty directory when the user cache dir is unavailable; lookups then
// always miss and writes are skipped.
func NewStore() *Store {
	base, err := os.UserCacheDir()
	if err != nil || base == "" {
		return &Store{}
	}
	return &Store{dir: filepath.Join(base, "ronda", "references")}
}

// NewStoreAt returns a store rooted at dir (used by tests).
func NewStoreAt(dir string) *Store {
	return &Store{dir: dir}
}

func (s *Store) path(key string) string {
	if s == nil || s.dir == "" {
		return ""
	}
	return filepath.Join(s.dir, key+".json")
}

// Get loads a cached reference. The key fields must all match the request,
// manifest paths must be safe and digests well-formed, otherwise the entry is
// discarded as a miss.
func (s *Store) Get(platform, version, archiveURL, digest string) (Reference, bool) {
	path := s.path(CacheKey(platform, version, archiveURL, digest))
	if path == "" {
		return Reference{}, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Reference{}, false
	}
	var ref Reference
	if err := json.Unmarshal(data, &ref); err != nil {
		return Reference{}, false
	}
	if ref.Platform != platform || ref.Version != version ||
		ref.ArchiveURL != archiveURL || !strings.EqualFold(ref.Digest, digest) {
		return Reference{}, false
	}
	if err := ref.Manifest.validate(); err != nil {
		return Reference{}, false
	}
	return ref, true
}

// GetForVersion loads the newest cached reference for a platform and exact
// version regardless of the archive identity. It backs offline mode, where
// the published digest cannot be re-fetched; the returned reference still
// carries its own authenticated archive identity and creation time.
func (s *Store) GetForVersion(platform, version string) (Reference, bool) {
	if s == nil || s.dir == "" {
		return Reference{}, false
	}
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return Reference{}, false
	}
	best := Reference{}
	found := false
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.dir, e.Name()))
		if err != nil {
			continue
		}
		var ref Reference
		if err := json.Unmarshal(data, &ref); err != nil {
			continue
		}
		if ref.Platform != platform || ref.Version != version {
			continue
		}
		if err := ref.Manifest.validate(); err != nil {
			continue
		}
		if !found || ref.Created.After(best.Created) {
			best, found = ref, true
		}
	}
	return best, found
}

// Put atomically stores a reference. Failures are silent: the cache is an
// optimization, never a source of truth.
func (s *Store) Put(ref Reference) {
	path := s.path(CacheKey(ref.Platform, ref.Version, ref.ArchiveURL, ref.Digest))
	if path == "" {
		return
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return
	}
	if ref.Created.IsZero() {
		ref.Created = time.Now().UTC()
	}
	data, err := json.Marshal(ref)
	if err != nil {
		return
	}
	tmp, err := os.CreateTemp(s.dir, "tmp-")
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

// validate guards against a tampered or corrupted cache file: every path must
// be relative and traversal-free, every digest a 64-char hex sha256.
func (m Manifest) validate() error {
	if len(m) == 0 {
		return fmt.Errorf("cached manifest is empty")
	}
	for path, sum := range m {
		if path == "" || strings.Contains(path, "..") || strings.Contains(path, "\\") || strings.HasPrefix(path, "/") {
			return fmt.Errorf("unsafe cached path %q", path)
		}
		if len(sum) != 64 || !isHex(sum) {
			return fmt.Errorf("invalid cached sha256 for %s", path)
		}
	}
	return nil
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}
