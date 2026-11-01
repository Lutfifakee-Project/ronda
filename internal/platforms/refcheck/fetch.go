package refcheck

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Lutfifakee-Project/ronda/internal/official"
)

// Digest is one expected archive digest used to authenticate a download.
type Digest struct {
	Algorithm string // "sha256", "sha1" or "md5"
	Hex       string
}

// Archive describes a downloaded, digest-checked release archive.
type Archive struct {
	Path   string // temporary file; caller must remove it
	Size   int64
	SHA256 string
	SHA1   string
	MD5    string
}

// Cleanup removes the temporary archive file.
func (a Archive) Cleanup() {
	if a.Path != "" {
		os.Remove(a.Path)
	}
}

// DefaultMaxArchiveBytes bounds one official release archive download.
const DefaultMaxArchiveBytes = 512 << 20 // 512 MiB

// FetchArchive streams url into a temporary file (never into a scanned
// installation) while computing SHA-256/SHA-1/MD5 digests, enforcing maxBytes.
func FetchArchive(ctx context.Context, client *official.Client, rawURL string, maxBytes int64) (Archive, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxArchiveBytes
	}
	tmp, err := os.CreateTemp("", "ronda-ref-")
	if err != nil {
		return Archive{}, err
	}
	tmpName := tmp.Name()

	shaW := sha256.New()
	sha1W := sha1.New()
	md5W := md5.New()
	sink := io.MultiWriter(tmp, shaW, sha1W, md5W)

	n, dlErr := client.Download(ctx, rawURL, sink, maxBytes)
	closeErr := tmp.Close()
	if dlErr != nil || closeErr != nil {
		os.Remove(tmpName)
		if dlErr != nil {
			return Archive{}, dlErr
		}
		return Archive{}, closeErr
	}
	return Archive{
		Path:   tmpName,
		Size:   n,
		SHA256: hex.EncodeToString(shaW.Sum(nil)),
		SHA1:   hex.EncodeToString(sha1W.Sum(nil)),
		MD5:    hex.EncodeToString(md5W.Sum(nil)),
	}, nil
}

// VerifyDigests checks the downloaded archive against every published digest.
// All provided digests must match; an empty list is an error so that an
// archive can never slip through unauthenticated.
func (a Archive) VerifyDigests(digests []Digest) error {
	if len(digests) == 0 {
		return errors.New("no published digest available for the archive; refusing to trust an unauthenticated download")
	}
	for _, d := range digests {
		got, err := a.digest(d.Algorithm)
		if err != nil {
			return err
		}
		if !strings.EqualFold(got, d.Hex) {
			return fmt.Errorf("archive %s digest mismatch: expected %s, got %s", d.Algorithm, strings.ToLower(d.Hex), got)
		}
	}
	return nil
}

func (a Archive) digest(algorithm string) (string, error) {
	switch strings.ToLower(algorithm) {
	case "sha256":
		return a.SHA256, nil
	case "sha1":
		return a.SHA1, nil
	case "md5":
		return a.MD5, nil
	default:
		return "", fmt.Errorf("unsupported digest algorithm %q", algorithm)
	}
}
