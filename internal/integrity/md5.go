package integrity

import (
	"crypto/md5"
	"encoding/hex"
	"io"
	"os"
)

// MD5File returns the lowercase hex MD5 digest of a file, streamed in
// fixed-size chunks so large files are never fully buffered in memory.
//
// MD5 is used only because the WordPress.org core checksum API publishes MD5
// digests. SHA-256 remains RONDA's default integrity digest elsewhere.
func MD5File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := md5.New()
	if _, err := io.CopyBuffer(h, f, make([]byte, 64*1024)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
