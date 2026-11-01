// Package integrity computes file digests with bounded concurrency.
package integrity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"runtime"
	"sync"
)

// FileInfo is the digest and metadata collected for one file.
type FileInfo struct {
	Path   string
	Size   int64
	SHA256 string
	// Err is set when the file could not be read (often a permission problem).
	Err error
}

// DefaultWorkers returns a conservative worker count for the host.
func DefaultWorkers() int {
	n := runtime.NumCPU() * 2
	if n < 4 {
		n = 4
	}
	if n > 32 {
		n = 32
	}
	return n
}

// HashFiles hashes every path using a bounded worker pool.
//
// Results preserve the input order so callers get deterministic output.
// Cancellation is honoured and partial results are still returned.
func HashFiles(ctx context.Context, paths []string, workers int) []FileInfo {
	out := make([]FileInfo, len(paths))
	if workers < 1 {
		workers = DefaultWorkers()
	}
	if workers > len(paths) && len(paths) > 0 {
		workers = len(paths)
	}

	jobs := make(chan int)
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for idx := range jobs {
				out[idx] = hashOne(paths[idx])
			}
		}()
	}

	for i := range paths {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			for j := i; j < len(out); j++ {
				out[j] = FileInfo{Path: paths[j], Err: ctx.Err()}
			}
			return out
		case jobs <- i:
		}
	}
	close(jobs)
	wg.Wait()
	return out
}

func hashOne(path string) FileInfo {
	info := FileInfo{Path: path}
	f, err := os.Open(path)
	if err != nil {
		info.Err = err
		return info
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		info.Err = err
		return info
	}
	info.Size = st.Size()

	h := sha256.New()
	// io.CopyBuffer keeps memory flat for large files.
	if _, err := io.CopyBuffer(h, f, make([]byte, 64*1024)); err != nil {
		info.Err = err
		return info
	}
	info.SHA256 = hex.EncodeToString(h.Sum(nil))
	return info
}
