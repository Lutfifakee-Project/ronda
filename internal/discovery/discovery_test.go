package discovery

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestWalkFindsFilesAndSkipsDirs(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "a.php"), "x")
	mustWrite(t, filepath.Join(root, "sub", "b.txt"), "y")
	mustWrite(t, filepath.Join(root, ".git", "c"), "z")
	mustWrite(t, filepath.Join(root, ".hidden", "d"), "w")

	res, err := Walk(context.Background(), root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := len(res.Files)
	if got != 2 {
		t.Fatalf("expected 2 files (hidden/git skipped), got %d: %v", got, res.Files)
	}
}

func TestWalkTruncatesOnCancel(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "a"), "x")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := Walk(ctx, root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Truncated {
		t.Fatal("expected Truncated=true after cancel")
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
