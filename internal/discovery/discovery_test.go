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

func TestWalkSkipsPseudoTreeRoot(t *testing.T) {
	pseudo := t.TempDir()
	orig := PseudoTrees
	PseudoTrees = []string{pseudo}
	defer func() { PseudoTrees = orig }()

	mustWrite(t, filepath.Join(pseudo, "shell.php"), "<?php eval($_POST['a']); ?>")

	res, err := Walk(context.Background(), pseudo, Options{IncludeHidden: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Files) != 0 {
		t.Fatalf("pseudo root contents must not be scanned, got %v", res.Files)
	}
	if len(res.SkippedTrees) != 1 || res.SkippedTrees[0] != pseudo {
		t.Fatalf("skipped tree must be disclosed, got %v", res.SkippedTrees)
	}
}

func TestWalkSkipsNestedPseudoTreeButScansSiblings(t *testing.T) {
	root := t.TempDir()
	pseudo := filepath.Join(root, "proc")
	orig := PseudoTrees
	PseudoTrees = []string{pseudo}
	defer func() { PseudoTrees = orig }()

	mustWrite(t, filepath.Join(pseudo, "pagemap"), "would block")
	mustWrite(t, filepath.Join(root, "site.php"), "<?php echo 1; ?>")

	res, err := Walk(context.Background(), root, Options{IncludeHidden: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Files) != 1 || res.Files[0] != filepath.Join(root, "site.php") {
		t.Fatalf("sibling must still be scanned, got %v", res.Files)
	}
	if len(res.SkippedTrees) != 1 || res.SkippedTrees[0] != pseudo {
		t.Fatalf("nested pseudo tree must be disclosed, got %v", res.SkippedTrees)
	}
}

func TestIsPseudoTreeExactMatchOnly(t *testing.T) {
	orig := PseudoTrees
	PseudoTrees = []string{"/proc"}
	defer func() { PseudoTrees = orig }()

	if !isPseudoTree("/proc") || !isPseudoTree("/proc/") {
		t.Fatal("/proc must be recognised")
	}
	if isPseudoTree("/home/user/proc") || isPseudoTree("/proctest") || isPseudoTree("") {
		t.Fatal("non-exact paths must not be treated as pseudo trees")
	}
}
