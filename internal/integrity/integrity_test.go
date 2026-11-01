package integrity

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestHashFilesSHA256(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, []byte("abc"), 0o644); err != nil {
		t.Fatal(err)
	}
	res := HashFiles(context.Background(), []string{p}, 2)
	if len(res) != 1 {
		t.Fatalf("got %d results", len(res))
	}
	if res[0].Err != nil {
		t.Fatal(res[0].Err)
	}
	// sha256("abc")
	want := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if res[0].SHA256 != want {
		t.Fatalf("hash=%s want %s", res[0].SHA256, want)
	}
}

func TestHashMissingFileSetsError(t *testing.T) {
	res := HashFiles(context.Background(), []string{"/no/such/file/xyz"}, 1)
	if len(res) != 1 || res[0].Err == nil {
		t.Fatal("expected an error for missing file")
	}
}
