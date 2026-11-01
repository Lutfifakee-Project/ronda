package archive

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// writeFile writes one regular file with deterministic content.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// buildTARGZ packs files (path -> content) under an optional top prefix.
// Symlink entries may be injected with content starting with "@link:".
func buildTARGZ(t *testing.T, path, top string, files map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	if top != "" {
		if err := tw.WriteHeader(&tar.Header{Name: top + "/", Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range sortedKeys(files) {
		hdr := &tar.Header{Mode: 0o644, Size: int64(len(files[name]))}
		if top != "" {
			hdr.Name = top + "/" + name
		} else {
			hdr.Name = name
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(files[name])); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
}

func buildZIP(t *testing.T, path string, files map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	for _, name := range sortedKeys(files) {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(files[name])); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func shaOf(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

// rep builds repeated filler content without long literals.
func rep(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}

func openForRead(t *testing.T, path string) *os.File {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func TestTARGZStripsTopPrefix(t *testing.T) {
	dir := t.TempDir()
	arch := filepath.Join(dir, "drupal-1.2.3.tar.gz")
	buildTARGZ(t, arch, "drupal-1.2.3", map[string]string{
		"core/index.php": "core",
		"index.php":      "root",
		"vendor/a.txt":   "a",
	})
	manifest, info, err := ManifestSHA256(context.Background(), arch, openForRead(t, arch), DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	if info.TopDir != "drupal-1.2.3" {
		t.Fatalf("TopDir=%q", info.TopDir)
	}
	if len(manifest) != 3 {
		t.Fatalf("manifest %v", manifest)
	}
	if manifest["core/index.php"] != shaOf("core") || manifest["index.php"] != shaOf("root") {
		t.Fatalf("manifest %v", manifest)
	}
	if info.Files != 3 || info.TotalBytes != int64(len("core")+len("root")+len("a")) {
		t.Fatalf("info %+v", info)
	}
}

func TestZIPFlatLayout(t *testing.T) {
	dir := t.TempDir()
	arch := filepath.Join(dir, "pkg.zip")
	buildZIP(t, arch, map[string]string{
		"libraries/a.php": "<?php",
		"index.php":       "<?php echo 1;",
	})
	manifest, info, err := ManifestSHA256(context.Background(), arch, openForRead(t, arch), DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	if info.TopDir != "" || len(manifest) != 2 {
		t.Fatalf("info %+v manifest %v", info, manifest)
	}
	if manifest["libraries/a.php"] != shaOf("<?php") {
		t.Fatalf("manifest %v", manifest)
	}
}

func TestRejectsTraversalAndAbsoluteEntries(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name  string
		build func(string)
	}{
		{"traversal", func(p string) { buildTARGZ(t, p, "", map[string]string{"../evil.txt": "x", "ok.txt": "y"}) }},
		{"absolute", func(p string) { buildTARGZ(t, p, "", map[string]string{"/abs.txt": "x", "ok.txt": "y"}) }},
	}
	for _, tc := range cases {
		arch := filepath.Join(dir, tc.name+".tar.gz")
		tc.build(arch)
		_, _, err := ManifestSHA256(context.Background(), arch, openForRead(t, arch), DefaultOptions())
		if err == nil {
			t.Fatalf("%s: expected unsafe path rejection", tc.name)
		}
	}
}

func TestSkipPrefixes(t *testing.T) {
	dir := t.TempDir()
	arch := filepath.Join(dir, "a.tar.gz")
	buildTARGZ(t, arch, "", map[string]string{
		"core/a.php":    "a",
		"sites/x/y.txt": "skipme",
	})
	manifest, info, err := ManifestSHA256(context.Background(), arch, openForRead(t, arch), Options{
		MaxEntries: DefaultMaxEntries, MaxFileBytes: DefaultMaxFileBytes, MaxTotalBytes: DefaultMaxTotalBytes,
		SkipPrefixes: []string{"sites"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := manifest["sites/x/y.txt"]; ok {
		t.Fatal("sites prefix was not skipped")
	}
	if len(manifest) != 1 {
		t.Fatalf("info %+v manifest %v", info, manifest)
	}
}

func TestEntryCountCap(t *testing.T) {
	dir := t.TempDir()
	arch := filepath.Join(dir, "many.tar.gz")
	files := map[string]string{"a.txt": "a", "b.txt": "b", "c.txt": "c"}
	buildTARGZ(t, arch, "", files)
	opts := DefaultOptions()
	opts.MaxEntries = 2
	_, _, err := ManifestSHA256(context.Background(), arch, openForRead(t, arch), opts)
	if err == nil {
		t.Fatal("expected entry count cap to trigger")
	}
}

func TestPerFileSizeCap(t *testing.T) {
	dir := t.TempDir()
	arch := filepath.Join(dir, "big.tar.gz")
	buildTARGZ(t, arch, "", map[string]string{"big.txt": rep("x", 100)})
	opts := DefaultOptions()
	opts.MaxFileBytes = 50
	_, _, err := ManifestSHA256(context.Background(), arch, openForRead(t, arch), opts)
	if err == nil {
		t.Fatal("expected per-file cap to trigger")
	}
}

func TestTotalSizeCap(t *testing.T) {
	dir := t.TempDir()
	arch := filepath.Join(dir, "tot.tar.gz")
	buildTARGZ(t, arch, "", map[string]string{
		"a.txt": rep("x", 80),
		"b.txt": rep("y", 80),
	})
	opts := DefaultOptions()
	opts.MaxTotalBytes = 100
	_, _, err := ManifestSHA256(context.Background(), arch, openForRead(t, arch), opts)
	if err == nil {
		t.Fatal("expected total size cap to trigger")
	}
}

func TestSymlinkEntriesSkipped(t *testing.T) {
	dir := t.TempDir()
	arch := filepath.Join(dir, "links.tar.gz")
	f, err := os.Create(arch)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "evil.php", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd", Mode: 0o777}); err != nil {
		t.Fatal(err)
	}
	if err := tw.WriteHeader(&tar.Header{Name: "ok.php", Typeflag: tar.TypeReg, Mode: 0o644, Size: 5}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	manifest, info, err := ManifestSHA256(context.Background(), arch, openForRead(t, arch), DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest) != 1 || manifest["ok.php"] != shaOf("hello") {
		t.Fatalf("manifest %v", manifest)
	}
	if info.SkippedNonRegular != 1 {
		t.Fatalf("info %+v", info)
	}
}

func TestDotDotTopPrefixRejected(t *testing.T) {
	dir := t.TempDir()
	arch := filepath.Join(dir, "escape.tar.gz")
	buildTARGZ(t, arch, "..", map[string]string{"a.txt": "a", "b.txt": "b"})
	_, _, err := ManifestSHA256(context.Background(), arch, openForRead(t, arch), DefaultOptions())
	if err == nil {
		t.Fatal("expected .. top prefix rejection")
	}
}

func TestCorruptArchiveRejected(t *testing.T) {
	dir := t.TempDir()
	arch := filepath.Join(dir, "corrupt.tar.gz")
	writeFile(t, arch, "this is not an archive at all")
	_, _, err := ManifestSHA256(context.Background(), arch, openForRead(t, arch), DefaultOptions())
	if err == nil {
		t.Fatal("expected unsupported/corrupt archive error")
	}
}

func TestEmptyArchiveRejected(t *testing.T) {
	dir := t.TempDir()
	arch := filepath.Join(dir, "empty.zip")
	buildZIP(t, arch, map[string]string{})
	_, _, err := ManifestSHA256(context.Background(), arch, openForRead(t, arch), DefaultOptions())
	if err == nil {
		t.Fatal("expected empty archive error")
	}
}
