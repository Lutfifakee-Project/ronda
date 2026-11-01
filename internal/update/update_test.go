package update

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Lutfifakee-Project/ronda/internal/release"
)

// hexEncode renders b as lowercase hex.
func hexEncode(b []byte) string {
	return hex.EncodeToString(b)
}

// sha256sum digests b and returns the raw sum.
func sha256sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

// lastPriv holds the private key of the most recent testKeys call so the
// release servers in each test can sign with the matching key.
var lastPriv ed25519.PrivateKey

// testKeys generates one Ed25519 keypair, embeds the public key the way
// -ldflags -X would, and returns a restore func.
func testKeys(t *testing.T) (pubHex string, restore func()) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	lastPriv = priv
	old := release.TrustedPublicKeyHex
	release.TrustedPublicKeyHex = hexEncode(pub)
	return hexEncode(pub), func() { release.TrustedPublicKeyHex = old }
}

// currentPriv returns the signing key of the active test.
func currentPriv(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	if lastPriv == nil {
		t.Fatal("no private key generated; call testKeys first")
	}
	return lastPriv
}

// fakeAsset returns artifact bytes that look enough like a RONDA binary for
// the ELF check: valid magic, the requested e_machine and a marker body.
func fakeAsset(arch string, marker string) []byte {
	var machine uint16
	switch arch {
	case "amd64":
		machine = elfMachineX86_64
	case "arm64":
		machine = elfMachineAArch64
	}
	// e_ident: magic, 64-bit class, little-endian data, version, osabi.
	head := []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0}
	head = append(head, make([]byte, 8)...)              // rest of e_ident (16 bytes total)
	head = append(head, 2, 0)                            // e_type = ET_EXEC (offset 16)
	head = append(head, byte(machine), byte(machine>>8)) // e_machine (offset 18)
	head = append(head, make([]byte, 8)...)
	return append(head, []byte(marker)...)
}

// releaseServer serves a complete release: artifact, SHA256SUMS and its
// detached signature made with priv over the exact sums bytes.
func releaseServer(t *testing.T, priv ed25519.PrivateKey, artifact []byte, sums string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ronda-linux-amd64":
			w.Write(artifact)
		case "/SHA256SUMS":
			w.Write([]byte(sums))
		case "/SHA256SUMS.sig":
			w.Write([]byte(hexEncode(ed25519.Sign(priv, []byte(sums)))))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// acceptAll is the test URL gate that lets the pipeline fetch from the local
// httptest server. Production code keeps nil (release.IsOfficialURL).
func acceptAll(string) error { return nil }

// epsFor returns Endpoints pointing at the local release server.
func epsFor(srv *httptest.Server) *Endpoints {
	return &Endpoints{
		ArtifactURL:  srv.URL + "/ronda-linux-amd64",
		ChecksumsURL: srv.URL + "/SHA256SUMS",
		SignatureURL: srv.URL + "/SHA256SUMS.sig",
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"0.1.0", "0.1.0", 0},
		{"v0.1.0", "0.1.0", 0},
		{"0.1.0", "0.1.1", -1},
		{"0.2.0", "0.1.9", 1},
		{"1.0.0", "0.9.9", 1},
		{"0.1", "0.1.0", 0},
		{"0.1.0-rc1", "0.1.0", 0},
		{"", "0.1.0", -1},
	}
	for _, c := range cases {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestCheckerLatestTag(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"tag_name":"v0.2.0","name":"r","author":{"login":"x"},"assets":[1,2]}`))
	}))
	defer srv.Close()

	c := &Checker{APIURL: srv.URL + "/repos/x/releases/latest", Client: srv.Client(), Validate: acceptAll}
	tag, err := c.LatestTag(context.Background())
	if err != nil {
		t.Fatalf("LatestTag: %v", err)
	}
	if tag != "0.2.0" {
		t.Fatalf("tag = %q, want 0.2.0", tag)
	}
}

func TestCheckerNoReleaseIsNotAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	c := &Checker{APIURL: srv.URL, Client: srv.Client(), Validate: acceptAll}
	tag, err := c.LatestTag(context.Background())
	if err != nil {
		t.Fatalf("404 must not be an error: %v", err)
	}
	if tag != "" {
		t.Fatalf("tag = %q, want empty", tag)
	}
}

func TestCheckerRejectsBadPayloadAndStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/bad":
			w.Write([]byte(`{not json`))
		case "/boom":
			http.Error(w, "no", http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	c := &Checker{APIURL: srv.URL + "/bad", Client: srv.Client(), Validate: acceptAll}
	if _, err := c.LatestTag(context.Background()); err == nil {
		t.Fatal("invalid JSON must fail")
	}
	c = &Checker{APIURL: srv.URL + "/boom", Client: srv.Client(), Validate: acceptAll}
	if _, err := c.LatestTag(context.Background()); err == nil {
		t.Fatal("HTTP 500 must fail")
	}
}

func TestCheckerRefusesUntrustedHost(t *testing.T) {
	// Default validation (nil): the httptest URL is not an official host, so
	// the checker must refuse before any request is made.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("no request must reach an untrusted host")
	}))
	defer srv.Close()

	c := &Checker{APIURL: srv.URL, Client: srv.Client()}
	if _, err := c.LatestTag(context.Background()); err == nil {
		t.Fatal("untrusted host must be refused")
	}
}

func TestPerformRefusesWithoutTrustedKey(t *testing.T) {
	if release.HasTrustedKey() {
		t.Skip("test binary was built with an embedded key")
	}
	dir := t.TempDir()
	_, restore := testKeys(t)
	release.TrustedPublicKeyHex = ""
	defer restore()

	_, err := Perform(context.Background(), Options{
		DestPath: filepath.Join(dir, "ronda"), CurrentVersion: "0.1.0",
		TargetVersion: "0.2.0", Arch: "amd64", Validate: acceptAll,
	})
	if err != release.ErrTrustNotConfigured {
		t.Fatalf("err = %v, want ErrTrustNotConfigured", err)
	}
}

func TestPerformRefusesSameVersionAndDowngrade(t *testing.T) {
	pubHex, restore := testKeys(t)
	_ = pubHex
	defer restore()
	dir := t.TempDir()

	base := Options{
		DestPath: filepath.Join(dir, "ronda"), CurrentVersion: "0.2.0",
		Arch: "amd64", Validate: acceptAll,
		VersionProbe: func(path, want string) error { return nil },
	}
	_, err := Perform(context.Background(), withTarget(base, "0.2.0"))
	if err != ErrAlreadyUpToDate {
		t.Fatalf("same version: err = %v, want ErrAlreadyUpToDate", err)
	}
	_, err = Perform(context.Background(), withTarget(base, "0.1.0"))
	if err == nil || !strings.Contains(err.Error(), "downgrade") {
		t.Fatalf("downgrade: err = %v, want downgrade refusal", err)
	}
	// Nothing must have been created.
	if _, serr := os.Stat(filepath.Join(dir, "ronda")); !os.IsNotExist(serr) {
		t.Fatal("no destination file must be created for refused updates")
	}
}

func withTarget(o Options, v string) Options {
	o.TargetVersion = v
	return o
}

func TestPerformSuccessAndBackup(t *testing.T) {
	pubHex, restore := testKeys(t)
	_ = pubHex
	defer restore()

	artifact := fakeAsset("amd64", "fake ronda body")
	sums := fmt.Sprintf("%s  ronda-linux-amd64\n", hexEncode(sha256sum(artifact)))
	priv := currentPriv(t)
	srv := releaseServer(t, priv, artifact, sums)

	dir := t.TempDir()
	dest := filepath.Join(dir, "ronda")
	os.WriteFile(dest, []byte("old binary"), 0o755)

	probe := func(path, want string) error {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !strings.Contains(string(data), "fake ronda body") {
			return fmt.Errorf("probe: wrong artifact content")
		}
		return nil
	}
	res, err := Perform(context.Background(), Options{
		DestPath: dest, CurrentVersion: "0.1.0", TargetVersion: "0.2.0",
		Arch: "amd64", Validate: acceptAll, Endpoints: epsFor(srv),
		VersionProbe: probe,
	})
	if err != nil {
		t.Fatalf("Perform: %v", err)
	}
	if res.From != "0.1.0" || res.To != "0.2.0" {
		t.Fatalf("result versions = %q -> %q", res.From, res.To)
	}
	got, _ := os.ReadFile(dest)
	if string(got) != string(artifact) {
		t.Fatal("installed artifact content mismatch")
	}
	old, _ := os.ReadFile(res.BackupPath)
	if string(old) != "old binary" {
		t.Fatal("backup must preserve the previous executable")
	}
	// No temp files may survive.
	matches, _ := filepath.Glob(filepath.Join(dir, ".ronda-update-*.tmp"))
	if len(matches) != 0 {
		t.Fatalf("temporary files survived: %v", matches)
	}
}

func TestPerformRejectsCorruptArtifact(t *testing.T) {
	pubHex, restore := testKeys(t)
	_ = pubHex
	defer restore()

	artifact := fakeAsset("amd64", "real body")
	// Sums signed for DIFFERENT content: the served artifact is corrupt.
	sums := fmt.Sprintf("%s  ronda-linux-amd64\n", hexEncode(sha256sum([]byte("different bytes"))))
	priv := currentPriv(t)
	srv := releaseServer(t, priv, artifact, sums)

	dir := t.TempDir()
	dest := filepath.Join(dir, "ronda")
	os.WriteFile(dest, []byte("old binary"), 0o755)

	_, err := Perform(context.Background(), Options{
		DestPath: dest, CurrentVersion: "0.1.0", TargetVersion: "0.2.0",
		Arch: "amd64", Validate: acceptAll, Endpoints: epsFor(srv),
		VersionProbe: func(string, string) error { return nil },
	})
	if err == nil || !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Fatalf("err = %v, want SHA-256 mismatch", err)
	}
	got, _ := os.ReadFile(dest)
	if string(got) != "old binary" {
		t.Fatal("the installed executable must stay untouched on checksum failure")
	}
}

func TestPerformRejectsBadSignature(t *testing.T) {
	pubHex, restore := testKeys(t)
	_ = pubHex
	defer restore()

	artifact := fakeAsset("amd64", "body")
	digest := hexEncode(sha256sum(artifact))
	sums := fmt.Sprintf("%s  ronda-linux-amd64\n", digest)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ronda-linux-amd64":
			w.Write(artifact)
		case "/SHA256SUMS":
			// Signed sums, then served sums differ: signature must fail.
			w.Write([]byte(sums + "# appended line breaks the signature\n"))
		case "/SHA256SUMS.sig":
			priv := currentPriv(t)
			w.Write([]byte(hexEncode(ed25519.Sign(priv, []byte(sums)))))
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	dest := filepath.Join(dir, "ronda")
	os.WriteFile(dest, []byte("old"), 0o755)

	_, err := Perform(context.Background(), Options{
		DestPath: dest, CurrentVersion: "0.1.0", TargetVersion: "0.2.0",
		Arch: "amd64", Validate: acceptAll, Endpoints: epsFor(srv),
		VersionProbe: func(string, string) error { return nil },
	})
	if err == nil {
		t.Fatal("a tampered SHA256SUMS must be rejected")
	}
	got, _ := os.ReadFile(dest)
	if string(got) != "old" {
		t.Fatal("the installed executable must stay untouched on signature failure")
	}
}

func TestPerformRejectsMissingChecksumEntryAndUntrustedDefaults(t *testing.T) {
	pubHex, restore := testKeys(t)
	_ = pubHex
	defer restore()

	artifact := fakeAsset("amd64", "body")
	sums := fmt.Sprintf("%s  ronda-some-other-asset\n", hexEncode(sha256sum(artifact)))
	priv := currentPriv(t)
	srv := releaseServer(t, priv, artifact, sums)

	dir := t.TempDir()
	dest := filepath.Join(dir, "ronda")
	os.WriteFile(dest, []byte("old"), 0o755)

	_, err := Perform(context.Background(), Options{
		DestPath: dest, CurrentVersion: "0.1.0", TargetVersion: "0.2.0",
		Arch: "amd64", Validate: acceptAll, Endpoints: epsFor(srv),
		VersionProbe: func(string, string) error { return nil },
	})
	if err == nil || !strings.Contains(err.Error(), "no checksum entry") {
		t.Fatalf("err = %v, want missing checksum entry", err)
	}

	// Production validation (nil Validate) must refuse the local test server.
	_, err = Perform(context.Background(), Options{
		DestPath: dest, CurrentVersion: "0.1.0", TargetVersion: "0.2.0",
		Arch:         "amd64",
		VersionProbe: func(string, string) error { return nil },
	})
	if err == nil {
		t.Fatal("default URL gate must refuse a non-official host")
	}
}

func TestPerformRejectsOversizeArtifact(t *testing.T) {
	pubHex, restore := testKeys(t)
	_ = pubHex
	defer restore()

	big := make([]byte, 4096)
	artifact := append(fakeAsset("amd64", "big"), big...)
	sums := fmt.Sprintf("%s  ronda-linux-amd64\n", hexEncode(sha256sum(artifact)))
	priv := currentPriv(t)
	srv := releaseServer(t, priv, artifact, sums)

	dir := t.TempDir()
	dest := filepath.Join(dir, "ronda")
	os.WriteFile(dest, []byte("old"), 0o755)
	_, err := Perform(context.Background(), Options{
		DestPath: dest, CurrentVersion: "0.1.0",
		TargetVersion: "0.2.0", Arch: "amd64", Validate: acceptAll,
		Endpoints:        epsFor(srv),
		MaxArtifactBytes: 16,
		VersionProbe:     func(string, string) error { return nil },
	})
	if err == nil || !strings.Contains(err.Error(), "safety limit") {
		t.Fatalf("err = %v, want size cap error", err)
	}
}

func TestPerformRollbackOnFailedPostCheck(t *testing.T) {
	pubHex, restore := testKeys(t)
	_ = pubHex
	defer restore()

	artifact := fakeAsset("amd64", "body")
	sums := fmt.Sprintf("%s  ronda-linux-amd64\n", hexEncode(sha256sum(artifact)))
	priv := currentPriv(t)
	srv := releaseServer(t, priv, artifact, sums)

	dir := t.TempDir()
	dest := filepath.Join(dir, "ronda")
	os.WriteFile(dest, []byte("old binary"), 0o755)

	calls := 0
	probe := func(path, want string) error {
		calls++
		if calls == 1 {
			return nil // pre-install probe passes
		}
		return fmt.Errorf("probe: broken after install") // post-install fails
	}
	_, err := Perform(context.Background(), Options{
		DestPath: dest, CurrentVersion: "0.1.0", TargetVersion: "0.2.0",
		Arch: "amd64", Validate: acceptAll, Endpoints: epsFor(srv),
		VersionProbe: probe,
	})
	if err == nil || !strings.Contains(err.Error(), "restored") {
		t.Fatalf("err = %v, want rollback report", err)
	}
	got, _ := os.ReadFile(dest)
	if string(got) != "old binary" {
		t.Fatal("rollback must restore the previous executable")
	}
}

func TestRecoverInterrupted(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "ronda")
	backup := dest + ".old"
	stale := filepath.Join(dir, ".ronda-update-123.tmp")

	// Simulate a crash between the two renames: dest missing, backup present.
	os.WriteFile(backup, []byte("old binary"), 0o755)
	os.WriteFile(stale, []byte("junk"), 0o600)
	if err := recoverInterrupted(dest); err != nil {
		t.Fatalf("recoverInterrupted: %v", err)
	}
	got, err := os.ReadFile(dest)
	if err != nil || string(got) != "old binary" {
		t.Fatalf("backup not restored: %v", err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatal("stale temp file must be removed")
	}

	// With dest present, recovery only removes stale temp files.
	os.WriteFile(dest, []byte("current"), 0o755)
	os.WriteFile(stale, []byte("junk"), 0o600)
	if err := recoverInterrupted(dest); err != nil {
		t.Fatalf("recoverInterrupted: %v", err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatal("stale temp file must be removed")
	}
	got, _ = os.ReadFile(dest)
	if string(got) != "current" {
		t.Fatal("the installed executable must not be touched by recovery")
	}
}

func TestCheckELFArch(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, data, 0o644)
		return p
	}
	if err := checkELFArch(write("amd64", fakeAsset("amd64", "x")), "amd64"); err != nil {
		t.Fatalf("amd64 ELF rejected: %v", err)
	}
	if err := checkELFArch(write("cross", fakeAsset("arm64", "x")), "amd64"); err == nil {
		t.Fatal("arm64 ELF must be rejected for amd64")
	}
	if err := checkELFArch(write("notelf", []byte("#!/bin/sh\n")), "amd64"); err == nil {
		t.Fatal("non-ELF must be rejected")
	}
	if err := checkELFArch(write("short", []byte{0x7f, 'E'}), "amd64"); err == nil {
		t.Fatal("truncated file must be rejected")
	}
}

func TestLookupChecksum(t *testing.T) {
	sums := "# comment line\n" +
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  ronda-linux-amd64\n" +
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb *ronda-linux-arm64\n"
	got, err := lookupChecksum(sums, "ronda-linux-amd64")
	if err != nil || got != strings.Repeat("a", 64) {
		t.Fatalf("amd64 lookup = %q, %v", got, err)
	}
	got, err = lookupChecksum(sums, "ronda-linux-arm64")
	if err != nil || got != strings.Repeat("b", 64) {
		t.Fatalf("arm64 lookup = %q, %v", got, err)
	}
	if _, err := lookupChecksum(sums, "missing"); err == nil {
		t.Fatal("missing entry must fail")
	}
	bad := strings.Repeat("z", 64) + "  ronda-linux-amd64\n"
	if _, err := lookupChecksum(bad, "ronda-linux-amd64"); err == nil {
		t.Fatal("non-hex digest must fail")
	}
}

func TestFirstLine(t *testing.T) {
	if got := firstLine("RONDA 0.1.0\nDetection rules: builtin-5\n"); got != "RONDA 0.1.0" {
		t.Fatalf("firstLine = %q", got)
	}
}

// --- helpers to reach the signing key used by the release server ---
