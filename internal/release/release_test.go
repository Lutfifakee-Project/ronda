package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestIsOfficialURLAcceptsOfficialLocations(t *testing.T) {
	good := []string{
		ReleasesBaseURL + "/latest/download/ronda-linux-amd64",
		ReleasesBaseURL + "/download/v0.1.1/SHA256SUMS",
		LatestAPIURL,
		"https://raw.githubusercontent.com/Lutfifakee-Project/ronda/main/install.sh",
		"https://objects.githubusercontent.com/SOME-SIGNED-PATH",
	}
	for _, u := range good {
		if err := IsOfficialURL(u); err != nil {
			t.Errorf("IsOfficialURL(%q) = %v, want nil", u, err)
		}
	}
}

func TestIsOfficialURLRejectsUntrusted(t *testing.T) {
	bad := []string{
		"http://github.com/Lutfifakee-Project/ronda/releases/latest/download/ronda-linux-amd64", // plaintext
		"https://evil.example.com/ronda-linux-amd64",
		"https://github.com/Other-Owner/ronda/releases/latest/download/ronda-linux-amd64",
		"https://api.github.com/repos/Other/repo/releases/latest",
		"https://github.com/Lutfifakee-Project/ronda.wiki/x",
		"ftp://github.com/Lutfifakee-Project/ronda/releases/x",
		"https://github.com/Lutfifakee-Project:ronda@evil.example.com/x", // userinfo
		"://broken",
		"",
	}
	for _, u := range bad {
		if err := IsOfficialURL(u); err == nil {
			t.Errorf("IsOfficialURL(%q) = nil, want error", u)
		}
	}
}

func TestRedirectValidation(t *testing.T) {
	// A redirect from an official URL to a non-official host must be refused
	// by the shared client. Simulate the CheckRedirect logic directly.
	client := OfficialHTTPClient()
	if client.Timeout != requestTimeout {
		t.Fatalf("client timeout = %v", client.Timeout)
	}
	start, _ := url.Parse(ReleasesBaseURL + "/latest/download/ronda-linux-amd64")
	hop, _ := url.Parse("https://evil.example.com/ronda")
	err := client.CheckRedirect(&http.Request{URL: hop}, []*http.Request{{URL: start}})
	if err == nil {
		t.Fatal("redirect to evil host must be refused")
	}
	hopOK, _ := url.Parse("https://objects.githubusercontent.com/signed-asset")
	if err := client.CheckRedirect(&http.Request{URL: hopOK}, []*http.Request{{URL: start}}); err != nil {
		t.Fatalf("redirect to the release CDN must be accepted: %v", err)
	}
	tooMany := make([]*http.Request, maxRedirects)
	for i := range tooMany {
		tooMany[i] = &http.Request{URL: start}
	}
	if err := client.CheckRedirect(&http.Request{URL: hopOK}, tooMany); err == nil {
		t.Fatal("redirect chain longer than the bound must be refused")
	}
}

func TestSigningStatusWithoutKey(t *testing.T) {
	if TrustedPublicKeyHex != "" {
		t.Skip("test binary was built with an embedded key")
	}
	if SigningStatus() != StatusNotConfigured {
		t.Fatalf("status = %q, want NOT_CONFIGURED", SigningStatus())
	}
	if HasTrustedKey() {
		t.Fatal("HasTrustedKey must be false without an embedded key")
	}
	err := VerifyDetachedSignature([]byte("SHA256SUMS content"), "00")
	if !errors.Is(err, ErrTrustNotConfigured) {
		t.Fatalf("err = %v, want ErrTrustNotConfigured", err)
	}
}

func TestVerifyDetachedSignatureRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("ronda 0.1.1 SHA256SUMS\nabc  ronda-linux-amd64\n")
	sig := ed25519.Sign(priv, message)

	// Verify through the same code path the updater uses, by temporarily
	// embedding the test key the way -ldflags -X would.
	old := TrustedPublicKeyHex
	TrustedPublicKeyHex = hexEncode(pub)
	defer func() { TrustedPublicKeyHex = old }()

	if SigningStatus() != StatusConfigured {
		t.Fatalf("status = %q, want CONFIGURED", SigningStatus())
	}
	if err := VerifyDetachedSignature(message, hexEncode(sig)); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	tampered := append([]byte(nil), message...)
	tampered[0] ^= 1
	if err := VerifyDetachedSignature(tampered, hexEncode(sig)); err == nil {
		t.Fatal("tampered message accepted")
	}
	// Flip one bit of the final signature byte. A bit flip (not an
	// overwrite with a fixed byte) guarantees the signature actually
	// changes: overwriting the last byte with 0x00 coincides with the
	// original value whenever the signer produced a trailing 0x00 byte
	// (p = 1/256), which made this check intermittently accept a
	// legitimate signature and report a false "tampered signature
	// accepted" failure.
	mutated := append([]byte(nil), sig...)
	mutated[len(mutated)-1] ^= 1
	if err := VerifyDetachedSignature(message, hexEncode(mutated)); err == nil {
		t.Fatal("tampered signature accepted")
	}
	if err := VerifyDetachedSignature(message, "zz"); err == nil {
		t.Fatal("non-hex signature accepted")
	}
}

func TestParsePublicKeyHex(t *testing.T) {
	if _, err := ParsePublicKeyHex(strings.Repeat("ab", 32)); err != nil {
		t.Fatalf("valid 32-byte key rejected: %v", err)
	}
	if _, err := ParsePublicKeyHex(""); err == nil {
		t.Fatal("empty key accepted")
	}
	if _, err := ParsePublicKeyHex("00"); err == nil {
		t.Fatal("short key accepted")
	}
	if _, err := ParsePublicKeyHex(strings.Repeat("zz", 32)); err == nil {
		t.Fatal("non-hex key accepted")
	}
}

// hexEncode avoids importing encoding/hex twice in the test file.
func hexEncode(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0x0f])
	}
	return string(out)
}
