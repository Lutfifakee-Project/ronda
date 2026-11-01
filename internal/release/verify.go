package release

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// TrustedPublicKeyHex is the Ed25519 public key of the official RONDA
// release signer, embedded at build time via -ldflags -X. It is EMPTY by
// default: an empty key means signature verification is NOT_CONFIGURED and
// authenticated installation or self-update must stay disabled. There is
// deliberately no way to set the trusted key at runtime.
//
// The value must only be embedded after the project owner confirms the
// provenance and ownership of the corresponding private key. Never embed a
// key of unknown origin, and never embed or commit a private key.
var TrustedPublicKeyHex = ""

// SignatureStatus describes whether artifact signature verification can
// actually run in this binary.
type SignatureStatus string

const (
	// StatusConfigured means a trusted Ed25519 public key was embedded at
	// build time and detached signatures can be verified.
	StatusConfigured SignatureStatus = "CONFIGURED"

	// StatusNotConfigured means no trusted public key is embedded. SHA-256
	// checksums still detect accidental corruption, but artifacts cannot be
	// authenticated, so automatic authenticated installation and self-update
	// must stay disabled.
	StatusNotConfigured SignatureStatus = "NOT_CONFIGURED"
)

// ErrTrustNotConfigured is returned by every verification entry point when
// no trusted public key is embedded in the binary.
var ErrTrustNotConfigured = errors.New("ronda: release signature verification is NOT_CONFIGURED (no trusted public key embedded at build time)")

// SigningStatus reports whether detached-signature verification is available
// in this binary. The status is derived from the embedded key only; it is
// never read from configuration or the environment.
func SigningStatus() SignatureStatus {
	if TrustedPublicKeyHex == "" {
		return StatusNotConfigured
	}
	return StatusConfigured
}

// HasTrustedKey reports whether signature verification can be performed.
func HasTrustedKey() bool {
	return TrustedPublicKeyHex != ""
}

// TrustedKey parses the embedded trusted public key.
func TrustedKey() (ed25519.PublicKey, error) {
	if TrustedPublicKeyHex == "" {
		return nil, ErrTrustNotConfigured
	}
	return ParsePublicKeyHex(TrustedPublicKeyHex)
}

// ParsePublicKeyHex decodes a hex-encoded Ed25519 public key. The accepted
// form is exactly 64 hex characters (32 bytes).
func ParsePublicKeyHex(s string) (ed25519.PublicKey, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return nil, errors.New("ronda: empty public key")
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("ronda: public key is not valid hex: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("ronda: public key must be %d bytes, got %d", ed25519.PublicKeySize, len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

// VerifyDetachedSignature authenticates message against a hex-encoded
// detached Ed25519 signature using the trusted public key embedded at build
// time. It returns ErrTrustNotConfigured when no key is embedded, and a
// verification error when the signature does not match.
//
// The signed message is the exact byte content of the SHA256SUMS file; the
// signature is the 64-byte Ed25519 value, hex-encoded.
func VerifyDetachedSignature(message []byte, sigHex string) error {
	if !HasTrustedKey() {
		return ErrTrustNotConfigured
	}
	key, err := TrustedKey()
	if err != nil {
		return err
	}
	sigHex = strings.TrimSpace(strings.ToLower(sigHex))
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return fmt.Errorf("ronda: signature is not valid hex: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("ronda: signature must be %d bytes, got %d", ed25519.SignatureSize, len(sig))
	}
	if !ed25519.Verify(key, message, sig) {
		return errors.New("ronda: signature verification FAILED: the artifact set did not come from the trusted release signer")
	}
	return nil
}
