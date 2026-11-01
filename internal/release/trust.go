// Package release contains the release trust model for RONDA: the allowlist
// of official distribution hosts and detached-signature verification for
// release artifacts.
//
// # TRUST MODEL
//
// SHA-256 checksums detect accidental corruption but cannot authenticate the
// publisher: an attacker who can replace a download can replace its checksum
// file too. Publisher authentication comes from a detached Ed25519 signature
// over the checksum file, verified against a public key that is embedded in
// the RONDA binary at build time. RONDA never trusts a key supplied at
// runtime, from the environment or from the downloaded metadata itself.
//
// The trusted public key is embedded only when its provenance and ownership
// are confirmed by the project owner, with:
//
//	-ldflags "-X github.com/Lutfifakee-Project/ronda/internal/release.TrustedPublicKeyHex=<64-byte ed25519 public key, hex>"
//
// While no key is embedded, SigningStatus reports NOT_CONFIGURED and every
// authenticated installation path must stay disabled. See verify.go.
package release

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Repository coordinates of the official RONDA distribution.
const (
	RepoOwner = "Lutfifakee-Project"
	RepoName  = "ronda"
)

// Official base URLs. Every download performed by the installer or the
// updater must be one of these or a redirect target that this package still
// accepts (see IsOfficialURL).
const (
	ReleasesBaseURL = "https://github.com/" + RepoOwner + "/" + RepoName + "/releases"
	LatestAPIURL    = "https://api.github.com/repos/" + RepoOwner + "/" + RepoName + "/releases/latest"
)

// errUntrusted is returned for any URL outside the official hosts.
var errUntrusted = errors.New("ronda: URL is not an official RONDA release location")

// officialHosts pins the allowed path prefixes for hosts that serve more
// content than RONDA releases. objects.githubusercontent.com is GitHub's
// release asset CDN: its asset URLs are signed and cannot be pinned further,
// so the host itself is the trust boundary and every hop must stay HTTPS.
var officialHosts = map[string][]string{
	"github.com":                    {"/" + RepoOwner + "/" + RepoName + "/"},
	"api.github.com":                {"/repos/" + RepoOwner + "/" + RepoName + "/"},
	"raw.githubusercontent.com":     {"/" + RepoOwner + "/" + RepoName + "/"},
	"objects.githubusercontent.com": {"/"},
}

// IsOfficialURL reports whether urlstr is an HTTPS URL on an official RONDA
// release host with an allowed path. This is the single gate used before any
// network fetch in the update path.
func IsOfficialURL(urlstr string) error {
	u, err := url.Parse(urlstr)
	if err != nil {
		return fmt.Errorf("%w: %v", errUntrusted, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("%w: scheme must be https, got %q", errUntrusted, u.Scheme)
	}
	if u.User != nil {
		return fmt.Errorf("%w: userinfo is not allowed", errUntrusted)
	}
	prefixes, ok := officialHosts[u.Hostname()]
	if !ok {
		return fmt.Errorf("%w: host %q is not an official release host", errUntrusted, u.Hostname())
	}
	path := u.Path
	for _, p := range prefixes {
		if strings.HasPrefix(path, p) {
			return nil
		}
	}
	return fmt.Errorf("%w: path %q is outside the official release prefix", errUntrusted, path)
}
