package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/Lutfifakee-Project/ronda/internal/release"
)

// Checker queries the official RONDA release metadata. It performs metadata
// reads only: it never downloads binaries and never modifies anything.
type Checker struct {
	// APIURL is the official "latest release" API endpoint. It must pass
	// release.IsOfficialURL before any request is made.
	APIURL string

	// Client is the hardened official-host HTTP client.
	Client *http.Client

	// Validate gates APIURL before any request. nil uses
	// release.IsOfficialURL. It exists so tests can point the checker at a
	// local server; production code must keep it nil.
	Validate func(string) error
}

// NewChecker returns a Checker pinned to the official GitHub API with the
// shared hardened HTTP client.
func NewChecker() *Checker {
	return &Checker{
		APIURL: release.LatestAPIURL,
		Client: release.OfficialHTTPClient(),
	}
}

// githubRelease is the subset of the GitHub release payload RONDA reads.
// Unknown fields are ignored, so the decode stays compatible with real
// payloads that contain nested objects.
type githubRelease struct {
	TagName     string `json:"tag_name"`
	Name        string `json:"name"`
	Draft       bool   `json:"draft"`
	Prerelease  bool   `json:"prerelease"`
	HTMLURL     string `json:"html_url"`
	PublishedAt string `json:"published_at"`
}

// LatestTag returns the latest published release version without the "v"
// prefix. When the repository has no published release (GitHub answers 404)
// it returns ("", nil) so callers can report "no release" without treating
// it as a failure.
func (c *Checker) LatestTag(ctx context.Context) (string, error) {
	if c.APIURL == "" {
		return "", errors.New("no release API URL configured")
	}
	validate := c.Validate
	if validate == nil {
		validate = release.IsOfficialURL
	}
	if err := validate(c.APIURL); err != nil {
		return "", err
	}
	client := c.Client
	if client == nil {
		client = release.OfficialHTTPClient()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.APIURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("release check failed: %w", err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return "", nil
	case resp.StatusCode != http.StatusOK:
		return "", apiStatusError(resp.Status)
	}
	var body githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("invalid release metadata: %w", err)
	}
	tag := strings.TrimPrefix(strings.TrimSpace(body.TagName), "v")
	return tag, nil
}

// apiStatusError turns a non-2xx API status into a user-actionable error.
// Unauthenticated GitHub API access is rate limited per source IP, so a 403
// usually means the limit is exhausted rather than a missing release.
func apiStatusError(status string) error {
	if strings.HasPrefix(status, "403") {
		return fmt.Errorf("release API returned %s (GitHub rate-limits unauthenticated API requests per source IP; retry later)", status)
	}
	if strings.HasPrefix(status, "40") {
		return fmt.Errorf("release API returned %s", status)
	}
	return fmt.Errorf("release API returned %s", status)
}
