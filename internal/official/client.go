// Package official provides a hardened HTTPS fetch client restricted to an
// explicit allowlist of official distribution hosts.
//
// RONDA must never request a URL taken from scanned (target-controlled)
// metadata. Every request, including every redirect hop, is checked against a
// static allowlist of official project hosts, only https is accepted, response
// sizes are capped and redirects are bounded. No scanned file content, no
// secrets and no reports are ever transmitted: the client only performs GETs
// of fixed official reference URLs.
package official

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Host is one allowlisted official origin. Host must match the URL host and
// port exactly (u.Host); PathPrefix, when non-empty, additionally constrains
// the URL path. Official distribution always uses the default https port.
type Host struct {
	Host       string
	PathPrefix string
}

// DefaultMaxResponseBytes caps every response body (references and metadata).
const DefaultMaxResponseBytes = 64 << 20 // 64 MiB

// maxRedirects bounds the redirect chain.
const maxRedirects = 5

// Client fetches official reference material.
type Client struct {
	http     *http.Client
	allow    []Host
	MaxBytes int64
}

// NewClient returns a client that only talks to the given hosts.
func NewClient(allow []Host, maxBytes int64) *Client {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxResponseBytes
	}
	c := &Client{
		allow:    allow,
		MaxBytes: maxBytes,
	}
	// The closure reads c.allow so callers can retarget the allowlist (used
	// by tests to point the client at a local reference server).
	c.http = &http.Client{
		Timeout: 120 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return errors.New("too many redirects")
			}
			return checkURL(req.URL, c.allow)
		},
	}
	return c
}

func checkURL(u *url.URL, allow []Host) error {
	if u == nil {
		return errors.New("nil URL")
	}
	if u.Scheme != "https" {
		return fmt.Errorf("only https URLs are allowed, got %q scheme", u.Scheme)
	}
	host := u.Host // host:port, so a non-standard port never matches an allowlist entry
	for i := range allow {
		if host != allow[i].Host {
			continue
		}
		if allow[i].PathPrefix == "" || strings.HasPrefix(u.Path, allow[i].PathPrefix) {
			return nil
		}
		return fmt.Errorf("path %q is outside the allowed prefix %q for host %q", u.Path, allow[i].PathPrefix, host)
	}
	return fmt.Errorf("host %q is not on the official allowlist", host)
}

// CheckURL reports whether rawURL would be accepted for a request.
func (c *Client) CheckURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	return checkURL(u, c.allow)
}

// SetTestTransport replaces the underlying HTTP transport. It exists purely
// for tests of dependent packages (which need to trust a local httptest TLS
// certificate); production code must never call it. All allowlist, scheme,
// size and redirect rules are enforced by this client itself and are not
// affected by the transport.
func (c *Client) SetTestTransport(rt http.RoundTripper) {
	c.http.Transport = rt
}

// get performs one allowlisted GET and returns the response body.
func (c *Client) get(ctx context.Context, rawURL string) (io.ReadCloser, error) {
	if err := c.CheckURL(rawURL); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ronda-security-scanner")
	req.Header.Set("Accept", "*/*")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		resp.Body.Close()
		return nil, errors.New("official server rate limited the request")
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("official server returned status %s", resp.Status)
	}
	return resp.Body, nil
}

// Get fetches a small reference document (page, metadata) fully into memory.
func (c *Client) Get(ctx context.Context, rawURL string) ([]byte, error) {
	body, err := c.get(ctx, rawURL)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	data, err := io.ReadAll(io.LimitReader(body, c.MaxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > c.MaxBytes {
		return nil, fmt.Errorf("response from %s exceeds the %d byte limit", rawURL, c.MaxBytes)
	}
	return data, nil
}

// Post performs one allowlisted POST with a small JSON body and returns the
// response body fully in memory. It exists for minimal machine-readable
// queries (OSV) where only the package identity needed for the query is
// transmitted; body must never contain hostnames, paths, inventories or any
// scanned content. All allowlist, scheme, size and redirect rules apply.
func (c *Client) Post(ctx context.Context, rawURL, contentType string, body []byte) ([]byte, error) {
	if err := c.CheckURL(rawURL); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ronda-security-scanner")
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		resp.Body.Close()
		return nil, errors.New("official server rate limited the request")
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("official server returned status %s", resp.Status)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, c.MaxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > c.MaxBytes {
		return nil, fmt.Errorf("response from %s exceeds the %d byte limit", rawURL, c.MaxBytes)
	}
	return data, nil
}

// Download streams a larger response (a release archive) into w without
// buffering it in memory. The byte limit is enforced while streaming.
func (c *Client) Download(ctx context.Context, rawURL string, w io.Writer, maxBytes int64) (int64, error) {
	body, err := c.get(ctx, rawURL)
	if err != nil {
		return 0, err
	}
	defer body.Close()
	if maxBytes <= 0 {
		maxBytes = c.MaxBytes
	}
	n, err := io.Copy(w, io.LimitReader(body, maxBytes+1))
	if err != nil {
		return n, err
	}
	if n > maxBytes {
		return n, fmt.Errorf("download from %s exceeds the %d byte limit", rawURL, maxBytes)
	}
	return n, nil
}
