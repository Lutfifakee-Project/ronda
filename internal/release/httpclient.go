package release

import (
	"fmt"
	"net/http"
	"time"
)

// maxRedirects bounds the redirect chain for every official download.
const maxRedirects = 5

// requestTimeout bounds a single HTTP request, including the response body
// read performed by the standard client transport for non-streaming reads.
// Long artifact downloads stream the body themselves and are additionally
// size-capped by the caller.
const requestTimeout = 60 * time.Second

// OfficialHTTPClient returns the hardened HTTP client used for every
// official download:
//
//   - HTTPS only; TLS verification is never disabled.
//   - The initial URL and every redirect hop must pass IsOfficialURL.
//   - The redirect chain is bounded (maxRedirects).
//   - Requests time out instead of hanging a VPS session.
//
// The client never adds credentials, never sends environment data and never
// caches responses.
func OfficialHTTPClient() *http.Client {
	return &http.Client{
		Timeout: requestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("ronda: stopped after %d redirects", maxRedirects)
			}
			return IsOfficialURL(req.URL.String())
		},
	}
}
