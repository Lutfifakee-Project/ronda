package official

import (
	"bytes"
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func testAllow() []Host {
	return []Host{
		{Host: "official.example", PathPrefix: "/files/"},
		{Host: "mirror.example", PathPrefix: "/official-downloads/"},
	}
}

func testClient(allow []Host) *Client {
	return NewClient(allow, 1024)
}

// hostOf returns the host:port of a URL string, mirroring how the client
// matches allowlist entries.
func hostOf(t *testing.T, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host
}

func TestCheckURLEnforcesAllowlist(t *testing.T) {
	c := testClient(testAllow())
	cases := []struct {
		url  string
		want bool
	}{
		{"https://official.example/files/x.tar.gz", true},
		{"https://official.example/files/a/b/c.txt", true},
		{"https://mirror.example/official-downloads/x.zip", true},
		{"http://official.example/files/x.tar.gz", false},           // not https
		{"https://evil.example/files/x.tar.gz", false},              // unknown host
		{"https://official.example.evil.com/files/x.tar.gz", false}, // suffix spoof
		{"https://official.example/other/x.tar.gz", false},          // wrong prefix
		{"https://mirror.example/official-downloads-ev/x.zip", false},
		{"https://official.example:8080/files/x.tar.gz", false}, // port mismatch
	}
	for _, tc := range cases {
		err := c.CheckURL(tc.url)
		if (err == nil) != tc.want {
			t.Errorf("CheckURL(%q) err=%v want accepted=%v", tc.url, err, tc.want)
		}
	}
}

// tlsServer starts a TLS test server whose certificate the returned client
// trusts. TLS verification itself stays enabled.
func tlsServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *Client) {
	t.Helper()
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)
	c := testClient(testAllow())
	c.http.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs},
	}
	return srv, c
}

func TestGetServesAllowlistedBody(t *testing.T) {
	srv, c := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte("hello")); err != nil {
			t.Errorf("write: %v", err)
		}
	})
	// Point the allowlist at the test server host (host:port, exact match).
	c.allow = []Host{{Host: hostOf(t, srv.URL)}}
	data, err := c.Get(context.Background(), srv.URL+"/file.txt")
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello" {
		t.Fatalf("body %q", data)
	}
}

func TestGetRejectsNonAllowlistedHost(t *testing.T) {
	srv, c := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte("nope")); err != nil {
			t.Errorf("write: %v", err)
		}
	})
	_, err := c.Get(context.Background(), srv.URL+"/file.txt")
	if err == nil || !strings.Contains(err.Error(), "allowlist") {
		t.Fatalf("expected allowlist error, got %v", err)
	}
}

func TestGetEnforcesSizeCap(t *testing.T) {
	srv, c := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		// The client aborts the read once the cap is reached, so this write
		// may legitimately fail with a broken pipe. The assertion under test
		// is the client-side size limit, so server write errors are ignored.
		_, _ = w.Write(bytes.Repeat([]byte("a"), 4096))
	})
	c.allow = []Host{{Host: hostOf(t, srv.URL)}}
	_, err := c.Get(context.Background(), srv.URL+"/big.txt")
	if err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("expected size limit error, got %v", err)
	}
}

func TestRedirectMustStayAllowlisted(t *testing.T) {
	offHost := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte("secret")); err != nil {
			t.Errorf("write: %v", err)
		}
	}))
	defer offHost.Close()

	srv, c := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, offHost.URL+"/leak", http.StatusFound)
	})
	c.allow = []Host{{Host: hostOf(t, srv.URL)}}
	_, err := c.Get(context.Background(), srv.URL+"/start")
	if err == nil {
		t.Fatal("expected redirect to non-allowlisted host to fail")
	}
}

func TestRedirectToAllowlistedMirrorSucceeds(t *testing.T) {
	srv, c := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/files/start" {
			http.Redirect(w, r, "https://"+r.Host+"/mirror-file", http.StatusFound)
			return
		}
		if _, err := w.Write([]byte("redirected")); err != nil {
			t.Errorf("write: %v", err)
		}
	})
	c.allow = []Host{{Host: hostOf(t, srv.URL)}}
	data, err := c.Get(context.Background(), srv.URL+"/files/start")
	if err != nil {
		t.Fatalf("allowlisted redirect should succeed: %v", err)
	}
	if string(data) != "redirected" {
		t.Fatalf("body after redirect %q", data)
	}
}

func TestGetReportsHTTPStatus(t *testing.T) {
	srv, c := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	c.allow = []Host{{Host: hostOf(t, srv.URL)}}
	_, err := c.Get(context.Background(), srv.URL+"/missing")
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("expected 404 error, got %v", err)
	}
}

func TestDownloadStreamsIntoWriter(t *testing.T) {
	srv, c := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write(bytes.Repeat([]byte("b"), 1000)); err != nil {
			t.Errorf("write: %v", err)
		}
	})
	c.allow = []Host{{Host: hostOf(t, srv.URL)}}
	var buf bytes.Buffer
	n, err := c.Download(context.Background(), srv.URL+"/arch", &buf, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1000 || buf.Len() != 1000 {
		t.Fatalf("n=%d len=%d", n, buf.Len())
	}
	_, err = c.Download(context.Background(), srv.URL+"/arch", &bytes.Buffer{}, 100)
	if err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("expected limit error on tiny cap, got %v", err)
	}
}
