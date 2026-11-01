package cmd

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestKernelHelpAndUsage pins the kernel command surface: help works, bad
// options fail with ExitUsage, and the help discloses the honest limitations.
func TestKernelHelpAndUsage(t *testing.T) {
	out := capture(t, func() {
		Execute([]string{"kernel", "--help"})
	})
	for _, want := range []string{"--root", "--offline", "--refresh", "--format", "UNVERIFIED", "never invokes rpm, dnf or yum"} {
		if !strings.Contains(out, want) {
			t.Errorf("kernel help missing %q", want)
		}
	}

	cases := [][]string{
		{"kernel", "--bogus"},
		{"kernel", "--root"},
		{"kernel", "--format", "pdf"},
		{"kernel", "--timeout", "abc"},
		{"kernel", "--timeout", "0"},
	}
	for _, args := range cases {
		code := Execute(args)
		if code != ExitUsage {
			t.Errorf("Execute(%v) = %d, want %d", args, code, ExitUsage)
		}
	}
}

func TestKernelOfflineRootJSON(t *testing.T) {
	// Isolate the feed cache: a populated user cache would turn this
	// offline-miss scenario into real findings.
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "/etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "/etc/os-release"),
		[]byte("ID=debian\nVERSION_ID=12\nVERSION_CODENAME=bookworm\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "/var/lib/dpkg"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "/var/lib/dpkg/status"),
		[]byte("Package: linux-image-6.1.0-18-amd64\nSource: linux\nVersion: 6.1.112-1\nArchitecture: amd64\nStatus: install ok installed\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var out string
	code := captureCode(t, &out, func() int {
		return Execute([]string{"kernel", "--root", root, "--offline", "--format", "json"})
	})
	if code != ExitOK {
		t.Fatalf("offline root with no feed cache must exit OK (nothing affected proven), got %d", code)
	}
	var doc struct {
		Schema string `json:"schema"`
		Kernel struct {
			Identity struct {
				Mode      string `json:"mode"`
				OSRelease struct {
					ID string `json:"id"`
				} `json:"osRelease"`
				Running struct {
					Available bool `json:"available"`
				} `json:"running"`
				Packages []struct {
					Name string `json:"name"`
				} `json:"packages"`
			} `json:"identity"`
			Findings []struct {
				CVE   string `json:"cve"`
				State string `json:"state"`
			} `json:"findings"`
			Feeds []struct {
				State string `json:"state"`
			} `json:"feeds"`
		} `json:"kernel"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("kernel JSON invalid: %v\n%s", err, out)
	}
	if doc.Schema != "ronda.kernel.v1" {
		t.Errorf("schema = %q", doc.Schema)
	}
	if doc.Kernel.Identity.Mode != "offline-rootfs" || doc.Kernel.Identity.OSRelease.ID != "debian" {
		t.Errorf("identity wrong: %+v", doc.Kernel.Identity)
	}
	if doc.Kernel.Identity.Running.Available {
		t.Error("offline target must not report a running kernel")
	}
	if len(doc.Kernel.Identity.Packages) == 0 {
		t.Error("inventory missing from JSON")
	}
	if len(doc.Kernel.Feeds) == 0 || doc.Kernel.Feeds[0].State != "no-reference-available" {
		t.Errorf("offline miss must surface no-reference-available: %+v", doc.Kernel.Feeds)
	}
	if !strings.Contains(out, "UNVERIFIED") && !strings.Contains(out, "no-reference-available") {
		t.Error("offline miss must be visible as unverified in JSON")
	}
}

func TestKernelOfflineTerminalIncludesDisclaimer(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "/etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "/etc/os-release"),
		[]byte("ID=debian\nVERSION_ID=12\nVERSION_CODENAME=bookworm\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out string
	captureCode(t, &out, func() int {
		return Execute([]string{"kernel", "--root", root, "--offline"})
	})
	for _, want := range []string{
		"offline RootFS target",
		"not a statement that the system is secure",
		"UNVERIFIED",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("terminal output missing %q in:\n%s", want, out)
		}
	}
}

// captureCode runs fn while capturing stdout, returning the exit code. The
// reader runs concurrently so large outputs cannot deadlock on the pipe.
func captureCode(t *testing.T, out *string, fn func() int) int {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan string)
	go func() {
		b, err := io.ReadAll(r)
		if err != nil {
			b = nil
		}
		done <- string(b)
	}()
	code := fn()
	w.Close()
	os.Stdout = orig
	*out = <-done
	return code
}
