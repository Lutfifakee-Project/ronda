package cmd

import (
	"io"
	"os"
	"strings"
	"testing"
)

// capture runs f while capturing os.Stdout and returns what was written.
func capture(t *testing.T, f func()) string {
	t.Helper()
	old := os.Stdout
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
	f()
	w.Close()
	os.Stdout = old
	return <-done
}

func TestHelpCommands(t *testing.T) {
	topics := [][]string{
		{"help"},
		{"help", "scan"},
		{"help", "kernel"},
		{"help", "system"},
		{"help", "update"},
		{"help", "version"},
		{"scan", "--help"},
		{"kernel", "--help"},
		{"system", "--help"},
		{"update", "--help"},
		{"version", "--help"},
	}
	for i := 0; i < len(topics); i++ {
		args := topics[i]
		out := capture(t, func() { Execute(args) })
		if len(strings.TrimSpace(out)) == 0 {
			t.Errorf("no output for args %v", args)
		}
	}
}

func TestVersionOutput(t *testing.T) {
	out := capture(t, func() { Execute([]string{"version"}) })
	if !strings.Contains(out, "RONDA") {
		t.Fatalf("version output missing RONDA: %q", out)
	}
}

func TestUnknownCommandExitCode(t *testing.T) {
	if code := Execute([]string{"nope"}); code != ExitUsage {
		t.Fatalf("exit=%d want %d", code, ExitUsage)
	}
}

func TestScanRequiresTarget(t *testing.T) {
	if code := Execute([]string{"scan"}); code != ExitUsage {
		t.Fatalf("exit=%d want %d", code, ExitUsage)
	}
}

// Phase 3 requires platform flags to combine (--drupal --joomla verifies
// both platforms in one scan). The former mutual-exclusion rule described a
// single-flag CLI and is superseded by the Phase 3 specification; --all
// stays exclusive with explicit platform flags, and repeated flags stay an
// error so the requested set remains unambiguous.
func TestParseScanPlatformCombination(t *testing.T) {
	opts, err := parseScanArgs([]string{"/tmp", "--drupal", "--joomla"})
	if err != nil {
		t.Fatalf("combination must be accepted: %v", err)
	}
	if len(opts.Platforms) != 2 || opts.Platforms[0] != "drupal" || opts.Platforms[1] != "joomla" {
		t.Fatalf("platforms = %v", opts.Platforms)
	}

	opts, err = parseScanArgs([]string{"/tmp", "--wordpress", "--drupal", "--joomla", "--laravel"})
	if err != nil {
		t.Fatalf("four-way combination must be accepted: %v", err)
	}
	if len(opts.Platforms) != 4 {
		t.Fatalf("platforms = %v", opts.Platforms)
	}

	if _, err := parseScanArgs([]string{"/tmp", "--all", "--drupal"}); err == nil {
		t.Fatal("--all with an explicit platform flag must stay an error")
	}
	if _, err := parseScanArgs([]string{"/tmp", "--drupal", "--drupal"}); err == nil {
		t.Fatal("a repeated platform flag must be an error")
	}
	if _, err := parseScanArgs([]string{"/tmp", "--drupal"}); err != nil {
		t.Fatalf("single flag must keep working: %v", err)
	}
}
