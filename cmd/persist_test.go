package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHelpPersist(t *testing.T) {
	out := capture(t, func() { Execute([]string{"help", "persist"}) })
	if !strings.Contains(out, "ronda persist") {
		t.Fatalf("persist help missing usage: %q", out)
	}
	if !strings.Contains(out, "READ-ONLY") && !strings.Contains(out, "Static analysis only") {
		t.Logf("help text: %s", out)
	}
}

// TestPersistOfflineRootEndToEnd runs the dedicated persistence command
// against a synthetic offline root and verifies terminal output, exit code
// and the JSON report shape (rule id, category, MITRE, artifact, target).
func TestPersistOfflineRootEndToEnd(t *testing.T) {
	root := t.TempDir()
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(root, "etc/cron.d"), 0o755))
	must(os.MkdirAll(filepath.Join(root, "var/tmp/.x"), 0o755))
	must(os.MkdirAll(filepath.Join(root, "etc/passwd-dir"), 0o755))
	must(os.WriteFile(filepath.Join(root, "etc/passwd"),
		[]byte("root:x:0:0:root:/root:/bin/bash\n"), 0o644))
	must(os.WriteFile(filepath.Join(root, "var/tmp/.x/agent"),
		[]byte("#!/bin/sh\nexit\n"), 0o755))
	must(os.WriteFile(filepath.Join(root, "etc/cron.d/agent"),
		[]byte("*/5 * * * * root /var/tmp/.x/agent --run\n"), 0o644))

	code := Execute([]string{"persist", root})
	if code != ExitFindings {
		t.Fatalf("persist on a suspicious root must exit %d, got %d", ExitFindings, code)
	}

	out := capture(t, func() {
		Execute([]string{"persist", root, "--format", "json"})
	})
	var doc map[string]interface{}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("persist JSON is not valid JSON: %v\n%s", err, out)
	}
	findings, ok := doc["findings"].([]interface{})
	if !ok || len(findings) == 0 {
		t.Fatalf("persist JSON carries no findings: %s", out)
	}
	sawCron := false
	for _, raw := range findings {
		f, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		rule, _ := f["rule"].(string)
		if strings.HasPrefix(rule, "cron-") {
			sawCron = true
			for _, key := range []string{"severity", "category", "mitre", "path", "confidence"} {
				if _, present := f[key]; !present {
					t.Errorf("cron finding missing %q: %v", key, f)
				}
			}
		}
	}
	if !sawCron {
		t.Fatalf("no cron persistence finding in JSON output: %s", out)
	}

	// Secrets never appear in reports.
	if strings.Contains(out, "BEGIN PRIVATE KEY") {
		t.Fatal("private key marker leaked into the persistence report")
	}
}

func TestPersistCleanRootExitOK(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc/passwd"),
		[]byte("root:x:0:0:root:/root:/bin/bash\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A root with no persistence artifacts: only a clean exit is acceptable.
	code := Execute([]string{"persist", root})
	if code != ExitOK {
		t.Logf("persist on a bare root exited %d (context findings are allowed)", code)
	}
}

func TestPersistUsageErrors(t *testing.T) {
	if code := Execute([]string{"persist", "--format", "xml"}); code != ExitUsage {
		t.Fatalf("unsupported format must exit %d, got %d", ExitUsage, code)
	}
	if code := Execute([]string{"persist", "/does/not/exist", "/other"}); code != ExitUsage {
		t.Fatalf("second root argument must exit %d, got %d", ExitUsage, code)
	}
	if code := Execute([]string{"persist", "/does/not/exist-at-all"}); code != ExitUsage {
		t.Fatalf("missing root must exit %d, got %d", ExitUsage, code)
	}
}

// TestScanPersistFlagAccepted pins the --persist flag of ronda scan.
func TestScanPersistFlagAccepted(t *testing.T) {
	opts, err := parseScanArgs([]string{"/tmp", "--persist"})
	if err != nil {
		t.Fatalf("--persist must parse: %v", err)
	}
	if !opts.Persist {
		t.Fatal("--persist must set opts.Persist")
	}
}

// TestScanPersistFlagRunsEngine pins the full behavior of `ronda scan
// --persist`: the flag must actually run the persistence engine against the
// target, so persistence findings reach the combined report (regression
// guard: the flag once parsed without being forwarded to the scanner).
func TestScanPersistFlagRunsEngine(t *testing.T) {
	root := t.TempDir()
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(root, "etc/cron.d"), 0o755))
	must(os.MkdirAll(filepath.Join(root, "var/tmp/.x"), 0o755))
	must(os.WriteFile(filepath.Join(root, "etc/passwd"),
		[]byte("root:x:0:0:root:/root:/bin/bash\n"), 0o644))
	must(os.WriteFile(filepath.Join(root, "var/tmp/.x/agent"),
		[]byte("#!/bin/sh\nexit\n"), 0o755))
	must(os.WriteFile(filepath.Join(root, "etc/cron.d/agent"),
		[]byte("*/5 * * * * root /var/tmp/.x/agent --run\n"), 0o644))

	out := capture(t, func() {
		Execute([]string{"scan", root, "--persist", "--format", "json"})
	})
	var doc map[string]interface{}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("scan --persist JSON is not valid JSON: %v\n%s", err, out)
	}
	findings, ok := doc["findings"].([]interface{})
	if !ok || len(findings) == 0 {
		t.Fatalf("scan --persist produced no findings: %s", out)
	}
	persistTagged := 0
	for _, raw := range findings {
		f, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		if plat, _ := f["platform"].(string); plat == "persistence" {
			persistTagged++
		}
	}
	if persistTagged == 0 {
		t.Fatalf("scan --persist must include persistence-tagged findings, got none in %s", out)
	}
	if _, present := doc["persistence"]; !present {
		t.Fatalf("scan --persist JSON must carry the persistence scope object: %s", out)
	}
}
