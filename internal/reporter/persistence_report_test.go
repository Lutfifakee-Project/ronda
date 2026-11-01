package reporter

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Lutfifakee-Project/ronda/internal/finding"
	"github.com/Lutfifakee-Project/ronda/internal/persistence"
)

// persistenceFixture builds a small Phase 5 report whose finding carries the
// full metadata set, so the terminal, JSON and HTML renderers can be checked
// for the same underlying evidence.
func persistenceFixture() persistence.Report {
	f := finding.Finding{
		Status:      finding.Suspicious,
		Severity:    finding.High,
		Title:       "Cron job executes a hidden script",
		Platform:    "persistence",
		Path:        "/etc/cron.d/suspicious",
		Line:        3,
		Rule:        "cron-hidden-target",
		Evidence:    "0 2 * * * root /root/.cfg/agent",
		Confidence:  finding.ConfidencePossible,
		Category:    "SCHEDULED_TASK_PERSISTENCE",
		MITRE:       []string{"T1053.003"},
		Target:      "/root/.cfg/agent",
		User:        "root",
		Owner:       "root:root",
		Permissions: "-rw-r--r--",
		Modified:    "2026-11-01T00:00:00Z",
		Kind:        "crontab",
	}
	return persistence.Report{
		Root:               "/mnt/synthetic",
		Distribution:       "Debian GNU/Linux",
		PackageDB:          "dpkg",
		InitSystems:        []string{"systemd", "cron"},
		Findings:           []finding.Finding{f},
		ArtifactsInspected: 7,
		TargetsInspected:   3,
		Denied:             []string{"/etc/cron.d/secret: permission denied"},
		DeniedCount:        1,
		Unverified:         []string{"/var/spool/cron/atjobs: unreadable"},
		UnverifiedCount:    1,
		Notes:              []string{"rpm database present; ownership checks are limited to dpkg"},
	}
}

// TestPersistenceTerminalFormat pins the standalone terminal renderer: rule
// ID, MITRE mapping from the registry, target, user, owner, permissions,
// evidence and the denied/unverified scope sections must all be present.
func TestPersistenceTerminalFormat(t *testing.T) {
	out := renderPersistenceTerminal(persistenceFixture())
	for _, want := range []string{
		"RONDA Persistence & Backdoor Scan",
		"[HIGH] Cron job executes a hidden script",
		"artifact: /etc/cron.d/suspicious",
		"line: 3",
		"rule: cron-hidden-target",
		"SCHEDULED_TASK_PERSISTENCE",
		"T1053.003",
		"confidence: possible",
		"target: /root/.cfg/agent",
		"user: root",
		"owner: root:root",
		"permissions: -rw-r--r--",
		"evidence: 0 2 * * * root /root/.cfg/agent",
		"[DENIED] /etc/cron.d/secret: permission denied",
		"[UNVERIFIED] /var/spool/cron/atjobs: unreadable",
		"UNVERIFIED (not CLEAN)",
		"Distribution: Debian GNU/Linux",
		"not proof that a program executed",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("terminal output missing %q", want)
		}
	}
}

// TestPersistenceJSONFormat verifies the standalone JSON report: the
// findings array itself must be present with stable field names, and the
// persistence scope object must carry the inspection counters.
func TestPersistenceJSONFormat(t *testing.T) {
	var buf bytes.Buffer
	if err := WritePersistence(&buf, persistenceFixture(), Options{Format: "json"}); err != nil {
		t.Fatalf("WritePersistence(json): %v", err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	fl, ok := doc["findings"].([]interface{})
	if !ok || len(fl) != 1 {
		t.Fatalf("findings array = %#v, want exactly the fixture finding", doc["findings"])
	}
	f0, ok := fl[0].(map[string]interface{})
	if !ok {
		t.Fatalf("finding entry is not an object: %#v", fl[0])
	}
	for key, want := range map[string]interface{}{
		"rule":        "cron-hidden-target",
		"path":        "/etc/cron.d/suspicious",
		"target":      "/root/.cfg/agent",
		"user":        "root",
		"owner":       "root:root",
		"permissions": "-rw-r--r--",
		"kind":        "crontab",
		"confidence":  "possible",
		"category":    "SCHEDULED_TASK_PERSISTENCE",
	} {
		if got := f0[key]; got != want {
			t.Errorf("finding %s = %#v, want %#v", key, got, want)
		}
	}
	mitre, ok := f0["mitre"].([]interface{})
	if !ok || len(mitre) != 1 || mitre[0] != "T1053.003" {
		t.Errorf("finding mitre = %#v, want [T1053.003]", f0["mitre"])
	}
	scope, ok := doc["persistence"].(map[string]interface{})
	if !ok {
		// The standalone report puts the scope object at the top level.
		scope = doc
	}
	for key, want := range map[string]interface{}{
		"artifacts_inspected": float64(7),
		"targets_inspected":   float64(3),
		"distribution":        "Debian GNU/Linux",
		"package_database":    "dpkg",
	} {
		if got := scope[key]; got != want {
			t.Errorf("persistence scope %s = %#v, want %#v", key, got, want)
		}
	}
	// Unreadable and unverified scopes are reported as arrays; they must
	// never be silently dropped from the JSON report.
	if denied, ok := scope["denied"].([]interface{}); !ok || len(denied) != 1 {
		t.Errorf("persistence scope denied = %#v, want one entry", scope["denied"])
	}
	if unverified, ok := scope["unverified"].([]interface{}); !ok || len(unverified) != 1 {
		t.Errorf("persistence scope unverified = %#v, want one entry", scope["unverified"])
	}
}

// TestPersistenceHTMLFormat verifies the standalone HTML report carries the
// same rule, severity, artifact, target, owner, permission, MITRE evidence
// and the denied/unverified sections.
func TestPersistenceHTMLFormat(t *testing.T) {
	var buf bytes.Buffer
	if err := WritePersistence(&buf, persistenceFixture(), Options{Format: "html"}); err != nil {
		t.Fatalf("WritePersistence(html): %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"cron-hidden-target",
		"sev-HIGH",
		"SCHEDULED_TASK_PERSISTENCE",
		"T1053.003",
		"/etc/cron.d/suspicious",
		"/root/.cfg/agent",
		"root:root",
		"-rw-r--r--",
		"Unreadable locations",
		"Unverified scopes",
		"possible",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML output missing %q", want)
		}
	}
}

// TestPersistenceFormatsShowSameFinding is the three-format consistency
// check required by Phase 5 §19: every format must present the same rule
// ID, severity, artifact and evidence.
func TestPersistenceFormatsShowSameFinding(t *testing.T) {
	rep := persistenceFixture()

	terminal := renderPersistenceTerminal(rep)
	var buf bytes.Buffer
	if err := WritePersistence(&buf, rep, Options{Format: "json"}); err != nil {
		t.Fatalf("json: %v", err)
	}
	jsonOut := buf.String()
	buf.Reset()
	if err := WritePersistence(&buf, rep, Options{Format: "html"}); err != nil {
		t.Fatalf("html: %v", err)
	}
	htmlOut := buf.String()

	for _, want := range []string{"cron-hidden-target", "/etc/cron.d/suspicious", "/root/.cfg/agent", "0 2 * * * root /root/.cfg/agent"} {
		for name, out := range map[string]string{"terminal": terminal, "json": jsonOut, "html": htmlOut} {
			if !strings.Contains(out, want) {
				t.Errorf("%s format missing %q", name, want)
			}
		}
	}
}

// TestPersistenceHTMLDeniedSection ensures unreadable locations are never
// silently dropped from the HTML report.
func TestPersistenceHTMLDeniedSection(t *testing.T) {
	var buf bytes.Buffer
	if err := WritePersistence(&buf, persistenceFixture(), Options{Format: "html"}); err != nil {
		t.Fatalf("html: %v", err)
	}
	if !strings.Contains(buf.String(), "/etc/cron.d/secret: permission denied") {
		t.Error("HTML must list denied locations")
	}
}
