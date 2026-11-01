package persistence

import (
	"testing"

	"github.com/Lutfifakee-Project/ronda/internal/finding"
)

// TestCronMentionOnlyWritablePathIsLowContext pins the precision policy:
// a scheduled command that merely MENTIONS a writable path (conditional
// test, cat, echo) is LOW context, never the HIGH execution finding.
func TestCronMentionOnlyWritablePathIsLowContext(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/etc/cron.d/checker", `*/5 * * * * root test -d /tmp/appdata || /usr/bin/telemetry --check
`)
	rep := f.scan()
	fls := findingsByRule(rep)["cron-exec-writable-path"]
	if len(fls) == 0 {
		t.Fatal("writable-path mention should still be recorded as context")
	}
	for _, fl := range fls {
		if fl.Severity != finding.Low {
			t.Fatalf("mention-only writable path must be LOW, got %s (%s)", fl.Severity, fl.Evidence)
		}
	}
}

// TestCronExecutedWritablePathStaysHigh pins the detection side of the
// policy: execution from a writable location keeps HIGH.
func TestCronExecutedWritablePathStaysHigh(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.writeExecutable("/var/tmp/.sysmon/agent", "script")
	f.write("/var/spool/cron/crontabs/root", "*/1 * * * * /var/tmp/.sysmon/agent\n")
	rep := f.scan()
	for _, fl := range findingsByRule(rep)["cron-exec-writable-path"] {
		if fl.Severity != finding.High {
			t.Fatalf("execution from a writable location must stay HIGH, got %s", fl.Severity)
		}
	}
}

// TestCorrelationPseudoDeviceAndDirectoryNeverReported pins the
// correlation eligibility rule: /dev/null (and friends) and directories
// are not payloads, no matter how many mechanisms mention them.
func TestCorrelationPseudoDeviceAndDirectoryNeverReported(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/etc/cron.d/noise", "0 * * * * root /usr/bin/job >/dev/null 2>&1\n")
	f.write("/etc/systemd/system/noise.service", "[Service]\nExecStart=/bin/sh -c \"exec >/dev/null; /usr/bin/job\"\n")
	f.write("/home/u/.bashrc", "exec >/dev/null 2>&1\n")
	f.write("/etc/cron.d/runcheck", "0 * * * * root test -d /run/systemd/system && /usr/bin/ready\n")
	f.write("/etc/systemd/system/runcheck.service", "[Service]\nExecStartCondition=/run/systemd/system\nExecStart=/usr/bin/ready\n")
	rep := f.scan()
	for _, fl := range rep.Findings {
		if fl.Rule == "correlation-shared-payload" || fl.Rule == "correlation-shared-hash" {
			t.Fatalf("pseudo-device or directory correlated as a payload: %s -> %s", fl.Rule, fl.Target)
		}
	}
}

// TestPAMDebianDenyPermitIdiomNotFlagged pins the standard Debian password
// stack idiom: pam_deny.so (requisite) followed by an unreachable
// pam_permit.so is distribution configuration, not an auth bypass.
func TestPAMDebianDenyPermitIdiomNotFlagged(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/etc/pam.d/common-password", `password	requisite			pam_deny.so
password	required			pam_permit.so
`)
	rep := f.scan()
	for _, fl := range rep.Findings {
		if fl.Rule == "pam-bypass-indicator" {
			t.Fatalf("dead-code pam_permit idiom flagged: %s (%s)", fl.Path, fl.Evidence)
		}
	}
}

// TestPAMPermitInAuthStackStillFlagged keeps the detection side: a live
// pam_permit in a sensitive auth stack without the deny guard is reported.
func TestPAMPermitInAuthStackStillFlagged(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/etc/pam.d/sudo", "auth	sufficient	pam_permit.so\n")
	rep := f.scan()
	countRule(t, rep, "pam-bypass-indicator", 1)
}
