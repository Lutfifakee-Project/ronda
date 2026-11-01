package persistence

import (
	"os"
	"strings"
	"testing"

	"github.com/Lutfifakee-Project/ronda/internal/finding"
)

func TestPAMStandardStackNoFindings(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/etc/pam.d/sshd", `# PAM configuration for the Secure Shell service
@include common-auth
account    required     pam_nologin.so
@include common-account
session    required     pam_loginuid.so
session    optional     pam_keyinit.so force revoke
@include common-session
@include common-password
`)
	f.write("/etc/pam.d/systemd-user", `account  include pam_unix.so
session  required pam_permit.so
`)
	rep := f.scan()
	for _, fl := range rep.Findings {
		if fl.Severity.Rank() >= finding.Medium.Rank() {
			t.Fatalf("standard PAM stack produced %s finding: %s (%s)", fl.Severity, fl.Title, fl.Evidence)
		}
	}
}

func TestPAMCustomModuleStandardDirs(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/usr/lib/x86_64-linux-gnu/security/pam_custom.so", elfBytes(62))
	f.write("/etc/pam.d/sudo", "auth  required  /usr/lib/x86_64-linux-gnu/security/pam_custom.so\n")
	rep := f.scan()
	for _, fl := range rep.Findings {
		if strings.HasPrefix(fl.Rule, "pam-") && fl.Severity.Rank() >= finding.Medium.Rank() {
			t.Fatalf("standard-dir module reported: %s (%s)", fl.Rule, fl.Evidence)
		}
	}
}

func TestPAMExternalModulePath(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/opt/mfa/pam_mfa.so", elfBytes(62))
	f.write("/etc/pam.d/sshd", "auth  required  /opt/mfa/pam_mfa.so\n")
	rep := f.scan()
	countRule(t, rep, "pam-external-module-path", 1)
	fl := findingsByRule(rep)["pam-external-module-path"][0]
	if fl.Severity != finding.Medium {
		t.Errorf("external module path is context (MEDIUM), got %s", fl.Severity)
	}
}

func TestPAMMissingModule(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/etc/pam.d/login", "auth  required  /usr/lib/security/pam_gone.so\n")
	rep := f.scan()
	countRule(t, rep, "pam-missing-module", 1)
	fl := findingsByRule(rep)["pam-missing-module"][0]
	if fl.Severity != finding.Low {
		t.Errorf("missing module is LOW, got %s", fl.Severity)
	}
}

func TestPAMWorldWritableModule(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.writeFileMode("/opt/mfa/pam_mfa.so", elfBytes(62), 0o666)
	f.write("/etc/pam.d/sshd", "auth  required  /opt/mfa/pam_mfa.so\n")
	rep := f.scan()
	countRule(t, rep, "pam-writable-module", 1)
	fl := findingsByRule(rep)["pam-writable-module"][0]
	if fl.Severity != finding.High {
		t.Errorf("world-writable PAM module must be HIGH, got %s", fl.Severity)
	}
}

func TestPAMModuleInTmp(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/tmp/pam_hook.so", elfBytes(62))
	f.write("/etc/pam.d/su", "auth  sufficient  /tmp/pam_hook.so\n")
	rep := f.scan()
	countRule(t, rep, "pam-writable-module", 1)
}

func TestPAMInvalidConfigurationSkipped(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/etc/pam.d/broken", "auth\nrequired\n\n# comment\n")
	rep := f.scan()
	for _, fl := range rep.Findings {
		if strings.HasPrefix(fl.Rule, "pam-") {
			t.Fatalf("malformed stack lines must not produce findings, got %s", fl.Rule)
		}
	}
}

func TestPAMExecHelperSuspicious(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/tmp/pam-helper.sh", "script")
	f.write("/etc/pam.d/cron", "session  required  pam_exec.so /tmp/pam-helper.sh\n")
	rep := f.scan()
	countRule(t, rep, "pam-exec-suspicious", 1)
	fl := findingsByRule(rep)["pam-exec-suspicious"][0]
	if fl.Severity != finding.High {
		t.Errorf("writable pam_exec helper must be HIGH, got %s", fl.Severity)
	}
}

func TestPAMExecHelperLegitimate(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/usr/local/sbin/pam-notify.sh", "script")
	f.write("/etc/pam.d/sshd", "session  optional  pam_exec.so /usr/local/sbin/pam-notify.sh\n")
	rep := f.scan()
	for _, fl := range rep.Findings {
		if fl.Rule == "pam-exec-suspicious" {
			t.Fatalf("/usr-local helper misclassified: %s", fl.Evidence)
		}
	}
}

func TestPAMPermitInSensitiveService(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/etc/pam.d/sudo", "auth  sufficient  pam_permit.so\naccount required pam_unix.so\n")
	rep := f.scan()
	countRule(t, rep, "pam-bypass-indicator", 1)
	fl := findingsByRule(rep)["pam-bypass-indicator"][0]
	if fl.Severity != finding.Medium {
		t.Errorf("bypass indicator should be MEDIUM, got %s", fl.Severity)
	}
}

func TestPAMPermissionDeniedReported(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission-denied fixtures need a non-root test runner")
	}
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/etc/pam.d/sshd", "auth required pam_unix.so\n")
	f.writeFileMode("/etc/pam.d/sshd", "auth required pam_unix.so\n", 0o000)
	rep := f.scan()
	denied := false
	for _, d := range rep.Denied {
		if strings.Contains(d, "/etc/pam.d/sshd") {
			denied = true
		}
	}
	if !denied {
		t.Fatalf("unreadable PAM stack must be reported as denied, got %v", rep.Denied)
	}
}
