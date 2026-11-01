package persistence

import (
	"strings"
	"testing"

	"github.com/Lutfifakee-Project/ronda/internal/finding"
)

// accountsBaseRoot returns a fixture whose homes all exist, so the
// home-missing context rule stays silent unless a test targets it.
func accountsBaseRoot(t *testing.T) *fixtureRoot {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.addGroups()
	f.mkdirs("/root")
	f.mkdirs("/home/ubuntu")
	f.mkdirs("/var/lib/svc")
	return f
}

func TestAccountsNormalNoFindings(t *testing.T) {
	f := accountsBaseRoot(t)
	rep := f.scan()
	for _, fl := range rep.Findings {
		if fl.Severity.Rank() >= finding.Medium.Rank() {
			t.Fatalf("normal accounts produced %s finding: %s (%s)", fl.Severity, fl.Title, fl.Evidence)
		}
	}
}

func TestAccountsServiceAccountClean(t *testing.T) {
	f := accountsBaseRoot(t)
	rep := f.scan()
	for _, fl := range rep.Findings {
		if fl.Rule == "account-unusual-shell" || fl.Rule == "account-home-missing" {
			if fl.User == "svc" || fl.User == "daemon" {
				t.Fatalf("service account flagged: %s (%s)", fl.Rule, fl.Evidence)
			}
		}
	}
}

func TestAccountsExtraUIDZero(t *testing.T) {
	f := accountsBaseRoot(t)
	f.write("/etc/passwd", basePasswd+"toor:x:0:0:backdoor root:/root:/bin/bash\n")
	rep := f.scan()
	countRule(t, rep, "account-extra-uid0", 1)
	fl := findingsByRule(rep)["account-extra-uid0"][0]
	if fl.Severity != finding.High {
		t.Errorf("second UID-0 account must be HIGH, got %s", fl.Severity)
	}
	if fl.User != "toor" {
		t.Errorf("user = %q, want toor", fl.User)
	}
}

func TestAccountsSudoersNOPASSWD(t *testing.T) {
	f := accountsBaseRoot(t)
	f.write("/etc/sudoers", "Defaults env_reset\nroot ALL=(ALL:ALL) ALL\nubuntu ALL=(ALL) NOPASSWD:ALL\ndeploy ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart app\n")
	rep := f.scan()
	countRule(t, rep, "account-sudoers-nopasswd", 2)
	for _, fl := range findingsByRule(rep)["account-sudoers-nopasswd"] {
		if fl.User == "ubuntu" {
			// Cloud-default accounts get INFO; ordinary grants MEDIUM.
			if fl.Severity != finding.Info {
				t.Errorf("default admin NOPASSWD should be INFO, got %s", fl.Severity)
			}
		}
	}
}

func TestAccountsSudoersWritablePath(t *testing.T) {
	f := accountsBaseRoot(t)
	f.write("/etc/sudoers", "deploy ALL=(ALL) NOPASSWD: /tmp/fixer\n")
	rep := f.scan()
	countRule(t, rep, "account-sudoers-writable-path", 1)
	fl := findingsByRule(rep)["account-sudoers-writable-path"][0]
	if fl.Severity != finding.High {
		t.Errorf("sudoers granting a /tmp binary must be HIGH, got %s", fl.Severity)
	}
}

func TestAccountsSudoersWorldWritableFile(t *testing.T) {
	f := accountsBaseRoot(t)
	f.writeFileMode("/etc/sudoers.d/helper", "helper ALL=(ALL) NOPASSWD:ALL\n", 0o666)
	rep := f.scan()
	countRule(t, rep, "account-sudoers-writable-path", 1)
}

func TestAccountsAdminGroupContext(t *testing.T) {
	f := accountsBaseRoot(t)
	rep := f.scan()
	countRule(t, rep, "account-admin-group-member", 2) // sudo:ubuntu, wheel:root
	for _, fl := range findingsByRule(rep)["account-admin-group-member"] {
		if fl.Severity != finding.Info {
			t.Errorf("group membership without baseline is INFO context, got %s", fl.Severity)
		}
	}
}

func TestAccountsMalformedPasswdEntry(t *testing.T) {
	f := accountsBaseRoot(t)
	f.write("/etc/passwd", basePasswd+"broken:x:0:0:missing fields\n")
	rep := f.scan()
	countRule(t, rep, "account-passwd-malformed", 1)
	fl := findingsByRule(rep)["account-passwd-malformed"][0]
	if fl.Severity != finding.Low {
		t.Errorf("malformed entry is LOW, got %s", fl.Severity)
	}
}

func TestAccountsUnusualShellHigh(t *testing.T) {
	f := accountsBaseRoot(t)
	f.write("/etc/passwd", basePasswd+"intruder:x:1002:1002:intruder:/home/intruder:/opt/tools/customsh\n")
	f.writeExecutable("/opt/tools/customsh", "script")
	rep := f.scan()
	countRule(t, rep, "account-unusual-shell", 1)
	fl := findingsByRule(rep)["account-unusual-shell"][0]
	if fl.Severity != finding.High {
		t.Errorf("login shell from a writable-location binary must be HIGH, got %s", fl.Severity)
	}
}

func TestAccountsUnusualShellContextOnly(t *testing.T) {
	f := accountsBaseRoot(t)
	f.write("/etc/passwd", basePasswd+"fisher:x:1002:1002:fisher:/home/fisher:/bin/tcsh\n")
	rep := f.scan()
	countRule(t, rep, "account-unusual-shell", 1)
	fl := findingsByRule(rep)["account-unusual-shell"][0]
	if fl.Severity != finding.Info {
		t.Errorf("non-standard but system-dir shell is INFO context, got %s", fl.Severity)
	}
}

func TestAccountsMissingHomeDirectory(t *testing.T) {
	f := accountsBaseRoot(t)
	// ubuntu's home directory was created by the base fixture; remove it
	// from this fixture's account instead by pointing to a fresh account
	// whose home was never written.
	f.write("/etc/passwd", basePasswd+"newbie:x:1003:1003:newbie:/home/newbie:/bin/bash\n")
	rep := f.scan()
	countRule(t, rep, "account-home-missing", 1)
	fl := findingsByRule(rep)["account-home-missing"][0]
	if fl.Severity != finding.Low {
		t.Errorf("missing home for a login-capable account is LOW, got %s", fl.Severity)
	}
	if fl.User != "newbie" {
		t.Errorf("user = %q, want newbie", fl.User)
	}
}

func TestAccountsMissingHomeNotFlaggedForServiceAccounts(t *testing.T) {
	f := accountsBaseRoot(t)
	f.write("/etc/passwd", basePasswd+"jobrunner:x:1004:1004:runner:/var/empty:/usr/sbin/nologin\n")
	rep := f.scan()
	for _, fl := range findingsByRule(rep)["account-home-missing"] {
		if fl.User == "jobrunner" {
			t.Fatalf("nologin account must not be flagged for a missing home")
		}
	}
}

func TestAccountsHomePermissions(t *testing.T) {
	f := accountsBaseRoot(t)
	f.chmodDir("/home/ubuntu", 0o777)
	rep := f.scan()
	countRule(t, rep, "account-home-permissions", 1)
}

func TestAccountsShadowNeverRead(t *testing.T) {
	f := accountsBaseRoot(t)
	f.write("/etc/shadow", "root:$6$NEVERREAD:19000:0:99999:7:::\n")
	rep := f.scan()
	for _, fl := range rep.Findings {
		if strings.Contains(fl.Evidence, "$6$") || strings.Contains(fl.Evidence, "NEVERREAD") {
			t.Fatalf("password hash materialized in a finding: %s", fl.Evidence)
		}
	}
	// The shadow database is not part of any inspected artifact set.
	for _, d := range rep.Denied {
		if strings.Contains(d, "/etc/shadow") {
			t.Fatalf("shadow should not even be attempted, got %v", rep.Denied)
		}
	}
}
