package persistence

import (
	"strings"
	"testing"

	"github.com/Lutfifakee-Project/ronda/internal/finding"
)

func TestProvenanceDPKGOwnership(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/etc/os-release", "NAME=\"Ubuntu\"\nID=ubuntu\n")
	f.write("/usr/sbin/owned-agent", elfBytes(62))
	f.write("/var/lib/dpkg/info/owned-agent.list", "/usr/sbin/owned-agent\n/etc/owned-agent.conf\n")
	f.write("/etc/cron.d/owned", "0 * * * * root /usr/sbin/owned-agent --run\n")
	f.write("/etc/systemd/system/owned.service", "[Service]\nExecStart=/usr/sbin/owned-agent\n")
	rep := f.scan()
	if rep.PackageDB != "dpkg" {
		t.Fatalf("packageDB = %q, want dpkg", rep.PackageDB)
	}
	if rep.Distribution != "Ubuntu" {
		t.Errorf("distribution = %q", rep.Distribution)
	}
	// Package-owned target referenced by two mechanisms without suspicious
	// traits stays quiet: distribution tooling is not a backdoor finding.
	countRule(t, rep, "correlation-shared-payload", 0)
	countRule(t, rep, "target-unowned-executable", 0)
}

func TestProvenanceUnownedExecutableContext(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/etc/os-release", "NAME=\"Debian\"\n")
	f.write("/usr/local/bin/localtool", elfBytes(62))
	f.write("/var/lib/dpkg/info/libc6.list", "/usr/lib/x86_64-linux-gnu/libc.so.6\n")
	f.write("/etc/cron.d/local", "0 * * * * root /usr/local/bin/localtool\n")
	rep := f.scan()
	// With a dpkg database consulted, the unclaimed executable is recorded
	// as unowned context (INFO), not as an unverified unknown.
	countRule(t, rep, "target-unowned-executable", 1)
	fl := findingsByRule(rep)["target-unowned-executable"][0]
	if fl.Severity.Rank() != finding.Info.Rank() {
		t.Errorf("unowned locally-deployed tools are INFO context, got %s", fl.Severity)
	}
}

func TestProvenanceAPKOwnership(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/etc/os-release", "NAME=\"Alpine Linux\"\nID=alpine\n")
	f.write("/usr/sbin/apk-agent", elfBytes(62))
	f.write("/lib/apk/db/installed", "P:apk-agent\nV:1.0\nF:usr\nR:sbin\nR:sbin/apk-agent\n\nP:other\nV:1.0\nF:etc\nR:motd\n")
	f.write("/etc/cron.d/apk", "0 * * * * root /usr/sbin/apk-agent --run\n")
	f.write("/etc/systemd/system/apk.service", "[Service]\nExecStart=/usr/sbin/apk-agent\n")
	rep := f.scan()
	if rep.PackageDB != "apk" {
		t.Fatalf("packageDB = %q, want apk", rep.PackageDB)
	}
	countRule(t, rep, "correlation-shared-payload", 0)
	countRule(t, rep, "target-unowned-executable", 0)
}

func TestProvenanceRPMUnverifiedHonest(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/etc/os-release", "NAME=\"Rocky Linux\"\n")
	f.mkdirs("/var/lib/rpm")
	f.write("/usr/sbin/rpm-agent", elfBytes(62))
	f.write("/etc/cron.d/rpm", "0 * * * * root /usr/sbin/rpm-agent\n")
	rep := f.scan()
	if rep.PackageDB != "rpm" {
		t.Fatalf("packageDB = %q, want rpm", rep.PackageDB)
	}
	// RPM BerkeleyDB cannot be parsed without the rpm tooling: every target
	// stays unverified and the limitation is recorded, never hidden.
	for _, fl := range rep.Findings {
		if fl.Trust == "package-owned" {
			t.Fatalf("rpm provenance must not fabricate ownership: %s", fl.Evidence)
		}
	}
	found := false
	for _, n := range rep.Notes {
		if strings.Contains(strings.ToLower(n), "rpm") {
			found = true
		}
	}
	if !found {
		t.Fatalf("rpm limitation must be disclosed in report notes, got %v", rep.Notes)
	}
}

func TestProvenanceNoDatabase(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/usr/local/bin/tool", elfBytes(62))
	f.write("/etc/cron.d/tool", "0 * * * * root /usr/local/bin/tool\n")
	rep := f.scan()
	if rep.PackageDB != "" {
		t.Fatalf("packageDB = %q, want empty", rep.PackageDB)
	}
	for _, fl := range rep.Findings {
		if fl.Trust == "package-owned" {
			t.Fatalf("no database present, yet a finding claims ownership: %s", fl.Evidence)
		}
	}
}

func TestProvenancePackageManagersNeverExecuted(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/usr/bin/dpkg", "elf")
	f.write("/usr/bin/rpm", "elf")
	f.write("/usr/bin/apk", "elf")
	f.write("/var/lib/dpkg/info/core.list", "/usr/bin/dpkg\n")
	rep := f.scan()
	// Static metadata only: the engine has no mechanism to spawn package
	// managers, and the scan must complete without invoking them.
	if rep.PackageDB != "dpkg" {
		t.Fatalf("packageDB = %q", rep.PackageDB)
	}
}
