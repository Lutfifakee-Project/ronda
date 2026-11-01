package persistence

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/Lutfifakee-Project/ronda/internal/finding"
)

// fakeKeyBlob builds a synthetic public-key blob: valid base64 over
// deterministic bytes, so only the parse/fingerprint path is exercised.
func fakeKeyBlob(n int) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xAB}, n))
}

var (
	fakeEd25519Blob = fakeKeyBlob(48)
	fakeRSABlob     = fakeKeyBlob(256)
)

func TestSSHStandardKeyNoFindings(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/home/ubuntu/.ssh/authorized_keys", "ssh-ed25519 "+fakeEd25519Blob+" operator@laptop\n")
	rep := f.scan()
	for _, fl := range rep.Findings {
		if fl.Severity.Rank() >= finding.Medium.Rank() {
			t.Fatalf("standard key produced %s finding: %s", fl.Severity, fl.Title)
		}
	}
	if len(rep.Findings) != 0 {
		t.Logf("context findings recorded: %d", len(rep.Findings))
	}
}

func TestSSHRestrictedKeyNoFindings(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.writeExecutable("/usr/bin/rrsync", "elf")
	f.write("/home/ubuntu/.ssh/authorized_keys",
		`command="/usr/bin/rrsync /srv/repo",restrict ssh-ed25519 `+fakeEd25519Blob+" deploy@ci\n")
	rep := f.scan()
	for _, fl := range rep.Findings {
		if fl.Rule == "ssh-forced-command" {
			t.Fatalf("standard restricted pattern reported: %s", fl.Evidence)
		}
	}
}

func TestSSHForcedCommandSuspiciousTarget(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.writeExecutable("/tmp/.x/agent", "script")
	f.write("/home/ubuntu/.ssh/authorized_keys",
		`command="/tmp/.x/agent --serve",restrict ssh-ed25519 `+fakeEd25519Blob+" ops@hub\n")
	rep := f.scan()
	countRule(t, rep, "ssh-forced-command", 1)
	fl := findingsByRule(rep)["ssh-forced-command"][0]
	if fl.Severity != finding.High {
		t.Errorf("writable-path forced command should be HIGH, got %s", fl.Severity)
	}
	if fl.Target != "/tmp/.x/agent" {
		t.Errorf("target = %q", fl.Target)
	}
	if fl.User != "ubuntu" {
		t.Errorf("user = %q, want ubuntu", fl.User)
	}
}

func TestSSHRootKeyContextOnly(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/root/.ssh/authorized_keys", "ssh-rsa "+fakeRSABlob+" admin@vault\n")
	rep := f.scan()
	countRule(t, rep, "ssh-root-authorized-key", 1)
	fl := findingsByRule(rep)["ssh-root-authorized-key"][0]
	if fl.Severity != finding.Info {
		t.Errorf("root key presence is context (INFO), got %s", fl.Severity)
	}
}

func TestSSHUnsafeKeyPermissions(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.writeFileMode("/home/ubuntu/.ssh/authorized_keys",
		"ssh-ed25519 "+fakeEd25519Blob+" a@b\n", 0o646)
	rep := f.scan()
	countRule(t, rep, "ssh-unsafe-key-permissions", 1)
}

func TestSSHUnsafeDotSSHDirectory(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/home/ubuntu/.ssh/authorized_keys", "ssh-ed25519 "+fakeEd25519Blob+" a@b\n")
	f.chmodDir("/home/ubuntu/.ssh", 0o777)
	rep := f.scan()
	countRule(t, rep, "ssh-unsafe-key-permissions", 1)
}

func TestSSHInvalidKeyFormat(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/home/ubuntu/.ssh/authorized_keys",
		"definitely-not-a-key\nssh-ed25519 not-base64!!\n")
	rep := f.scan()
	countRule(t, rep, "ssh-malformed-key", 2)
	for _, fl := range findingsByRule(rep)["ssh-malformed-key"] {
		if strings.Contains(fl.Evidence, "AAAAC3") {
			t.Errorf("malformed-line evidence leaked key material: %q", fl.Evidence)
		}
	}
}

func TestSSHMatchBlockContext(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/etc/ssh/sshd_config", `PermitRootLogin no

Match Group developers
    PermitRootLogin yes
`)
	rep := f.scan()
	countRule(t, rep, "ssh-config-permitroot", 1)
	fl := findingsByRule(rep)["ssh-config-permitroot"][0]
	if !strings.Contains(fl.Evidence, "Match Group developers") {
		t.Errorf("Match context missing from evidence: %q", fl.Evidence)
	}
}

func TestSSHAuthorizedKeysCommandSuspicious(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.writeExecutable("/tmp/ak-helper", "script")
	f.write("/etc/ssh/sshd_config", "AuthorizedKeysCommand /tmp/ak-helper %u\n")
	rep := f.scan()
	countRule(t, rep, "ssh-authorizedkeyscommand", 1)
	fl := findingsByRule(rep)["ssh-authorizedkeyscommand"][0]
	if fl.Severity != finding.High {
		t.Errorf("writable AuthorizedKeysCommand helper should be HIGH, got %s", fl.Severity)
	}
}

func TestSSHNoPrivateKeyDisclosure(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/home/ubuntu/.ssh/authorized_keys",
		"command=\"/opt/agent --password=secret123 serve\" ssh-ed25519 "+fakeEd25519Blob+" a@b\n")
	rep := f.scan()
	out := ""
	for _, fl := range rep.Findings {
		out += fl.Evidence + "\n"
	}
	if strings.Contains(out, "secret123") {
		t.Fatalf("credential leaked into ssh findings: %s", out)
	}
}

func TestSSHKeyMaterialNeverInEvidence(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.writeFileMode("/home/deploy/.ssh/authorized_keys",
		"ssh-ed25519 "+fakeEd25519Blob+" deploy@ci\n", 0o646)
	f.write("/etc/passwd", basePasswd+"deploy:x:1001:1001:Deploy:/home/deploy:/bin/bash\n")
	rep := f.scan()
	for _, fl := range rep.Findings {
		if strings.Contains(fl.Evidence, fakeEd25519Blob) {
			t.Errorf("key blob leaked via %s: %q", fl.Rule, fl.Evidence)
		}
	}
}
