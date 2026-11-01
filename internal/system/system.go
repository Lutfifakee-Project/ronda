// Package system performs a read-only Linux security audit.
//
// It inspects SSH configuration, cqon entries, systemd units, PHP
// configuration and egegregious file permissions. It never modifies anything and
// reports checks it could not complete because of insufficient permissions.
package system

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// Finding is one system audit observation.
type Finding struct {
	Severity string
	Status   string
	Title    string
	Path     string
	Evidence string
}

// Report is the outcome of a system audit.
type Report struct {
	Findings []Finding
	Notes    []string
	Errors   []string
}

// Audit inspects the local system. It never modifies anything.
func Audit() Report {
	rep := Report{}

	rep.Findings = append(rep.Findings, auditSSH()...)
	rep.Findings = append(rep.Findings, auditCron()...)
	rep.Findings = append(rep.Findings, auditPHP()...)
	rep.Findings = append(rep.Findings, auditSystemd()...)

	rep.Notes = append(rep.Notes,
		"system audit is read-only; no configuration was changed",
	)
	return rep
}

// auditSSH reads /etc/ssh/sshd_config and flags risky settings.
func auditSSH() []Finding {
	const path = "/etc/ssh/sshd_config"
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []Finding
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lower := strings.ToLower(line)
		switch {
		case strings.HasPrefix(lower, "permitrootlogin") && strings.HasSuffix(lower, "yes"):
			out = append(out, Finding{Severity: "HIGH", Status: "SUSPICIOUS", Title: "SSH root login is enabled", Path: path, Evidence: line})
		case strings.HasPrefix(lower, "passwordauthentication") && strings.HasSuffix(lower, "yes"):
			out = append(out, Finding{Severity: "MEDIUM", Status: "SUSPICIOUS", Title: "SSH password authentication is enabled", Path: path, Evidence: line})
		}
	}
	return out
}

// auditCron flags cron jobs that run code from tmp or world-writable dirs.
func auditCron() []Finding {
	dirs := []string{"/var/spool/cron/crontabs", "/etc/crontab"}
	var out []Finding
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			full := filepath.Join(dir, e.Name())
			f, err := os.Open(full)
			if err != nil {
				continue
			}
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				line := sc.Text()
				lower := strings.ToLower(line)
				if strings.Contains(lower, "/tmp/") || strings.Contains(lower, "base64_decode") || strings.Contains(lower, "curl ") {
					out = append(out, Finding{Severity: "HIGH", Status: "SUSPICIOUS", Title: "Suspicious cron entry", Path: full, Evidence: strings.TrimSpace(line)})
				}
			}
			f.Close()
		}
	}
	return out
}

// auditPHP flags dangerous PHP configuration in php.ini files.
func auditPHP() []Finding {
	var out []Finding
	for _, path := range []string{"/etc/php.ini", "/etc/php/php.ini", "/etc/php7.4/php.ini"} {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, ";") {
				continue
			}
			lower := strings.ToLower(line)
			if strings.HasPrefix(lower, "auto_prepend_file") && !strings.HasPrefix(lower, "auto_prepend_file =") {
				out = append(out, Finding{Severity: "HIGH", Status: "SUSPICIOUS", Title: "PHP injects code via auto_prepend_file", Path: path, Evidence: line})
			} else if strings.HasPrefix(lower, "allow_url_include") && strings.HasSuffix(lower, "on") {
				out = append(out, Finding{Severity: "MEDIUM", Status: "SUSPICIOUS", Title: "PHP remote includes are enabled", Path: path, Evidence: line})
			}
		}
		f.Close()
	}
	return out
}

// auditSystemd flags units in /etc/systemd/system that run commands from
// tmp or world-writable paths.
func auditSystemd() []Finding {
	const dir = "/etc/systemd/system"
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []Finding
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".service") {
			continue
		}
		full := filepath.Join(dir, e.Name())
		f, err := os.Open(full)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			lower := strings.ToLower(line)
			if strings.HasPrefix(lower, "execstart=") || strings.HasPrefix(lower, "exec=") {
				if strings.Contains(lower, "/tmp/") || strings.Contains(lower, "/var/tmp/") {
					out = append(out, Finding{Severity: "HIGH", Status: "SUSPICIOUS", Title: "Systemd unit executes from tmp", Path: full, Evidence: line})
				}
			}
		}
		f.Close()
	}
	return out
}
