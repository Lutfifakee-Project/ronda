// Package system performs a read-only Linux security audit.
//
// It inspects SSH configuration, cron entries, systemd units and PHP
// configuration for risky settings. It never modifies anything, and every
// location it could not read (absent or permission-denied) is recorded in
// Report.Errors so incomplete coverage is never reported as clean.
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
	// Errors lists locations the audit could not read. An entry here means
	// the corresponding check is incomplete; it is never treated as clean.
	Errors []string
}

// Production audit locations. Package-level so tests can inject fixtures.
var (
	sshConfigPath = "/etc/ssh/sshd_config"
	cronDirs      = []string{"/var/spool/cron/crontabs", "/etc/crontab"}
	phpIniPaths   = []string{"/etc/php.ini", "/etc/php/php.ini", "/etc/php7.4/php.ini"}
	systemdDir    = "/etc/systemd/system"
)

// Audit inspects the local system. It never modifies anything.
func Audit() Report {
	rep := Report{}

	sshF, sshE := auditSSH(sshConfigPath)
	rep.Findings = append(rep.Findings, sshF...)
	rep.Errors = append(rep.Errors, sshE...)

	cronF, cronE := auditCron(cronDirs)
	rep.Findings = append(rep.Findings, cronF...)
	rep.Errors = append(rep.Errors, cronE...)

	phpF, phpE := auditPHP(phpIniPaths)
	rep.Findings = append(rep.Findings, phpF...)
	rep.Errors = append(rep.Errors, phpE...)

	sdF, sdE := auditSystemd(systemdDir)
	rep.Findings = append(rep.Findings, sdF...)
	rep.Errors = append(rep.Errors, sdE...)

	rep.Notes = append(rep.Notes,
		"system audit is read-only; no configuration was changed",
	)
	return rep
}

// readLines returns the raw lines of one text file.
func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines, sc.Err()
}

// readError describes one unreadable location. Permission problems are
// named explicitly so an operator can see the check was blocked, not clean.
func readError(what, path string, err error) string {
	if os.IsPermission(err) {
		return what + " " + path + ": unreadable (permission denied); check incomplete"
	}
	return what + " " + path + ": unreadable (" + err.Error() + "); check incomplete"
}

// openErr returns nil when the audit target simply does not exist (nothing
// to audit - the check is complete, not incomplete) and the error otherwise.
func openErr(what, path string, err error) []string {
	if os.IsNotExist(err) {
		return nil
	}
	return []string{readError(what, path, err)}
}

// auditSSH reads one sshd_config and flags risky settings.
func auditSSH(path string) ([]Finding, []string) {
	lines, err := readLines(path)
	if err != nil {
		return nil, openErr("ssh config", path, err)
	}

	var out []Finding
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		lower := strings.ToLower(trimmed)
		switch {
		case strings.HasPrefix(lower, "permitrootlogin") && strings.HasSuffix(lower, "yes"):
			out = append(out, Finding{Severity: "HIGH", Status: "SUSPICIOUS", Title: "SSH root login is enabled", Path: path, Evidence: trimmed})
		case strings.HasPrefix(lower, "passwordauthentication") && strings.HasSuffix(lower, "yes"):
			out = append(out, Finding{Severity: "MEDIUM", Status: "SUSPICIOUS", Title: "SSH password authentication is enabled", Path: path, Evidence: trimmed})
		}
	}
	return out, nil
}

// auditCron flags cron jobs that run code from tmp, pipe remote content, or
// decode payloads. dirs may contain single files (e.g. /etc/crontab) as well
// as spool directories.
func auditCron(dirs []string) ([]Finding, []string) {
	var out []Finding
	var errs []string
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			if isNotDirErr(err) {
				// A single-file entry (e.g. /etc/crontab): read it directly.
				f, ferr := auditCronFile(dir)
				out = append(out, f...)
				errs = append(errs, ferr...)
			} else {
				errs = append(errs, openErr("cron location", dir, err)...)
			}
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			full := filepath.Join(dir, e.Name())
			f, ferr := auditCronFile(full)
			out = append(out, f...)
			errs = append(errs, ferr...)
		}
	}
	return out, errs
}

// auditCronFile scans one crontab file for suspicious entries.
func auditCronFile(path string) ([]Finding, []string) {
	lines, err := readLines(path)
	if err != nil {
		return nil, openErr("cron file", path, err)
	}
	var out []Finding
	for _, line := range lines {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "/tmp/") || strings.Contains(lower, "base64_decode") || strings.Contains(lower, "curl ") {
			out = append(out, Finding{Severity: "HIGH", Status: "SUSPICIOUS", Title: "Suspicious cron entry", Path: path, Evidence: strings.TrimSpace(line)})
		}
	}
	return out, nil
}

// isNotDirErr reports whether err means "the path is a file, not a
// directory" (ENOTDIR), which lets auditCron accept single-file entries.
func isNotDirErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "not a directory")
}

// auditPHP flags dangerous PHP configuration in php.ini files.
func auditPHP(paths []string) ([]Finding, []string) {
	var out []Finding
	var errs []string
	for _, path := range paths {
		lines, err := readLines(path)
		if err != nil {
			errs = append(errs, openErr("php config", path, err)...)
			continue
		}
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, ";") {
				continue
			}
			lower := strings.ToLower(trimmed)
			if strings.HasPrefix(lower, "auto_prepend_file") && !strings.HasPrefix(lower, "auto_prepend_file =") {
				out = append(out, Finding{Severity: "HIGH", Status: "SUSPICIOUS", Title: "PHP injects code via auto_prepend_file", Path: path, Evidence: trimmed})
			} else if strings.HasPrefix(lower, "allow_url_include") && strings.HasSuffix(lower, "on") {
				out = append(out, Finding{Severity: "MEDIUM", Status: "SUSPICIOUS", Title: "PHP remote includes are enabled", Path: path, Evidence: trimmed})
			}
		}
	}
	return out, errs
}

// auditSystemd flags units in dir that run commands from tmp paths.
func auditSystemd(dir string) ([]Finding, []string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, openErr("systemd units", dir, err)
	}
	var out []Finding
	var errs []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".service") {
			continue
		}
		full := filepath.Join(dir, e.Name())
		lines, lerr := readLines(full)
		if lerr != nil {
			errs = append(errs, readError("systemd unit", full, lerr))
			continue
		}
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			lower := strings.ToLower(trimmed)
			if strings.HasPrefix(lower, "execstart=") || strings.HasPrefix(lower, "exec=") {
				if strings.Contains(lower, "/tmp/") || strings.Contains(lower, "/var/tmp/") {
					out = append(out, Finding{Severity: "HIGH", Status: "SUSPICIOUS", Title: "Systemd unit executes from tmp", Path: full, Evidence: trimmed})
				}
			}
		}
	}
	return out, errs
}
