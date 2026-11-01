package persistence

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/Lutfifakee-Project/ronda/internal/finding"
)

// pamStackDirs lists the per-service PAM stack locations.
var pamStackDirs = []string{"/etc/pam.d"}

const pamConfFile = "/etc/pam.conf"

// pamStandardDirs are the directories distribution PAM modules live in.
// Module paths outside them need provenance to be trusted.
var pamStandardDirs = []string{
	"/lib/security/", "/lib64/security/",
	"/usr/lib/security/", "/usr/lib64/security/",
	"/lib/x86_64-linux-gnu/security/", "/usr/lib/x86_64-linux-gnu/security/",
	"/usr/lib/aarch64-linux-gnu/security/",
	"/lib/musl/x86_64/security/",
}

// pamSensitiveServices are stacks where an always-succeed module in the
// auth or password chain is a real bypass.
var pamSensitiveServices = []string{
	"sshd", "su", "sudo", "sudo-i", "login", "passwd", "polkit-1",
	"system-auth", "common-auth", "common-password", "auth", "remote",
	"sshd-password", "gdm-password", "lightdm", "kde", "xscreensaver",
	"cockpit", "dovecot", "smtp", "vsftpd", "proftpd", "cron", "crond",
	"atd", "runuser-l", "chsh", "chpasswd",
}

// pamAlwaysSucceed are modules whose purpose is to allow everything.
var pamAlwaysSucceed = []string{"pam_permit.so", "pam_allow.so"}

// analyzePAM audits PAM stacks: module locations, missing modules, writable
// module paths and bypass indicators. No authentication is attempted and no
// distribution stack layout is assumed beyond module directories.
func (e *Engine) analyzePAM() {
	e.scanPamDir("/etc/pam.d")
	e.analyzePamConf()
}

// scanPamDir reads all per-service stacks.
func (e *Engine) scanPamDir(dir string) {
	entries, err := os.ReadDir(e.fs.Physical(dir))
	if err != nil {
		if !os.IsNotExist(err) {
			e.deny(dir, err.Error())
		}
		return
	}
	if len(entries) > maxDirEntries {
		entries = entries[:maxDirEntries]
	}
	for _, entry := range entries {
		if e.canceled() {
			return
		}
		if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		e.analyzePamStack(filepath.Join(dir, entry.Name()), entry.Name())
	}
}

// analyzePamConf parses the legacy single-file pam.conf layout.
func (e *Engine) analyzePamConf() {
	lines, present, _ := e.artifactLines(pamConfFile)
	if !present {
		return
	}
	for i, raw := range lines {
		if e.canceled() {
			return
		}
		line := strings.TrimSpace(stripComment(raw))
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		// pam.conf: service type control module-path [args...]
		e.analyzePamModule(pamConfFile, i+1, fields[0], fields[1], fields[2], strings.Join(fields[3:], " "), 0)
	}
}

// analyzePamStack parses one /etc/pam.d/<service> file.
func (e *Engine) analyzePamStack(logical, service string) {
	lines, present, _ := e.artifactLines(logical)
	if !present {
		return
	}
	// denyGuard maps a stack type to the first pam_deny.so line: a
	// pam_permit line after it is dead code (standard Debian idiom).
	denyGuard := make(map[string]int)
	for i, raw := range lines {
		if e.canceled() {
			return
		}
		line := strings.TrimSpace(stripComment(raw))
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		mtype := fields[0]
		control := fields[1]
		module := fields[2]
		args := strings.Join(fields[3:], " ")
		if baseNamePam(module) == "pam_deny.so" {
			if _, seen := denyGuard[mtype]; !seen {
				denyGuard[mtype] = i + 1
			}
		}
		if strings.HasPrefix(mtype, "-") {
			mtype = strings.TrimPrefix(mtype, "-")
		}
		if strings.HasPrefix(module, "-") {
			// "-/path" marks the module optional (absence tolerated).
			module = strings.TrimPrefix(module, "-")
		}
		e.analyzePamModule(logical, i+1, service, mtype, module, args+" "+control, denyGuard[mtype])
	}
}

// analyzePamModule checks one PAM stack line.
func (e *Engine) analyzePamModule(artifact string, line int, service, mtype, module, args string, denyLine int) {
	modulePath := module
	if !strings.HasPrefix(modulePath, "/") {
		// Bare module names resolve against the default module directory;
		// they cannot be inspected as paths.
		modulePath = ""
	}
	if modulePath != "" {
		ti := e.InspectTarget(modulePath)
		e.reference(modulePath, "pam", artifact, line, "pam-external-module-path", false)

		loc := e.classifyLocation(modulePath)
		if loc == "temp" || loc == "writabledir" {
			f := e.baseFinding("pam-writable-module", finding.High, artifact)
			f.Line = line
			f.Evidence = "PAM module for " + service + " resides in " + locationLabel(loc) + ": " + modulePath
			f.Target = modulePath
			f.Trust = ti.Trust
			e.add(f)
		} else if ti.WorldWrit {
			// The module file itself is writable beyond its owner.
			f := e.baseFinding("pam-writable-module", finding.High, artifact)
			f.Line = line
			f.Evidence = "PAM module for " + service + " is writable beyond its owner (" + ti.Mode + "): " + modulePath
			f.Target = modulePath
			f.Trust = ti.Trust
			e.add(f)
		} else if !ti.Exists && ti.Accessible && !strings.HasPrefix(module, "-") {
			f := e.baseFinding("pam-missing-module", finding.Low, artifact)
			f.Line = line
			f.Evidence = "PAM module does not exist: " + modulePath + " (service " + service + ")"
			f.Target = modulePath
			e.add(f)
		} else if ti.Exists && !inPamStandardDirs(modulePath) && ti.Trust != TrustPackageOwned {
			f := e.baseFinding("pam-external-module-path", finding.Medium, artifact)
			f.Line = line
			f.Evidence = "PAM module outside standard module directories: " + modulePath + describeTarget(ti)
			f.Target = modulePath
			f.Trust = ti.Trust
			e.add(f)
		}
	}

	// pam_exec: the helper script location decides severity.
	base := baseNamePam(module)
	if base == "pam_exec.so" {
		helper := firstPamArgPath(args)
		if helper != "" {
			logical := helper
			if !strings.HasPrefix(logical, "/") {
				logical = ""
			}
			if logical != "" {
				ti := e.InspectTarget(logical)
				e.reference(logical, "pam", artifact, line, "pam-exec-suspicious", false)
				loc := e.classifyLocation(logical)
				if loc == "temp" || loc == "writabledir" || loc == "hidden" {
					f := e.baseFinding("pam-exec-suspicious", finding.High, artifact)
					f.Line = line
					f.Evidence = "pam_exec helper for " + service + " in " + locationLabel(loc) + ": " + logical
					f.Target = logical
					f.Trust = ti.Trust
					e.add(f)
				}
			}
		}
	}

	// Always-succeed modules in sensitive auth/password chains. The
	// dead-code idiom (a pam_deny requisite earlier in the same stack
	// type) is excluded: the permit line can never run there.
	if isPamAlwaysSucceed(base) && isPamSensitive(service) && !(denyLine > 0 && denyLine < line) {
		lower := strings.ToLower(mtype + " " + args)
		if strings.Contains(lower, "auth") || strings.EqualFold(mtype, "auth") || strings.EqualFold(mtype, "password") {
			f := e.baseFinding("pam-bypass-indicator", finding.Medium, artifact)
			f.Line = line
			f.Evidence = base + " participates in the " + mtype + " stack of " + service + " (" + strings.TrimSpace(strings.Join(strings.Fields(args), " ")) + ")"
			e.add(f)
		}
	}
}

// inPamStandardDirs reports whether a module path is under a standard
// module directory.
func inPamStandardDirs(path string) bool {
	for _, pre := range pamStandardDirs {
		if strings.HasPrefix(path, pre) {
			return true
		}
	}
	return false
}

// baseNamePam strips directories from a module reference.
func baseNamePam(m string) string {
	if i := strings.LastIndexAny(m, "/"); i >= 0 {
		return m[i+1:]
	}
	return m
}

// firstPamArgPath finds the first absolute path argument of a PAM module
// line (used for pam_exec helpers).
func firstPamArgPath(args string) string {
	fields := strings.Fields(args)
	for _, f := range fields {
		clean := strings.Trim(f, `"'=`)
		clean = strings.TrimPrefix(clean, "logfile=")
		clean = strings.TrimPrefix(clean, "command=")
		if strings.HasPrefix(clean, "/") {
			return clean
		}
	}
	return ""
}

// isPamAlwaysSucceed reports whether the module always succeeds.
func isPamAlwaysSucceed(base string) bool {
	for _, m := range pamAlwaysSucceed {
		if base == m {
			return true
		}
	}
	return false
}

// isPamSensitive reports whether the stack protects interactive or
// privileged access.
func isPamSensitive(service string) bool {
	lower := strings.ToLower(service)
	for _, s := range pamSensitiveServices {
		if lower == s {
			return true
		}
	}
	return false
}
