package persistence

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Lutfifakee-Project/ronda/internal/finding"
)

// standardShells are login shells that never raise the unusual-shell rule.
var standardShells = []string{
	"/bin/sh", "/bin/bash", "/bin/dash", "/bin/zsh", "/bin/ksh", "/bin/ash",
	"/usr/bin/sh", "/usr/bin/bash", "/usr/bin/dash", "/usr/bin/zsh",
	"/usr/bin/ksh", "/usr/bin/fish", "/bin/fish",
	"/sbin/nologin", "/usr/sbin/nologin", "/bin/false", "/usr/bin/false",
	"/sbin/halt", "/sbin/shutdown", "/bin/sync", "/usr/sbin/nologin",
}

// adminGroups are groups that confer privilege; membership is recorded as
// context because no trusted baseline exists.
var adminGroups = []string{"wheel", "sudo", "admin", "adm", "root"}

// sudoersDefaults are cloud-default users whose NOPASSWD grants are by
// design (duplicates adminUsers; kept for readability of sudoers checks).

// analyzeAccounts inspects /etc/passwd, /etc/group and sudoers. Password
// hashes are never read: /etc/shadow is not opened.
func (e *Engine) analyzeAccounts() {
	e.analyzePasswd()
	e.analyzeGroups()
	e.analyzeSudoers()
}

// analyzePasswd checks UID-0 duplication, shells, malformed entries and
// home directory hygiene.
func (e *Engine) analyzePasswd() {
	lines, present, _ := e.artifactLines("/etc/passwd")
	if !present {
		e.unverifiedScope("/etc/passwd", "account database not readable")
		return
	}
	rootHome := ""
	uid0 := 0
	for i, raw := range lines {
		if e.canceled() {
			return
		}
		lineNo := i + 1
		line := strings.TrimSpace(stripComment(raw))
		if line == "" {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) != 7 {
			f := e.baseFinding("account-passwd-malformed", finding.Low, "/etc/passwd")
			f.Line = lineNo
			f.Evidence = fmt.Sprintf("entry has %d fields instead of 7: %s", len(fields), safeToken(fields[0]))
			e.add(f)
			continue
		}
		name := fields[0]
		uid := parseIntSafe(fields[2])
		home := fields[5]
		shell := fields[6]
		_ = uid

		if uid == 0 {
			uid0++
			if name != "root" {
				f := e.baseFinding("account-extra-uid0", finding.High, "/etc/passwd")
				f.Line = lineNo
				f.Evidence = "account " + name + " carries UID 0"
				f.User = name
				e.add(f)
			} else {
				rootHome = home
			}
		}

		// Unusual shells: only meaningful for accounts that can log in.
		if shell != "" && !shellInList(shell) {
			// /etc and /usr interpreters outside the standard list are
			// recorded as INFO context; everything else (tmp, homes,
			// writable paths) is HIGH.
			loc := e.classifyLocation(shell)
			if strings.HasPrefix(shell, "/etc/") || strings.HasPrefix(shell, "/usr/") || strings.HasPrefix(shell, "/bin/") || strings.HasPrefix(shell, "/sbin/") {
				f := e.baseFinding("account-unusual-shell", finding.Info, "/etc/passwd")
				f.Line = lineNo
				f.Evidence = "account " + name + " uses non-standard shell " + shell + " (recorded as context)"
				f.User = name
				e.add(f)
			} else {
				f := e.baseFinding("account-unusual-shell", finding.High, "/etc/passwd")
				f.Line = lineNo
				f.Evidence = "account " + name + " uses shell " + shell + " (" + locationLabel(loc) + ")"
				f.User = name
				if shell != "" && strings.HasPrefix(shell, "/") {
					ti := e.InspectTarget(shell)
					f.Target = ti.LogicalPath
					f.Trust = ti.Trust
				}
				e.add(f)
			}
		}

		// Home directory hygiene for real users with real homes.
		if strings.HasPrefix(home, "/home/") || (name == "root" && home == "/root") {
			ti := e.InspectTarget(home)
			if ti.Exists && ti.WorldWrit {
				f := e.baseFinding("account-home-permissions", finding.Low, home)
				f.Evidence = "home directory of " + name + " is writable beyond its owner (" + ti.Mode + ")"
				f.User = name
				f.Owner = ti.Owner
				f.Permissions = ti.Mode
				e.add(f)
			} else if !ti.Exists && ti.Accessible && loginCapableShell(shell) {
				f := e.baseFinding("account-home-missing", finding.Low, "/etc/passwd")
				f.Line = lineNo
				f.Evidence = "account " + name + " has a login shell but its home directory " + home + " does not exist"
				f.User = name
				e.add(f)
			}
		}
	}
	_ = rootHome
}

// shellInList reports whether the shell is a standard one.
func shellInList(shell string) bool {
	for _, s := range standardShells {
		if shell == s {
			return true
		}
	}
	return false
}

// loginCapableShell reports whether a passwd shell permits interactive
// login: accounts shelled to nologin/false never need a home directory.
func loginCapableShell(shell string) bool {
	switch baseNamePam(shell) {
	case "nologin", "false", "sync", "halt", "shutdown":
		return false
	}
	return true
}

// parseIntSafe parses a non-negative integer, 0 on failure.
func parseIntSafe(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
		if n > 1<<31-1 {
			return 0
		}
	}
	return n
}

// analyzeGroups records administrative group membership as INFO context.
func (e *Engine) analyzeGroups() {
	for _, g := range e.groups {
		if e.canceled() {
			return
		}
		isAdmin := false
		for _, a := range adminGroups {
			if g.Name == a {
				isAdmin = true
				break
			}
		}
		if !isAdmin || len(g.Members) == 0 {
			continue
		}
		f := e.baseFinding("account-admin-group-member", finding.Info, "/etc/group")
		f.Line = g.Line // distinct per group so dedup keeps every entry
		f.Evidence = fmt.Sprintf("group %s members: %s (no baseline exists to judge membership)", g.Name, strings.Join(g.Members, ", "))
		e.add(f)
	}
}

// sudoersFiles lists the sudoers sources. The file is parsed statically;
// sudo is never executed and no sudoers modification is attempted.
func (e *Engine) analyzeSudoers() {
	e.analyzeSudoersFile("/etc/sudoers")
	e.scanSudoersDir("/etc/sudoers.d")
}

// scanSudoersDir reads /etc/sudoers.d/*.
func (e *Engine) scanSudoersDir(dir string) {
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
		if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") || strings.HasSuffix(entry.Name(), "~") {
			continue
		}
		e.analyzeSudoersFile(filepath.Join(dir, entry.Name()))
	}
}

// analyzeSudoersFile parses one sudoers file.
func (e *Engine) analyzeSudoersFile(logical string) {
	lines, present, _ := e.artifactLines(logical)
	if !present {
		return
	}
	for i, raw := range lines {
		if e.canceled() {
			return
		}
		lineNo := i + 1
		line := strings.TrimSpace(stripComment(raw))
		if line == "" {
			continue
		}
		// Defaults entries and aliases are configuration, not grants.
		upper := strings.ToUpper(line)
		if strings.HasPrefix(upper, "DEFAULTS") || strings.HasPrefix(upper, "Cmnd_Alias") ||
			strings.HasPrefix(upper, "User_Alias") || strings.HasPrefix(upper, "Host_Alias") ||
			strings.HasPrefix(upper, "Runas_Alias") {
			continue
		}
		e.analyzeSudoersRule(logical, lineNo, line)
	}
}

// analyzeSudoersRule inspects one user specification:
// WHO HOST=(RUNAS) [NOPASSWD:] COMMANDS
func (e *Engine) analyzeSudoersRule(logical string, line int, lineText string) {
	fields := strings.Fields(lineText)
	if len(fields) < 3 {
		return
	}
	who := fields[0]
	rest := strings.Join(fields[1:], " ")

	nopasswd := strings.Contains(rest, "NOPASSWD")
	runasExclusion := strings.Contains(rest, "!root") && (strings.Contains(rest, "(") || strings.Contains(rest, "Runas"))

	// Command part: after the runas spec if present, else after host.
	commands := rest
	if idx := strings.Index(rest, ")"); idx >= 0 {
		commands = strings.TrimSpace(rest[idx+1:])
	}
	commands = strings.TrimSpace(strings.TrimSuffix(strings.TrimSuffix(commands, "NOPASSWD:"), "PASSWD:"))
	commands = strings.TrimPrefix(commands, "NOPASSWD:")
	commands = strings.TrimSpace(commands)
	for _, tok := range strings.Fields(commands) {
		clean := strings.Trim(tok, `"'`)
		if clean == "" || clean == "ALL" || strings.HasPrefix(clean, "ALL") {
			continue
		}
		// Tags like SETENV:, NOEXEC: precede commands.
		if strings.HasSuffix(clean, ":") && !strings.Contains(clean, "/") {
			continue
		}
		full := sudoersCommandPath(clean)
		if full == "" {
			continue
		}
		if isTempPath(full) {
			f := e.baseFinding("account-sudoers-writable-path", finding.High, logical)
			f.Line = line
			f.Evidence = "sudoers authorizes " + who + " to run " + full + " from a temporary location"
			f.Target = full
			f.User = who
			e.add(f)
			continue
		}
		if strings.HasPrefix(full, "/") {
			if ti := e.InspectTarget(full); ti.DirWorldWrit {
				f := e.baseFinding("account-sudoers-writable-path", finding.High, logical)
				f.Line = line
				f.Evidence = "sudoers authorizes " + who + " to run " + full + " (directory writable by unprivileged users)"
				f.Target = full
				f.Trust = ti.Trust
				f.User = who
				e.add(f)
			}
		}
	}

	if nopasswd && who != "" && who != "root" && who != "%sudo" && who != "%wheel" && who != "%admin" {
		// sudoers file ownership check: writable beyond root escalates.
		owner := ""
		if ti := e.InspectTarget(logical); ti.Exists {
			owner = ti.Owner
			if ti.WorldWrit || ti.GroupWrit {
				f := e.baseFinding("account-sudoers-writable-path", finding.High, logical)
				f.Line = line
				f.Evidence = "sudoers file is writable beyond root (" + ti.Mode + ", owner " + ti.Owner + ") while granting NOPASSWD to " + who
				f.User = who
				f.Owner = ti.Owner
				f.Permissions = ti.Mode
				e.add(f)
				return
			}
		}
		sev := finding.Medium
		if isDefaultAdminUser(who) || strings.HasPrefix(who, "%") {
			sev = finding.Info
		}
		f := e.baseFinding("account-sudoers-nopasswd", sev, logical)
		f.Line = line
		f.Evidence = "sudoers grants NOPASSWD to " + who + " (" + strings.Join(fields[1:], " ") + ")"
		if owner != "" {
			f.Evidence += "; file owner " + owner
		}
		f.User = who
		e.add(f)
	}

	if runasExclusion {
		f := e.baseFinding("account-sudoers-runas-exclusion", finding.Medium, logical)
		f.Line = line
		f.Evidence = "Runas list excludes root explicitly (" + RedactSecrets(lineText) + ")"
		f.User = who
		e.add(f)
	}
}

// sudoersCommandPath extracts an inspectable path from a sudoers command
// token, handling directory prefixes ("DIR/") and wildcards.
func sudoersCommandPath(tok string) string {
	clean := strings.Trim(tok, `"'`)
	clean = strings.TrimPrefix(clean, "sudoedit ")
	clean = strings.TrimSpace(clean)
	if !strings.HasPrefix(clean, "/") {
		return ""
	}
	// Trailing wildcards are stripped for inspection purposes.
	clean = strings.TrimSuffix(clean, "*")
	clean = strings.TrimSuffix(clean, "/")
	return clean
}

// isDefaultAdminUser reports known cloud/distribution default accounts.
func isDefaultAdminUser(name string) bool {
	for _, u := range adminUsers {
		if u == name {
			return true
		}
	}
	return false
}
