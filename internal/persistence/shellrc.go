package persistence

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/Lutfifakee-Project/ronda/internal/finding"
)

// shellSystemFiles are system-wide shell startup files.
var shellSystemFiles = []string{
	"/etc/profile",
	"/etc/bash.bashrc",
	"/etc/bashrc",
	"/etc/zshrc",
	"/etc/zshenv",
	"/etc/zprofile",
	"/etc/zlogin",
	"/etc/environment",
	"/etc/rc.local",
	"/etc/rc.common",
}

var shellSystemDirs = []string{"/etc/profile.d", "/etc/zsh"}

// shellUserFiles are per-account startup files read from the static passwd
// home directories.
var shellUserFiles = []string{
	"/.profile", "/.bash_profile", "/.bash_login", "/.bashrc",
	"/.bash_logout", "/.zprofile", "/.zshenv", "/.zshrc",
	"/.zlogin", "/.zlogout",
}

// rcScriptDirs hold SysV-style RC scripts (T1037.004).
var rcScriptDirs = []string{"/etc/init.d"}

// shellTraitRules is the rule mapping for shell startup commands.
var shellTraitRules = traitRules{
	Writable:     "shell-writable-exec",
	Hidden:       "shell-hidden-exec",
	DownloadExec: "shell-download-exec",
	EncodedExec:  "shell-encoded-command",
	Reverse:      "shell-reverse-shell",
}

// analyzeShellStartup inspects system-wide and per-user shell startup
// files. Aliases, prompt definitions and pure environment exports are not
// execution evidence.
func (e *Engine) analyzeShellStartup() {
	for _, path := range shellSystemFiles {
		e.analyzeShellRC(path, "", "config")
	}
	for _, dir := range shellSystemDirs {
		e.scanShellDir(dir, "")
	}
	for _, dir := range rcScriptDirs {
		e.scanShellDir(dir, "")
	}
	for _, u := range e.users {
		if e.canceled() {
			return
		}
		home := u.Home
		if !strings.HasPrefix(home, "/") || home == "/dev/null" || home == "/nonexistent" {
			continue
		}
		for _, f := range shellUserFiles {
			e.analyzeShellRC(filepath.Clean("/"+home+f), u.Name, "shell-rc")
		}
	}
}

// scanShellDir lists a directory of shell snippets or RC scripts.
func (e *Engine) scanShellDir(dir, user string) {
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
		e.analyzeShellRC(filepath.Join(dir, entry.Name()), user, "shell-rc")
	}
}

// analyzeShellRC scans one startup file line by line.
func (e *Engine) analyzeShellRC(logical, user, kind string) {
	lines, present, _ := e.artifactLines(logical)
	if !present {
		return
	}
	for i, raw := range lines {
		if e.canceled() {
			return
		}
		lineNo := i + 1
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// Definitions are not startup execution.
		lower := strings.ToLower(trimmed)
		if strings.HasPrefix(lower, "alias ") || strings.HasPrefix(lower, "ps1=") ||
			strings.HasPrefix(lower, "ps2=") || strings.HasPrefix(lower, "prompt ") ||
			strings.HasPrefix(lower, "prompt=") || strings.HasPrefix(lower, "rprompt=") {
			continue
		}
		line := stripComment(raw)
		if strings.TrimSpace(line) == "" {
			continue
		}

		// LD_PRELOAD and PATH exports: "export VAR=..." carries the same
		// semantics as a bare assignment.
		exportless := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "export "))
		if key, value := envKV(exportless); key != "" {
			switch strings.ToUpper(key) {
			case "LD_PRELOAD":
				for _, lib := range strings.FieldsFunc(value, func(r rune) bool { return r == ':' || r == ' ' }) {
					if lib == "" {
						continue
					}
					home := userHome(e, user)
					full := lib
					if strings.HasPrefix(full, "~/") || strings.HasPrefix(full, "$HOME/") {
						full = expandHome(full, home)
					}
					e.reportPreloadLib(logical, lineNo, full, "shell-ldpreload-export", user, kind, "shell")
				}
				continue
			case "PATH":
				e.checkShellPathAssignment(logical, lineNo, value, user)
				continue
			default:
				if !strings.Contains(line, "/") && !strings.Contains(line, "$(") {
					continue // plain environment values carry no execution
				}
			}
		}

		// source/. of external files.
		if target := sourceTarget(line); target != "" {
			if e.checkShellSource(logical, lineNo, target, user, kind) {
				continue // suspicious source already reported for this line
			}
		}

		traits := AnalyzeCommand(line)
		if len(traits.Paths) == 0 && !traits.Downloads && !traits.Encoded && !traits.ReverseShell {
			continue
		}
		// Startup files routinely reference $HOME tooling; only flag
		// inspectable execution paths.
		execTarget := traits.ExecPath
		home := userHome(e, user)
		e.reportCommandTraits(traits, shellTraitRules, logical, lineNo, user, home, execTarget, kind)
	}
}

// userHome resolves the home of a user name for expansion.
func userHome(e *Engine, user string) string {
	if user == "" {
		return ""
	}
	if u, ok := e.userByName(user); ok {
		return u.Home
	}
	return ""
}

// envKV parses a leading VAR=value assignment.
func envKV(line string) (string, string) {
	if idx := strings.Index(line, "="); idx > 0 {
		key := strings.TrimSpace(line[:idx])
		if isShellVarName(key) {
			return key, strings.TrimSpace(line[idx+1:])
		}
	}
	return "", ""
}

// isShellVarName reports whether s is a valid shell variable name.
func isShellVarName(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '_':
		case r >= '0' && r <= '9' && i > 0:
		case r == ' ' || r == '\t':
			return false
		default:
			return false
		}
	}
	return true
}

// checkShellPathAssignment reports PATH assignments that put a temporary or
// world-writable directory in the search path.
func (e *Engine) checkShellPathAssignment(logical string, line int, value, user string) {
	var suspicious []string
	for _, dir := range strings.FieldsFunc(value, func(r rune) bool { return r == ':' || r == ' ' }) {
		if dir == "" {
			continue
		}
		switch dir {
		case "$PATH", "${PATH}", "$path":
			continue
		}
		full := dir
		if strings.HasPrefix(full, "~/") || strings.HasPrefix(full, "$HOME/") {
			home := userHome(e, user)
			full = expandHome(full, home)
			if full == "" {
				continue
			}
		}
		if !strings.HasPrefix(full, "/") {
			continue
		}
		if isTempPath(full) {
			suspicious = append(suspicious, dir)
			continue
		}
		if ti := e.InspectTarget(full); ti.DirWorldWrit {
			suspicious = append(suspicious, dir)
		}
	}
	if len(suspicious) == 0 {
		return
	}
	f := e.baseFinding("shell-path-injection", finding.Medium, logical)
	f.Line = line
	f.Evidence = "startup PATH includes writable locations: " + strings.Join(suspicious, ", ")
	f.User = user
	e.add(f)
}

// sourceTarget extracts the file operand of a source/. builtin invocation,
// or "" when the line is not a source.
func sourceTarget(line string) string {
	fields := strings.Fields(line)
	for i, tok := range fields {
		lower := strings.ToLower(strings.Trim(tok, `"'`))
		isSource := false
		if lower == "source" || lower == "." {
			isSource = true
		}
		if !isSource {
			continue
		}
		if i+1 < len(fields) {
			next := strings.Trim(fields[i+1], `"'`)
			// `source <(cmd)` is process substitution; the command itself is
			// analyzed by the trait scanner.
			if strings.HasPrefix(next, "<(") || strings.HasPrefix(next, "$(") {
				return ""
			}
			return next
		}
	}
	return ""
}

// checkShellSource reports startup files sourcing other files from
// suspicious locations. It returns true when a finding was emitted, so the
// caller skips the generic trait scan for that line. Sourcing hidden home
// paths is deliberately not flagged by itself: user tooling legitimately
// sources from ~/.config and similar directories.
func (e *Engine) checkShellSource(logical string, line int, target, user, kind string) bool {
	full := target
	if strings.HasPrefix(full, "~/") || strings.HasPrefix(full, "$HOME/") {
		home := userHome(e, user)
		full = expandHome(full, home)
	}
	if full == "" || !strings.HasPrefix(full, "/") {
		return false
	}
	if strings.HasPrefix(full, "/etc/") || strings.HasPrefix(full, "/usr/") || strings.HasPrefix(full, "/lib") {
		return false // distribution configuration sourcing is normal
	}
	// Well-known user tooling (nvm, sdkman, cargo...) is excluded.
	for _, known := range knownToolDotDirs {
		if strings.Contains(full, known) {
			return false
		}
	}
	ti := e.InspectTarget(full)
	e.reference(ti.LogicalPath, "shell", logical, line, "shell-suspicious-source", false)
	loc := e.classifyLocation(full)
	if loc != "temp" && loc != "writabledir" {
		return false
	}
	f := e.baseFinding("shell-suspicious-source", finding.Medium, logical)
	f.Line = line
	f.Evidence = "startup file sources " + full + " (" + locationLabel(loc) + ")"
	f.Target = full
	f.Trust = ti.Trust
	f.User = user
	f.Kind = kind
	e.add(f)
	return true
}
