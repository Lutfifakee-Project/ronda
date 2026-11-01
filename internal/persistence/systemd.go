package persistence

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Lutfifakee-Project/ronda/internal/finding"
)

// systemdSystemDirs lists the system-level unit directories from
// systemd.unit(5). Absent directories are simply skipped.
var systemdSystemDirs = []string{
	"/etc/systemd/system",
	"/etc/systemd/system.control",
	"/run/systemd/system",
	"/run/systemd/system.control",
	"/run/systemd/transient",
	"/run/systemd/generator",
	"/run/systemd/generator.early",
	"/run/systemd/generator.late",
	"/usr/local/lib/systemd/system",
	"/usr/lib/systemd/system",
	"/lib/systemd/system",
}

// systemdUserDirs lists the user-level unit directories that are not tied
// to a specific account home.
var systemdUserDirs = []string{
	"/etc/systemd/user",
	"/usr/local/lib/systemd/user",
	"/usr/lib/systemd/user",
	"/run/systemd/user",
	"/lib/systemd/user",
}

// systemdSuffixes are the unit file kinds this analyzer inspects.
var systemdSuffixes = []string{".service", ".timer"}

// unitSuspicion records that a unit's execution showed actionable traits;
// timers consult it to report what they activate.
type unitSuspicion struct {
	Rules []string
	Line  int
}

// unitState collects the parsed state of one unit (or drop-in set).
type unitState struct {
	path       string
	unitName   string
	affected   string // User= value
	envFiles   []string
	suspic     []string
	suspicLine int
}

// systemdTraitRules is the rule mapping for Exec* directives.
var systemdTraitRules = traitRules{
	Writable:     "systemd-exec-writable-path",
	Hidden:       "systemd-exec-hidden-path",
	DownloadExec: "systemd-download-exec",
	EncodedExec:  "systemd-obfuscated-exec",
	Reverse:      "systemd-reverse-shell",
	Missing:      "systemd-missing-target",
}

// analyzeSystemd inspects every visible systemd unit location: system and
// user directories, drop-ins, enablement symlinks and the account-home user
// units. Parse is static; systemctl is never invoked.
func (e *Engine) analyzeSystemd() {
	suspicions := make(map[string]unitSuspicion)
	timers := make([]string, 0, 64)

	for _, dir := range systemdSystemDirs {
		e.scanSystemdDir(dir, "", "system", suspicions, &timers)
	}
	for _, u := range e.users {
		if e.canceled() {
			return
		}
		for _, rel := range []string{"/.config/systemd/user", "/.local/share/systemd/user"} {
			e.scanSystemdDir(u.Home+rel, u.Name, "user", suspicions, &timers)
		}
	}
	for _, dir := range systemdUserDirs {
		e.scanSystemdDir(dir, "", "user", suspicions, &timers)
	}

	// Timers reporting on suspicious activated units.
	for _, timer := range timers {
		target := timerActivation(e, timer)
		if target == "" {
			continue
		}
		if s, ok := suspicions[target]; ok {
			f := finding.Finding{
				Status:     finding.Suspicious,
				Severity:   finding.High,
				Title:      ruleTitle("systemd-timer-suspicious"),
				Path:       timer,
				Rule:       "systemd-timer-suspicious",
				Evidence:   fmt.Sprintf("timer activates %s, which shows suspicious execution traits (%s)", target, strings.Join(s.Rules, ", ")),
				Confidence: finding.ConfidencePossible,
				Line:       s.Line,
			}
			if m, ok := RuleMetadata("systemd-timer-suspicious"); ok {
				f.Category = m.Category
				f.MITRE = m.MITRE
			}
			e.add(f)
		}
	}
}

// scanSystemdDir walks one unit directory: unit files, drop-in directories
// and enablement symlink directories.
func (e *Engine) scanSystemdDir(dir, user, scope string, suspicions map[string]unitSuspicion, timers *[]string) {
	entries, err := os.ReadDir(e.fs.Physical(dir))
	if err != nil {
		if err != nil && !os.IsNotExist(err) {
			e.deny(dir, err.Error())
		}
		return
	}
	if len(entries) > maxDirEntries {
		e.unverifiedScope(dir, fmt.Sprintf("directory exceeds %d entries; inspection bounded", maxDirEntries))
		entries = entries[:maxDirEntries]
	}
	for _, entry := range entries {
		if e.canceled() {
			return
		}
		name := entry.Name()
		full := filepath.Join(dir, name)
		if entry.IsDir() {
			switch {
			case strings.HasSuffix(name, ".d"):
				// Drop-ins: *.conf files override unit settings.
				e.scanDropins(full, user, scope, suspicions)
			case strings.HasSuffix(name, ".wants"), strings.HasSuffix(name, ".requires"):
				e.scanEnablementLinks(full, dir)
			}
			continue
		}
		if !hasAnySuffix(name, systemdSuffixes) {
			continue
		}
		if strings.HasSuffix(name, ".timer") {
			*timers = append(*timers, full)
		}
		e.analyzeUnitFile(full, name, user, suspicions)
	}
}

// scanDropins reads *.d/*.conf drop-in directories.
func (e *Engine) scanDropins(dir, user, scope string, suspicions map[string]unitSuspicion) {
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
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
			continue
		}
		full := filepath.Join(dir, entry.Name())
		e.analyzeUnitFile(full, entry.Name(), user, suspicions)
	}
}

// scanEnablementLinks inspects *.wants and *.requires enablement symlinks:
// dangling links are skipped, escapes and writable targets are reported.
func (e *Engine) scanEnablementLinks(dir, parentDir string) {
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
		full := filepath.Join(dir, entry.Name())
		phys := e.fs.Physical(full)
		link, err := os.Readlink(phys)
		if err != nil {
			continue // regular files in wants dirs are unusual but harmless
		}
		var resolved string
		if filepath.IsAbs(link) {
			resolved = e.fs.Physical(link)
		} else {
			resolved = filepath.Join(filepath.Dir(phys), link)
		}
		if !e.fs.contains(resolved) {
			f := e.baseFinding("systemd-symlink-escape", finding.Medium, full)
			f.Evidence = "enablement symlink resolves outside the scanned root: " + RedactSecrets(link)
			e.add(f)
			continue
		}
		logical := e.logicalOf(resolved)
		if isTempPath(logical) {
			f := e.baseFinding("systemd-symlink-escape", finding.Medium, full)
			f.Evidence = "enablement symlink points into a writable temporary location: " + RedactSecrets(link)
			f.Target = logical
			e.add(f)
			continue
		}
		// Record the enablement reference for correlation.
		e.reference(logical, "systemd", full, 0, "systemd-symlink-escape", isTempPath(logical))
	}
}

// logicalOf converts a contained physical path back to its logical form.
func (e *Engine) logicalOf(physical string) string {
	if e.fs.LiveHost() {
		return filepath.Clean(physical)
	}
	root := e.fs.Root()
	clean := filepath.Clean(physical)
	if strings.HasPrefix(clean, root+string(filepath.Separator)) {
		return strings.TrimPrefix(clean, root)
	}
	return clean
}

// analyzeUnitFile parses one unit or drop-in file for execution directives,
// environment settings and privilege context.
func (e *Engine) analyzeUnitFile(logical, name, user string, suspicions map[string]unitSuspicion) {
	lines, present, _ := e.artifactLines(logical)
	if !present {
		return
	}

	st := unitState{path: logical, unitName: name}
	section := ""
	for i := 0; i < len(lines); i++ {
		raw := lines[i]
		lineNo := i + 1
		// systemd continuation: trailing backslash joins the next line.
		value := raw
		for strings.HasSuffix(value, "\\") && i+1 < len(lines) {
			value = strings.TrimSuffix(value, "\\") + lines[i+1]
			i++
		}
		trimmed := strings.TrimSpace(value)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section = strings.TrimSuffix(strings.TrimPrefix(trimmed, "["), "]")
			continue
		}
		eq := strings.Index(trimmed, "=")
		if eq <= 0 {
			continue
		}
		key := strings.TrimSpace(trimmed[:eq])
		val := strings.TrimSpace(trimmed[eq+1:])
		if val == "" {
			continue
		}

		switch section {
		case "Service":
			switch {
			case strings.HasPrefix(key, "Exec") && isExecDirective(key):
				e.analyzeExec(&st, key, val, lineNo, user)
			case key == "Environment":
				e.analyzeEnvironment(st, val, lineNo)
			case key == "EnvironmentFile":
				e.analyzeEnvironmentFile(st, val, lineNo)
			case key == "User":
				st.affected = val
			}
		case "Timer":
			// Timer targets are resolved later via timerActivation.
		case "Unit":
			// Descriptions carry no execution semantics.
		}
	}

	if st.affected == "" && user != "" {
		st.affected = user
	}
	for _, rule := range st.suspic {
		s := suspicions[st.unitName]
		s.Rules = append(s.Rules, rule)
		if s.Line == 0 {
			s.Line = st.suspicLine
		}
		suspicions[st.unitName] = s
	}
}

// isExecDirective reports whether key is one of the Exec* directives that
// execute a program.
func isExecDirective(key string) bool {
	switch key {
	case "ExecStart", "ExecStartPre", "ExecStartPost", "ExecReload", "ExecStop", "ExecStopPost":
		return true
	}
	return false
}

// analyzeExec processes one Exec* directive value.
func (e *Engine) analyzeExec(st *unitState, key, val string, line int, user string) {
	raw := val

	home := ""
	affected := st.affected
	if affected == "" {
		affected = user
	}
	if affected != "" {
		if u, ok := e.userByName(affected); ok {
			home = u.Home
		}
	}

	traits := AnalyzeCommand(raw)
	// The inspectable target comes from the trait analysis: for `sh -c`
	// payloads it is the inner command's target (the wrapper shell is not
	// the payload), and PATH-resolved bare names are never guessed at.
	execTarget := traits.ExecPath
	_, _ = e.reportCommandTraits(traits, systemdTraitRules, st.path, line, affected, home, execTarget, "unit")
	for _, matched := range matchedRuleNames(traits, systemdTraitRules) {
		st.suspic = append(st.suspic, matched)
		if st.suspicLine == 0 {
			st.suspicLine = line
		}
	}
}

// matchedRuleNames lists the rule IDs whose conditions the traits satisfy,
// used to flag timer-activated units.
func matchedRuleNames(t CommandTraits, r traitRules) []string {
	var out []string
	if t.ReverseShell && r.Reverse != "" {
		out = append(out, r.Reverse)
	}
	if len(t.WritablePaths) > 0 && r.Writable != "" {
		out = append(out, r.Writable)
	}
	if len(t.WritablePaths) == 0 && len(t.HiddenPaths) > 0 && r.Hidden != "" {
		out = append(out, r.Hidden)
	}
	if t.Downloads && (t.PipeIntoExec || t.ChainedExec) && r.DownloadExec != "" {
		out = append(out, r.DownloadExec)
	}
	if t.Encoded && t.PipeIntoExec && r.EncodedExec != "" {
		out = append(out, r.EncodedExec)
	}
	return out
}

// analyzeEnvironment parses an Environment= line for LD_PRELOAD.
func (e *Engine) analyzeEnvironment(st unitState, val string, line int) {
	for _, pair := range splitEnvPairs(val) {
		eq := strings.Index(pair, "=")
		if eq <= 0 {
			continue
		}
		k := strings.TrimSpace(pair[:eq])
		if !strings.EqualFold(k, "LD_PRELOAD") {
			continue
		}
		for _, lib := range strings.FieldsFunc(pair[eq+1:], func(r rune) bool { return r == ':' || r == ' ' }) {
			if lib == "" {
				continue
			}
			e.reportPreloadLib(st.path, line, lib, "systemd-ldpreload-env", st.affected, "unit", "systemd")
		}
	}
}

// analyzeEnvironmentFile checks EnvironmentFile= locations and reads them
// for LD_PRELOAD when accessible.
func (e *Engine) analyzeEnvironmentFile(st unitState, val string, line int) {
	path := strings.TrimPrefix(val, "-") // leading '-' marks the file optional
	if path == "" {
		return
	}
	suspiciousLoc := isTempPath(path)
	ti := e.InspectTarget(path)
	e.reference(ti.LogicalPath, "systemd", st.path, line, "systemd-envfile-suspicious", suspiciousLoc)
	if suspiciousLoc {
		f := e.baseFinding("systemd-envfile-suspicious", finding.Medium, st.path)
		f.Line = line
		f.Evidence = "EnvironmentFile points into a temporary or writable-by-design location: " + RedactSecrets(path)
		f.Target = path
		f.Trust = ti.Trust
		e.add(f)
		return
	}
	// Read the env file for LD_PRELOAD assignments (bounded).
	if data, ok := readTextFile(e.fs.Physical(path)); ok {
		for i, ln := range strings.Split(data, "\n") {
			ln = strings.TrimSpace(ln)
			if ln == "" || strings.HasPrefix(ln, "#") {
				continue
			}
			e.analyzeEnvironment(st, ln, line+i+1)
		}
	}
}

// splitEnvPairs splits an Environment= value on unquoted whitespace.
func splitEnvPairs(val string) []string {
	var out []string
	var cur strings.Builder
	var quote byte
	for i := 0; i < len(val); i++ {
		c := val[i]
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			cur.WriteByte(c)
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
			cur.WriteByte(c)
		case ' ', '\t':
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteByte(c)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// reportPreloadLib inspects an LD_PRELOAD library reference: INFO as
// context, HIGH when the library lives in a writable, hidden or home
// location. The referenced library is never loaded.
func (e *Engine) reportPreloadLib(artifact string, line int, lib string, rule string, affected string, kind string, mechanism string) {
	logical := lib
	if !strings.HasPrefix(logical, "/") {
		return // relative LD_PRELOAD values resolve via loader search; recorded below
	}
	ti := e.InspectTarget(logical)
	e.reference(logical, mechanism, artifact, line, rule, false)
	sev := finding.Info
	loc := e.classifyLocation(logical)
	if loc == "temp" || loc == "writabledir" {
		sev = finding.High
	} else if loc == "hidden" || loc == "home" {
		sev = finding.Medium
	}
	f := e.baseFinding(rule, sev, artifact)
	f.Line = line
	f.Kind = kind
	f.User = affected
	f.Target = logical
	f.Trust = ti.Trust
	f.Evidence = fmt.Sprintf("LD_PRELOAD references %s (%s)", logical, preloadEvidence(loc, ti))
	e.add(f)
}

// preloadEvidence describes the referenced library state honestly.
func preloadEvidence(loc string, ti *TargetInfo) string {
	switch {
	case !ti.Exists:
		return "missing"
	case !ti.Accessible:
		return "inaccessible: " + ti.Err
	case loc == "temp":
		return "writable-by-design location"
	case loc == "writabledir":
		return "directory writable by unprivileged users"
	case loc == "hidden":
		return "hidden path"
	case loc == "home":
		return "user home path"
	case ti.Kind == "elf" && ti.ELFArch != "":
		return "ELF " + ti.ELFArch
	default:
		return "present"
	}
}

// timerActivation resolves the unit a timer activates: explicit Unit= or
// the default <timer-name>.service.
func timerActivation(e *Engine, timer string) string {
	lines, present, _ := e.artifactLines(timer)
	if !present {
		return ""
	}
	inTimer := false
	for _, raw := range lines {
		trimmed := strings.TrimSpace(raw)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			inTimer = strings.TrimSuffix(strings.TrimPrefix(trimmed, "["), "]") == "Timer"
			continue
		}
		if !inTimer {
			continue
		}
		if strings.HasPrefix(trimmed, "Unit=") {
			return strings.TrimSpace(strings.TrimPrefix(trimmed, "Unit="))
		}
	}
	base := filepath.Base(timer)
	if strings.HasSuffix(base, ".timer") {
		return strings.TrimSuffix(base, ".timer") + ".service"
	}
	return ""
}

// baseFinding builds a finding with registry metadata and artifact
// ownership attached.
func (e *Engine) baseFinding(rule string, sev finding.Severity, artifact string) finding.Finding {
	f := finding.Finding{
		Status:     finding.Suspicious,
		Severity:   sev,
		Title:      ruleTitle(rule),
		Path:       artifact,
		Rule:       rule,
		Confidence: finding.ConfidencePossible,
	}
	if m, ok := RuleMetadata(rule); ok {
		f.Category = m.Category
		f.MITRE = m.MITRE
	}
	owner, group, perms, modified := e.artifactStat(artifact)
	f.Owner = owner
	if group != "" {
		f.Owner = owner + ":" + group
	}
	f.Permissions = perms
	f.Modified = modified
	return f
}

// hasAnySuffix reports whether s ends with any of the suffixes.
func hasAnySuffix(s string, suffixes []string) bool {
	for _, suf := range suffixes {
		if strings.HasSuffix(s, suf) {
			return true
		}
	}
	return false
}
