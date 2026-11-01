package persistence

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Lutfifakee-Project/ronda/internal/finding"
)

// cronTraitRules is the rule mapping for scheduled commands (cron, at and
// run-parts scripts share the SCHEDULED_TASK_PERSISTENCE category).
var cronTraitRules = traitRules{
	Writable:     "cron-exec-writable-path",
	Hidden:       "cron-hidden-target",
	DownloadExec: "cron-download-exec",
	EncodedExec:  "cron-obfuscated-command",
	Reverse:      "cron-reverse-shell",
	Missing:      "cron-missing-target",
}

// cronLocations lists the scheduled-task locations. Booleans mark whether
// lines carry the user field (system crontab format).
type cronLocation struct {
	Path      string
	UserField bool
	SpoolUser bool // file name is the owning account
}

var cronLocations = []cronLocation{
	{"/etc/crontab", true, false},
	{"/etc/anacrontab", false, false},
}

var cronAtSpools = []string{
	"/var/spool/cron/crontabs", // Debian/Ubuntu user crontabs
	"/var/spool/cron",          // RHEL-family user crontabs
	"/var/spool/at",            // at spool (RHEL-family)
	"/var/spool/cron/atjobs",   // at spool (Debian/Ubuntu)
}

var cronRunParts = []string{
	"/etc/cron.hourly",
	"/etc/cron.daily",
	"/etc/cron.weekly",
	"/etc/cron.monthly",
}

// cronFieldRe matches a single cron schedule field (numbers, ranges, steps,
// lists, names and asterisks).
var cronFieldRe = regexp.MustCompile(`^[\*@0-9a-zA-Z\/,\-]+$`)

// envAssignRe matches a crontab environment assignment.
var envAssignRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*\s*=`)

// userNameRe matches an account-name-shaped token.
var userNameRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// analyzeCron inspects system crontabs, user spool crontabs, at jobs and
// run-parts directories. crontab(1) is never invoked.
func (e *Engine) analyzeCron() {
	for _, loc := range cronLocations {
		e.analyzeCrontabFile(loc.Path, "", loc.UserField, false)
	}
	// /etc/cron.d fragments use the system crontab format.
	if entries, err := os.ReadDir(e.fs.Physical("/etc/cron.d")); err == nil {
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
			e.analyzeCrontabFile(filepath.Join("/etc/cron.d", entry.Name()), "", true, false)
		}
	} else if !os.IsNotExist(err) {
		e.deny("/etc/cron.d", err.Error())
	}
	for _, spool := range cronAtSpools {
		e.scanCronSpool(spool)
	}
	for _, dir := range cronRunParts {
		e.scanRunParts(dir)
	}
}

// scanCronSpool lists one spool directory: each file is a user crontab or
// an at job.
func (e *Engine) scanCronSpool(dir string) {
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
		name := entry.Name()
		if strings.HasPrefix(name, ".") {
			continue // .SEQ and similar metadata
		}
		full := filepath.Join(dir, name)
		if entry.IsDir() {
			continue
		}
		if isAtJob(dir) {
			e.analyzeAtJob(full, name)
			continue
		}
		e.analyzeCrontabFile(full, name, false, true)
	}
}

// isAtJob reports whether the spool directory holds at jobs.
func isAtJob(dir string) bool {
	return strings.HasSuffix(dir, "/atjobs") || strings.HasSuffix(dir, "/at")
}

// scanRunParts inspects the run-parts script directories cron executes.
// Every script is a root-scheduled persistence target.
func (e *Engine) scanRunParts(dir string) {
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
		name := entry.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		full := filepath.Join(dir, name)
		if entry.IsDir() {
			continue
		}
		logical := full
		ti := e.InspectTarget(logical)
		e.reference(ti.LogicalPath, "cron", dir, 0, "cron-exec-writable-path", false)
		e.scanScriptContent(full)
	}
}

// scanScriptContent scans a scheduled script's first 200 non-empty lines
// with the cron trait rules. Comments are skipped so documentation never
// becomes evidence.
func (e *Engine) scanScriptContent(logical string) {
	lines, present, _ := e.artifactLines(logical)
	if !present {
		return
	}
	scanned := 0
	for i, raw := range lines {
		if e.canceled() || scanned >= 200 {
			return
		}
		line := stripComment(raw)
		if strings.TrimSpace(line) == "" {
			continue
		}
		scanned++
		if i == 0 && strings.HasPrefix(line, "#!") {
			continue // shebang is the interpreter, not a command
		}
		if strings.HasPrefix(strings.TrimSpace(raw), "#") {
			continue
		}
		if envAssignRe.MatchString(line) && !strings.Contains(line, "/") {
			continue // pure environment assignments without paths
		}
		traits := AnalyzeCommand(line)
		traits.Raw = RedactSecrets(line)
		if len(traits.Paths) == 0 && !traits.Downloads && !traits.Encoded && !traits.ReverseShell {
			continue
		}
		execTarget := traits.ExecPath
		e.reportCommandTraits(traits, cronTraitRules, logical, i+1, "", "", execTarget, "script")
	}
}

// analyzeCrontabFile parses one crontab (system, anacron or user spool).
func (e *Engine) analyzeCrontabFile(logical, spoolUser string, userField bool, isSpool bool) {
	lines, present, _ := e.artifactLines(logical)
	if !present {
		return
	}
	owner, group, perms, modified := e.artifactStat(logical)

	if isSpool {
		e.checkCronSpoolAnomaly(logical, spoolUser, owner, group, perms)
	}

	for i, raw := range lines {
		if e.canceled() {
			return
		}
		lineNo := i + 1
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Environment assignments: PATH matters, everything else is context.
		if envAssignRe.MatchString(line) {
			if strings.HasPrefix(strings.ToUpper(line), "PATH=") {
				e.checkCronPathAssignment(logical, lineNo, line)
			}
			continue
		}
		command, user := parseCrontabLine(line, userField, isSpool)
		if command == "" {
			continue
		}
		affected := user
		if isSpool {
			affected = spoolUser
		}
		home := ""
		if affected != "" {
			if u, ok := e.userByName(affected); ok {
				home = u.Home
			}
		}
		traits := AnalyzeCommand(command)
		// ExecPath keeps absolute and home-relative targets inspectable
		// and returns "" for PATH-resolved bare names.
		execTarget := traits.ExecPath
		_, matched := e.reportCommandTraits(traits, cronTraitRules, logical, lineNo, affected, home, execTarget, "crontab")
		_ = matched
	}
	_ = owner
	_ = group
	_ = perms
	_ = modified
}

// parseCrontabLine splits a crontab entry into command and user. System
// files carry the user field; spool files do not; @-shorthand schedules are
// supported.
func parseCrontabLine(line string, userField, isSpool bool) (command, user string) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return "", ""
	}
	// @reboot, @daily, @hourly, @weekly, @monthly, @yearly, @annually,
	// @midnight shorthand.
	if strings.HasPrefix(fields[0], "@") {
		rest := fields[1:]
		if userField && len(rest) > 0 && userNameRe.MatchString(rest[0]) {
			return strings.Join(rest[1:], " "), rest[0]
		}
		return strings.Join(rest, " "), ""
	}
	if isSpool {
		// User crontab: five schedule fields, then the command.
		if len(fields) < 6 {
			return "", ""
		}
		return strings.Join(fields[5:], " "), ""
	}
	// System crontab: five schedule fields, user, command. Tolerate 6-field
	// legacy forms where user is absent only when field 6 is clearly a path.
	if len(fields) < 6 {
		return "", ""
	}
	schedule := fields[:5]
	for _, f := range schedule {
		if !cronFieldRe.MatchString(f) {
			return "", ""
		}
	}
	sixth := fields[5]
	if userNameRe.MatchString(sixth) && len(fields) > 6 {
		return strings.Join(fields[6:], " "), sixth
	}
	// No user field (legacy or anacron-style): whole tail is the command.
	return strings.Join(fields[5:], " "), ""
}

// analyzeAtJob parses an at spool job. The first lines are metadata
// (shebang, atrun header); every other line is a shell command.
func (e *Engine) analyzeAtJob(logical, name string) {
	lines, present, _ := e.artifactLines(logical)
	if !present {
		return
	}
	owner, group, perms, modified := e.artifactStat(logical)

	affected := ""
	for i, raw := range lines {
		if e.canceled() {
			return
		}
		lineNo := i + 1
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			// "# atrun uid=1000 gid=1000" names the owning account.
			if strings.HasPrefix(line, "# atrun uid=") {
				affected = atJobUser(e, line)
			}
			continue
		}
		if strings.HasPrefix(line, "umask ") || strings.HasPrefix(line, "mail ") {
			continue
		}
		home := ""
		if affected != "" {
			if u, ok := e.userByName(affected); ok {
				home = u.Home
			}
		}
		traits := AnalyzeCommand(line)
		execTarget := traits.ExecPath
		e.reportCommandTraits(traits, cronTraitRules, logical, lineNo, affected, home, execTarget, "at-job")
	}
	_ = owner
	_ = group
	_ = perms
	_ = modified
	_ = name
}

// atJobUser extracts the account name from the "# atrun uid=N gid=N" header
// via the static passwd database.
func atJobUser(e *Engine, header string) string {
	if idx := strings.Index(header, "uid="); idx >= 0 {
		rest := header[idx+4:]
		if end := strings.IndexAny(rest, " \t"); end >= 0 {
			rest = rest[:end]
		}
		var uid int
		if _, err := fmt.Sscanf(rest, "%d", &uid); err == nil {
			return e.userName(uint32(uid))
		}
	}
	return ""
}

// checkCronSpoolAnomaly reports spool file ownership and permission
// anomalies (cron-spool-anomaly).
func (e *Engine) checkCronSpoolAnomaly(logical, spoolUser, owner, group, perms string) {
	var reasons []string
	if owner != spoolUser && owner != "" {
		reasons = append(reasons, fmt.Sprintf("owned by %s but named for %s", owner, spoolUser))
	}
	if strings.ContainsAny(perms[len(perms)-2:], "w") {
		// group or other writable
		reasons = append(reasons, "writable beyond its owner ("+perms+")")
	}
	if len(reasons) == 0 {
		return
	}
	f := e.baseFinding("cron-spool-anomaly", finding.Medium, logical)
	f.Evidence = strings.Join(reasons, "; ")
	f.User = spoolUser
	f.Owner = owner
	if group != "" {
		f.Owner = owner + ":" + group
	}
	f.Permissions = perms
	e.add(f)
}

// checkCronPathAssignment reports PATH assignments in crontabs that point
// into temporary or world-writable directories (cron-path-hijack).
func (e *Engine) checkCronPathAssignment(artifact string, line int, line_ string) {
	value := line_
	if idx := strings.Index(value, "="); idx >= 0 {
		value = value[idx+1:]
	}
	var suspicious []string
	for _, dir := range strings.FieldsFunc(value, func(r rune) bool { return r == ':' || r == ' ' }) {
		if dir == "" {
			continue
		}
		if isTempPath(filepath.Clean("/" + dir)) {
			suspicious = append(suspicious, dir)
			continue
		}
		logical := dir
		if !strings.HasPrefix(logical, "/") {
			continue
		}
		if ti := e.InspectTarget(logical); ti.DirWorldWrit {
			suspicious = append(suspicious, dir)
		}
	}
	if len(suspicious) == 0 {
		return
	}
	f := e.baseFinding("cron-path-hijack", finding.Medium, artifact)
	f.Line = line
	f.Evidence = "scheduled PATH includes writable locations: " + strings.Join(suspicious, ", ")
	f.Target = suspicious[0]
	e.add(f)
}
