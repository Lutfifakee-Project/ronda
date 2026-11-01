package persistence

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Lutfifakee-Project/ronda/internal/finding"
)

// sshdSystemConfig locations parsed statically. sshd(8) is never invoked.
var sshdConfigFiles = []string{"/etc/ssh/sshd_config", "/etc/ssh/ssh_config"}

var sshdConfigDropinDirs = []string{"/etc/ssh/sshd_config.d"}

// sshStandardCommandPrefixes are forced-command targets that are standard
// restricted-access patterns rather than suspicious payload references.
var sshStandardCommandPrefixes = []string{
	"/usr/bin/git-shell",
	"/usr/local/bin/git-shell",
	"/usr/bin/rrsync",
	"/usr/bin/rsync",
	"/usr/lib/openssh/sftp-server",
	"/usr/lib/sftp-server",
	"/usr/sbin/nologin",
	"internal-sftp",
	"git-shell",
}

// sshKeyInfo is the non-secret metadata of one authorized_keys entry.
type sshKeyInfo struct {
	Algorithm   string
	Fingerprint string
	Options     []string
	ForcedCmd   string
	Line        int
}

// analyzeSSH audits sshd configuration and every statically known user's
// authorized_keys. Key material is never printed or transmitted: only the
// algorithm and SHA-256 fingerprint are recorded.
func (e *Engine) analyzeSSH() {
	akFile := map[string]bool{} // AuthorizedKeysFile patterns (relative by default)
	akFile[".ssh/authorized_keys"] = true
	akFile[".ssh/authorized_keys2"] = true
	akCommand := ""

	for _, cfg := range sshdConfigFiles {
		e.analyzeSSHConfig(cfg, akFile, &akCommand)
	}
	for _, dir := range sshdConfigDropinDirs {
		e.scanSSHConfigDir(dir, akFile, &akCommand)
	}

	for _, u := range e.users {
		if e.canceled() {
			return
		}
		home := u.Home
		if !strings.HasPrefix(home, "/") || home == "/dev/null" || home == "/nonexistent" {
			continue
		}
		for pattern := range akFile {
			expanded := expandAKTokens(pattern, u.Name, home)
			if !strings.HasPrefix(expanded, "/") {
				expanded = filepath.Clean("/" + home + "/" + expanded)
			}
			e.analyzeAuthorizedKeys(expanded, u)
		}
	}
	_ = akCommand
}

// expandAKTokens expands sshd_config authorized_keys tokens. Only the
// tokens that matter statically are handled; unknown tokens are left.
func expandAKTokens(pattern, user, home string) string {
	r := strings.NewReplacer(
		"%u", user,
		"%h", home,
		"%%", "%",
		"%U", fmt.Sprintf("%d", 0), // uid resolved lazily; rarely used
		"%d", home,
	)
	return r.Replace(pattern)
}

// scanSSHConfigDir reads sshd_config.d drop-in files.
func (e *Engine) scanSSHConfigDir(dir string, akFile map[string]bool, akCommand *string) {
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
		e.analyzeSSHConfig(filepath.Join(dir, entry.Name()), akFile, akCommand)
	}
}

// analyzeSSHConfig parses one sshd_config-style file. Match blocks keep
// their criteria as context.
func (e *Engine) analyzeSSHConfig(logical string, akFile map[string]bool, akCommand *string) {
	lines, present, _ := e.artifactLines(logical)
	if !present {
		return
	}
	matchCtx := ""
	for i, raw := range lines {
		if e.canceled() {
			return
		}
		lineNo := i + 1
		line := strings.TrimSpace(stripComment(raw))
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "match ") {
			matchCtx = strings.TrimSpace(line[len("match "):])
			continue
		}
		key, value := splitConfigKeyValue(line)
		if key == "" {
			continue
		}
		switch strings.ToLower(key) {
		case "permitrootlogin":
			v := strings.ToLower(strings.Fields(value)[0])
			if v == "yes" {
				f := e.baseFinding("ssh-config-permitroot", finding.Medium, logical)
				f.Line = lineNo
				f.Evidence = "PermitRootLogin " + v
				if matchCtx != "" {
					f.Evidence += " (inside Match " + RedactSecrets(matchCtx) + ")"
				}
				e.add(f)
			}
		case "authorizedkeysfile":
			for _, pattern := range strings.Fields(value) {
				if pattern == "none" {
					continue
				}
				akFile[pattern] = true
			}
		case "authorizedkeyscommand":
			*akCommand = value
			e.checkAuthorizedKeysCommand(logical, lineNo, value, matchCtx)
		case "forcecommand":
			// Forced commands in sshd_config apply broadly; treat like a
			// key-level forced command for path checks.
			e.checkForcedCommand(logical, lineNo, value, "", "sshd_config ForceCommand")
		case "include":
			// Includes resolve within the root; drop-ins are covered by the
			// sshd_config.d scan. Record the reference for completeness.
			for _, tok := range strings.Fields(value) {
				if strings.HasPrefix(tok, "/") {
					e.reference(tok, "ssh", logical, lineNo, "ssh-authorizedkeyscommand", false)
				}
			}
		}
	}
}

// splitConfigKeyValue splits an OpenSSH-style "Key Value" line.
func splitConfigKeyValue(line string) (string, string) {
	idx := strings.IndexAny(line, " \t=")
	if idx < 0 {
		return line, ""
	}
	key := line[:idx]
	rest := strings.TrimSpace(line[idx:])
	rest = strings.TrimPrefix(rest, "=")
	return key, strings.TrimSpace(rest)
}

// checkAuthorizedKeysCommand reports AuthorizedKeysCommand values whose
// binary lives in a writable, temporary or unexpected location.
func (e *Engine) checkAuthorizedKeysCommand(logical string, line int, value, matchCtx string) {
	cmd := strings.TrimSpace(value)
	if cmd == "" || cmd == "none" {
		return
	}
	first := strings.Fields(cmd)[0]
	if !strings.HasPrefix(first, "/") {
		return // PATH-resolved helpers are a configuration style, not a path
	}
	ti := e.InspectTarget(first)
	e.reference(first, "ssh", logical, line, "ssh-authorizedkeyscommand", false)
	loc := e.classifyLocation(first)
	if loc == "temp" || loc == "writabledir" || loc == "hidden" {
		f := e.baseFinding("ssh-authorizedkeyscommand", finding.High, logical)
		f.Line = line
		f.Evidence = "AuthorizedKeysCommand references " + first + " (" + locationLabel(loc) + ")"
		f.Target = first
		f.Trust = ti.Trust
		if matchCtx != "" {
			f.Evidence += " (inside Match " + RedactSecrets(matchCtx) + ")"
		}
		e.add(f)
		return
	}
	// Absolute path outside standard binary directories without package
	// ownership stays worth recording as context.
	if ti.Exists && ti.Trust == TrustUnowned && !strings.HasPrefix(first, "/usr/") && !strings.HasPrefix(first, "/bin/") && !strings.HasPrefix(first, "/sbin/") {
		f := e.baseFinding("ssh-authorizedkeyscommand", finding.Medium, logical)
		f.Line = line
		f.Evidence = "AuthorizedKeysCommand references an unowned helper outside standard directories: " + first
		f.Target = first
		f.Trust = ti.Trust
		e.add(f)
	}
}

// locationLabel humanizes classifyLocation results.
func locationLabel(loc string) string {
	switch loc {
	case "temp":
		return "temporary or writable-by-design location"
	case "writabledir":
		return "directory writable by unprivileged users"
	case "hidden":
		return "hidden path"
	case "home":
		return "user home path"
	}
	return loc
}

// parseAuthorizedKeyLine parses one authorized_keys line into non-secret
// metadata. It returns (info, ok, blankOrComment). The key blob itself is
// discarded immediately after fingerprinting.
func parseAuthorizedKeyLine(line string) (sshKeyInfo, bool, bool) {
	info := sshKeyInfo{}
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return info, false, true
	}
	rest := trimmed
	// Leading options: either a quoted options string or a comma-separated
	// run without whitespace before the key type.
	for {
		if strings.HasPrefix(rest, "\"") {
			end := strings.Index(rest[1:], "\"")
			if end < 0 {
				return info, false, false
			}
			info.Options = append(info.Options, rest[1:1+end])
			rest = strings.TrimSpace(rest[end+2:])
			continue
		}
		if strings.Contains(rest, " ") {
			head, tail := splitFirstField(rest)
			if looksLikeOptions(head) {
				// An option value may contain quoted spaces
				// (command="/opt/a --serve"): keep consuming tokens until
				// the closing quote so the forced command survives word
				// splitting.
				for strings.Count(head, "\"")%2 == 1 && tail != "" {
					var next string
					next, tail = splitFirstField(tail)
					head += " " + next
				}
				info.Options = append(info.Options, head)
				rest = tail
				continue
			}
		}
		break
	}
	fields := strings.Fields(rest)
	if len(fields) < 2 {
		return info, false, false
	}
	alg := fields[0]
	blob := fields[1]
	if len(blob) > 16384 {
		return info, false, false
	}
	raw, err := base64.StdEncoding.DecodeString(blob)
	if err != nil || len(raw) == 0 {
		return info, false, false
	}
	sum := sha256.Sum256(raw)
	fp := base64.RawStdEncoding.EncodeToString(sum[:])
	info.Algorithm = alg
	info.Fingerprint = "SHA256:" + fp
	info.ForcedCmd = extractForcedCommand(info.Options)
	return info, true, false
}

// splitFirstField splits off the first whitespace-delimited token.
func splitFirstField(s string) (string, string) {
	idx := strings.IndexAny(s, " \t")
	if idx < 0 {
		return s, ""
	}
	return s[:idx], strings.TrimSpace(s[idx:])
}

// looksLikeOptions reports whether a leading token is an options run
// (comma-separated key[=value] pairs) rather than a key algorithm.
func looksLikeOptions(tok string) bool {
	if strings.Contains(tok, " ") {
		return false
	}
	if !strings.Contains(tok, ",") && !strings.Contains(tok, "=") {
		return false
	}
	return !strings.HasPrefix(tok, "ssh-") && !strings.HasPrefix(tok, "ecdsa-") && !strings.HasPrefix(tok, "sk-")
}

// forcedQuoted matches command="value" exactly: the value ends at the
// closing quote even when further options (,restrict) follow it.
var forcedQuoted = regexp.MustCompile(`command="([^"]*)"`)

// extractForcedCommand pulls command="..." out of an options string.
func extractForcedCommand(options []string) string {
	for _, opt := range options {
		if m := forcedQuoted.FindStringSubmatch(opt); m != nil {
			return m[1]
		}
	}
	for _, opt := range options {
		if strings.HasPrefix(opt, "command=") {
			return strings.TrimPrefix(opt, "command=")
		}
		for _, part := range strings.Split(opt, ",") {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, "command=\"") {
				return strings.TrimSuffix(strings.TrimPrefix(part, "command=\""), "\"")
			}
			if strings.HasPrefix(part, "command=") {
				return strings.TrimPrefix(part, "command=")
			}
		}
	}
	return ""
}

// analyzeAuthorizedKeys audits one authorized_keys file for a user.
func (e *Engine) analyzeAuthorizedKeys(logical string, u account) {
	lines, present, _ := e.artifactLines(logical)
	if !present {
		return
	}
	owner, group, perms, modified := e.artifactStat(logical)

	// Permission and ownership checks on the file and its .ssh directory.
	dirLogical := filepath.Dir(logical)
	dirTI := e.InspectTarget(dirLogical)
	if strings.ContainsAny(perms[len(perms)-2:], "w") {
		f := e.baseFinding("ssh-unsafe-key-permissions", finding.Medium, logical)
		f.Evidence = "authorized_keys is writable beyond its owner (" + perms + ")"
		f.User = u.Name
		f.Owner = owner
		f.Permissions = perms
		e.add(f)
	}
	if dirTI.WorldWrit {
		f := e.baseFinding("ssh-unsafe-key-permissions", finding.Medium, dirLogical)
		f.Evidence = ".ssh directory is writable beyond its owner (" + dirTI.Mode + ")"
		f.User = u.Name
		f.Owner = dirTI.Owner
		f.Permissions = dirTI.Mode
		e.add(f)
	}
	if owner != "" && owner != u.Name {
		// A known other account owning the file is a real mismatch. A
		// numeric uid absent from the scanned passwd is offline UID drift
		// (common on mounted images): context, not a mismatch.
		sev := finding.Medium
		suffix := ""
		if _, known := e.userByName(owner); !known {
			sev = finding.Info
			suffix = " (uid not present in the scanned passwd)"
		}
		f := e.baseFinding("ssh-key-owner-mismatch", sev, logical)
		f.Evidence = fmt.Sprintf("authorized_keys owned by %s but resides in %s's home%s", owner, u.Name, suffix)
		f.User = u.Name
		f.Owner = owner
		if group != "" {
			f.Owner = owner + ":" + group
		}
		f.Permissions = perms
		e.add(f)
	}

	keyCount := 0
	for i, raw := range lines {
		if e.canceled() {
			return
		}
		lineNo := i + 1
		info, ok, blank := parseAuthorizedKeyLine(raw)
		if blank {
			continue
		}
		if !ok {
			f := e.baseFinding("ssh-malformed-key", finding.Low, logical)
			f.Line = lineNo
			f.Evidence = "line is neither blank, comment nor a parseable public key (" + keyShape(raw) + ")"
			f.User = u.Name
			e.add(f)
			continue
		}
		keyCount++
		e.checkKeyOptions(logical, lineNo, info, u)
	}

	// Root keys are context, never automatic findings.
	if u.Name == "root" && keyCount > 0 {
		f := e.baseFinding("ssh-root-authorized-key", finding.Info, logical)
		f.Evidence = fmt.Sprintf("%d public key(s) present; fingerprints are recorded for baseline comparison", keyCount)
		f.User = u.Name
		f.Owner = owner
		if group != "" {
			f.Owner = owner + ":" + group
		}
		f.Permissions = perms
		f.Modified = modified
		e.add(f)
	}
}

// keyShape summarizes a malformed line without revealing key material.
func keyShape(raw string) string {
	trimmed := strings.TrimSpace(raw)
	fields := strings.Fields(trimmed)
	if len(fields) == 0 {
		return "empty after options"
	}
	shape := fmt.Sprintf("%d fields", len(fields))
	if fields[0] != "" {
		shape += ", first token " + safeToken(fields[0])
	}
	return shape
}

// safeToken prints a token only when it carries no base64-looking material.
func safeToken(tok string) string {
	if len(tok) > 32 {
		return "<" + fmt.Sprint(len(tok)) + " chars>"
	}
	if strings.ContainsAny(tok, "+/") && len(tok) > 20 {
		return "<encoded material>"
	}
	return tok
}

// checkKeyOptions inspects one key's options for forced commands.
func (e *Engine) checkKeyOptions(logical string, line int, info sshKeyInfo, u account) {
	if info.ForcedCmd == "" {
		return
	}
	e.checkForcedCommand(logical, line, info.ForcedCmd, u.Name, "authorized_keys forced command")
}

// checkForcedCommand analyzes a forced command target. Standard restricted
// patterns (git-shell, rrsync, internal-sftp) are skipped; everything else
// is reported by location and traits.
func (e *Engine) checkForcedCommand(artifact string, line int, cmd, user, label string) {
	redacted := RedactSecrets(cmd)
	trimmed := strings.TrimSpace(cmd)
	trimmed = strings.TrimPrefix(trimmed, "\"")
	trimmed = strings.TrimSuffix(trimmed, "\"")

	first := trimmed
	if fields := strings.Fields(trimmed); len(fields) > 0 {
		first = fields[0]
	}
	standard := false
	for _, pre := range sshStandardCommandPrefixes {
		if first == pre || strings.HasPrefix(first, pre) {
			standard = true
			break
		}
	}
	if standard {
		return
	}

	home := ""
	if user != "" {
		if u, ok := e.userByName(user); ok {
			home = u.Home
		}
	}
	traits := AnalyzeCommand(trimmed)
	// Inspectable target from the trait analysis; for `sh -c` payloads
	// it is the inner command's target.
	execTarget := traits.ExecPath
	if execTarget != "" && strings.HasPrefix(execTarget, "/") {
		if ti := e.InspectTarget(execTarget); ti.Exists {
			e.reference(execTarget, "ssh", artifact, line, "ssh-forced-command", true)
		}
	}
	sshRules := traitRules{
		Writable:     "ssh-forced-command",
		Hidden:       "ssh-forced-command",
		DownloadExec: "ssh-forced-command",
		EncodedExec:  "ssh-forced-command",
		Reverse:      "ssh-forced-command",
	}
	reported, _ := e.reportCommandTraits(traits, sshRules, artifact, line, user, home, execTarget, "authorized-keys")
	if reported.Raw == "" {
		reported.Raw = redacted
	}
	_ = reported

	// Non-standard absolute path without trait escalation: still reported
	// as MEDIUM context with the label so reviewers see the restriction.
	if execTarget != "" && strings.HasPrefix(execTarget, "/") {
		ti := e.InspectTarget(execTarget)
		loc := e.classifyLocation(execTarget)
		if loc == "" && ti.Exists {
			f := e.baseFinding("ssh-forced-command", finding.Medium, artifact)
			f.Line = line
			f.Evidence = label + " restricts sessions to: " + redacted
			f.Target = execTarget
			f.Trust = ti.Trust
			f.User = user
			e.add(f)
		}
	}
}

// execTokenHome is a tiny helper for readability in checkForcedCommand.
func execTokenHome(tok string) bool {
	return strings.HasPrefix(tok, "~/") || strings.HasPrefix(tok, "$HOME/")
}
