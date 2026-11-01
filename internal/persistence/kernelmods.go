package persistence

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/Lutfifakee-Project/ronda/internal/finding"
)

// kmodLoadFiles list modules to load at boot.
var kmodLoadFiles = []string{"/etc/modules"}

var kmodLoadDirs = []string{"/etc/modules-load.d"}

var kmodConfDirs = []string{"/etc/modprobe.d"}

// kernelModuleTrees hold .ko images for existence checks.
var kernelModuleTrees = []string{"/lib/modules", "/usr/lib/modules"}

// udevRuleDirs list udev rule locations. /lib/udev/rules.d is usually a
// symlink to /usr/lib/udev/rules.d; both are listed safely.
var udevRuleDirs = []string{
	"/etc/udev/rules.d",
	"/run/udev/rules.d",
	"/usr/local/lib/udev/rules.d",
	"/usr/lib/udev/rules.d",
	"/lib/udev/rules.d",
}

// analyzeKernelModules inspects module-load configuration and modprobe.d
// directives. No module is loaded and no modprobe/depmod command runs.
func (e *Engine) analyzeKernelModules() {
	for _, f := range kmodLoadFiles {
		e.analyzeModuleLoadFile(f)
	}
	for _, dir := range kmodLoadDirs {
		e.scanModuleLoadDir(dir)
	}
	for _, dir := range kmodConfDirs {
		e.scanModprobeDir(dir)
	}
}

// analyzeModuleLoadFile parses /etc/modules-style files (one module per
// line, optional args).
func (e *Engine) analyzeModuleLoadFile(logical string) {
	lines, present, _ := e.artifactLines(logical)
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
		mod := fields[0]
		e.checkModuleExists(logical, i+1, mod)
	}
}

// scanModuleLoadDir reads modules-load.d/*.conf.
func (e *Engine) scanModuleLoadDir(dir string) {
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
		e.analyzeModuleLoadFile(filepath.Join(dir, entry.Name()))
	}
}

// scanModprobeDir reads modprobe.d/*.conf for install/remove directives
// with suspicious helpers and insmod-style absolute .ko paths.
func (e *Engine) scanModprobeDir(dir string) {
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
		e.analyzeModprobeConf(filepath.Join(dir, entry.Name()))
	}
}

// analyzeModprobeConf parses one modprobe.d file.
func (e *Engine) analyzeModprobeConf(logical string) {
	lines, present, _ := e.artifactLines(logical)
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
		lineNo := i + 1
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "install":
			// install <module> <command...>
			command := strings.Join(fields[2:], " ")
			e.checkKmodCommand(logical, lineNo, command, fields[1])
		case "remove":
			command := strings.Join(fields[2:], " ")
			e.checkKmodCommand(logical, lineNo, command, fields[1])
		case "insmod":
			// insmod is not a modprobe.d directive but appears in legacy
			// configs and rules; the path decides.
			if len(fields) >= 2 && strings.HasPrefix(fields[1], "/") {
				e.checkKmodPath(logical, lineNo, fields[1])
			}
		}
	}
}

// checkKmodCommand analyzes an install/remove command for suspicious
// helper locations and traits.
func (e *Engine) checkKmodCommand(artifact string, line int, command, module string) {
	traits := AnalyzeCommand(command)
	if len(traits.Paths) == 0 && !traits.Downloads && !traits.Encoded && !traits.ReverseShell {
		return
	}
	execTarget := traits.ExecPath
	// modprobe install directives legitimately call modprobe itself.
	if execTarget == "modprobe" || execTarget == "true" || execTarget == "false" || execTarget == "/sbin/modprobe" || execTarget == "/usr/sbin/modprobe" {
		execTarget = ""
	}
	kmodRules := traitRules{
		Writable:     "kmod-install-suspicious",
		Hidden:       "kmod-install-suspicious",
		DownloadExec: "kmod-install-suspicious",
		EncodedExec:  "kmod-install-suspicious",
		Reverse:      "kmod-install-suspicious",
	}
	e.reportCommandTraits(traits, kmodRules, artifact, line, "", "", execTarget, "config")
}

// checkKmodPath reports .ko references under writable locations.
func (e *Engine) checkKmodPath(artifact string, line int, path string) {
	ti := e.InspectTarget(path)
	e.reference(ti.LogicalPath, "kmod", artifact, line, "kmod-load-writable-path", false)
	if isTempPath(path) || ti.DirWorldWrit {
		f := e.baseFinding("kmod-load-writable-path", finding.High, artifact)
		f.Line = line
		f.Evidence = "kernel module image referenced from a writable location: " + path + describeTarget(ti)
		f.Target = path
		f.Trust = ti.Trust
		e.add(f)
	}
}

// checkModuleExists reports load-listed modules with no .ko image anywhere
// under the kernel module trees (weak indicator).
func (e *Engine) checkModuleExists(artifact string, line int, module string) {
	if module == "" || strings.Contains(module, "/") {
		return
	}
	for _, tree := range kernelModuleTrees {
		base := e.fs.Physical(tree)
		if _, err := os.Stat(base); err != nil {
			continue
		}
		if findKmod(base, module) {
			return
		}
	}
	// No module tree at all: kernels without /lib/modules (containers).
	// Report as unverified scope instead of a missing-module finding when
	// no tree exists.
	found := false
	for _, tree := range kernelModuleTrees {
		if fi, err := os.Stat(e.fs.Physical(tree)); err == nil && fi.IsDir() {
			found = true
			break
		}
	}
	if !found {
		e.unverifiedScope(artifact, "module "+module+" cannot be verified: no kernel module tree present in this root")
		return
	}
	f := e.baseFinding("kmod-missing-module", finding.Low, artifact)
	f.Line = line
	f.Evidence = "module " + module + " has no .ko image under the kernel module trees"
	e.add(f)
}

// findKmod searches one module tree for <module>.ko images (including
// compressed variants). The walk is bounded per directory level.
func findKmod(base, module string) bool {
	found := false
	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		if found || depth > 6 {
			return
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		if len(entries) > maxDirEntries {
			entries = entries[:maxDirEntries]
		}
		for _, entry := range entries {
			if found {
				return
			}
			if entry.IsDir() {
				walk(filepath.Join(dir, entry.Name()), depth+1)
				continue
			}
			name := entry.Name()
			if name == module+".ko" || strings.HasPrefix(name, module+".ko.") {
				found = true
				return
			}
		}
	}
	walk(base, 0)
	return found
}

// analyzeUdev inspects udev rules for RUN/IMPORT{program} helpers with
// suspicious locations or command traits. udevadm is never invoked.
func (e *Engine) analyzeUdev() {
	for _, dir := range udevRuleDirs {
		e.scanUdevRules(dir)
	}
}

// scanUdevRules reads *.rules files from one directory.
func (e *Engine) scanUdevRules(dir string) {
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
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".rules") {
			continue
		}
		e.analyzeUdevRules(filepath.Join(dir, entry.Name()))
	}
}

// analyzeUdevRules parses one rules file. Only program-executing keys are
// inspected; device matching semantics are not security evidence.
func (e *Engine) analyzeUdevRules(logical string) {
	lines, present, _ := e.artifactLines(logical)
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
		lineNo := i + 1
		for _, tok := range udevProgramTokens(line) {
			program := strings.Trim(tok, `"'`)
			if program == "" {
				continue
			}
			// $env{} style dynamic programs are recorded as references only.
			if strings.Contains(program, "$") {
				continue
			}
			traits := AnalyzeCommand(program)
			// Bare names resolve via udev's built-in search; only
			// inspectable targets participate in trait reporting.
			execTarget := traits.ExecPath
			udevRules := traitRules{
				Writable:     "udev-run-suspicious",
				Hidden:       "udev-run-suspicious",
				DownloadExec: "udev-run-suspicious",
				EncodedExec:  "udev-run-suspicious",
				Reverse:      "udev-run-suspicious",
				Missing:      "udev-run-missing",
			}
			e.reportCommandTraits(traits, udevRules, logical, lineNo, "", "", execTarget, "rule")
		}
	}
}

// udevProgramTokens extracts program arguments from RUN{program}=, RUN+=,
// IMPORT{program}= and PROGRAM= keys.
func udevProgramTokens(line string) []string {
	var out []string
	keys := []string{"RUN{program}=", "RUN+=", "RUN=", "IMPORT{program}=", "IMPORT+=", "PROGRAM="}
	for _, key := range keys {
		idx := 0
		for {
			i := strings.Index(line[idx:], key)
			if i < 0 {
				break
			}
			start := idx + i + len(key)
			// The value runs to the next space that is not inside quotes.
			val := scanQuotedValue(line[start:])
			if val != "" {
				out = append(out, val)
			}
			idx = start + len(val)
			if idx >= len(line) {
				break
			}
		}
	}
	return out
}

// scanQuotedValue reads a udev value token starting at s, honoring quotes
// and stopping at unquoted whitespace.
func scanQuotedValue(s string) string {
	var quote byte
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			if c == quote {
				quote = 0
				continue
			}
			out.WriteByte(c)
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
		case ' ', '\t':
			return out.String()
		default:
			out.WriteByte(c)
		}
	}
	return out.String()
}
