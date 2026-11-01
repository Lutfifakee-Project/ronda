package persistence

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/Lutfifakee-Project/ronda/internal/finding"
)

// ldsoPreloadFile is the preload list the dynamic loader applies to every
// dynamically linked process.
const ldsoPreloadFile = "/etc/ld.so.preload"

var ldsoConfFiles = []string{"/etc/ld.so.conf"}

var ldsoConfDirs = []string{"/etc/ld.so.conf.d"}

// analyzeLinker inspects /etc/ld.so.preload and ld.so.conf search paths.
// Referenced libraries are inspected statically and never loaded; ldd is
// never called.
func (e *Engine) analyzeLinker() {
	e.analyzeLdsoPreload()
	for _, conf := range ldsoConfFiles {
		e.analyzeLdsoConf(conf, 0)
	}
	for _, dir := range ldsoConfDirs {
		e.scanLdsoConfDir(dir)
	}
}

// analyzeLdsoPreload parses the preload list: one path per line, comments
// allowed. An absent or empty file is normal and produces no finding.
func (e *Engine) analyzeLdsoPreload() {
	lines, present, _ := e.artifactLines(ldsoPreloadFile)
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
		for _, tok := range strings.Fields(line) {
			lib := strings.Trim(tok, `"'`)
			if lib == "" {
				continue
			}
			if !strings.HasPrefix(lib, "/") {
				// Relative entries resolve via loader context.
				f := e.baseFinding("ldso-relative-path", finding.Low, ldsoPreloadFile)
				f.Line = lineNo
				f.Evidence = "preload entry is a relative path: " + RedactSecrets(lib)
				e.add(f)
				continue
			}
			ti := e.InspectTarget(lib)
			e.reference(lib, "ldso", ldsoPreloadFile, lineNo, "ldso-preload-entry", false)

			// Context entry for every preload use.
			info := e.baseFinding("ldso-preload-entry", finding.Info, ldsoPreloadFile)
			info.Line = lineNo
			info.Kind = "library"
			info.Target = lib
			info.Trust = ti.Trust
			switch {
			case !ti.Exists:
				info.Evidence = "preloaded object does not exist: " + lib
				e.add(info)
				miss := e.baseFinding("ldso-preload-missing", finding.Low, ldsoPreloadFile)
				miss.Line = lineNo
				miss.Target = lib
				miss.Trust = ti.Trust
				miss.Evidence = "preloaded object is missing: " + lib
				e.add(miss)
				continue
			case !ti.Accessible:
				info.Evidence = "preloaded object cannot be inspected: " + lib + " (" + ti.Err + ")"
				e.add(info)
				continue
			}
			info.Evidence = "preloaded object: " + lib + describeTarget(ti)
			e.add(info)

			loc := e.classifyLocation(lib)
			if loc == "temp" || loc == "writabledir" || loc == "hidden" || loc == "home" {
				f := e.baseFinding("ldso-preload-suspicious-path", finding.High, ldsoPreloadFile)
				f.Line = lineNo
				f.Evidence = "preloaded object resides in " + locationLabel(loc) + ": " + lib + describeTarget(ti)
				f.Target = lib
				f.Trust = ti.Trust
				e.add(f)
			} else if ti.Kind != "elf" {
				f := e.baseFinding("ldso-preload-not-elf", finding.Medium, ldsoPreloadFile)
				f.Line = lineNo
				f.Evidence = "preloaded path exists but is not an ELF shared object (" + ti.Kind + "): " + lib
				f.Target = lib
				f.Trust = ti.Trust
				e.add(f)
			}
			// Architecture mismatch: only meaningful on live-host scans,
			// where the running machine defines the expected ELF
			// architecture. Offline roots have none to compare against.
			if e.fs.LiveHost() && archMismatch(elfArchForHost(), ti.ELFArch) {
				if host := elfArchForHost(); host != "" {
					f := e.baseFinding("ldso-preload-arch-mismatch", finding.Medium, ldsoPreloadFile)
					f.Line = lineNo
					f.Evidence = "preloaded object targets " + ti.ELFArch + " but the running host is " + host + ": " + lib
					f.Target = lib
					f.Trust = ti.Trust
					e.add(f)
				}
			}
		}
	}
}

// archMismatch compares the host ELF architecture with a preloaded
// object's: both must be known and different for a mismatch to be claimed.
func archMismatch(hostArch, elfArch string) bool {
	return hostArch != "" && elfArch != "" && hostArch != elfArch
}

// elfArchForHost maps the running GOARCH onto the ELF machine labels the
// header sniffer records. It returns "" on hosts RONDA cannot name, so
// no comparison is claimed there.
func elfArchForHost() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x86-64"
	case "arm64":
		return "aarch64"
	case "386":
		return "i386"
	case "arm":
		return "arm"
	case "riscv64":
		return "riscv"
	}
	return ""
}

// describeTarget renders honest static inspection metadata.
func describeTarget(ti *TargetInfo) string {
	if ti.ELFArch != "" {
		kind := "ELF"
		if ti.ELFShared {
			kind = "ELF shared object"
		}
		return " (" + kind + " " + ti.ELFArch + ", sha256 " + shortHash(ti.SHA256) + ")"
	}
	if ti.Kind != "" {
		return " (" + ti.Kind + ", sha256 " + shortHash(ti.SHA256) + ")"
	}
	return ""
}

// shortHash truncates a hash for display.
func shortHash(h string) string {
	if len(h) > 16 {
		return h[:16] + "..."
	}
	return h
}

// analyzeLdsoConf parses ld.so.conf and its includes for search directories.
func (e *Engine) analyzeLdsoConf(logical string, depth int) {
	if depth > 4 {
		return
	}
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
		if strings.HasPrefix(strings.ToLower(line), "include ") {
			pattern := strings.TrimSpace(line[len("include "):])
			e.expandLdsoInclude(logical, filepath.Dir(logical), pattern, depth)
			continue
		}
		if !strings.HasPrefix(line, "/") {
			continue
		}
		dir := strings.Fields(line)[0]
		e.checkLdsoDir(logical, lineNo, dir)
	}
}

// scanLdsoConfDir reads conf.d style directories.
func (e *Engine) scanLdsoConfDir(dir string) {
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
		e.analyzeLdsoConf(filepath.Join(dir, entry.Name()), 1)
	}
}

// expandLdsoInclude resolves include globs inside the root (bounded).
func (e *Engine) expandLdsoInclude(fromFile, fromDir, pattern string, depth int) {
	if !filepath.IsAbs(pattern) && !strings.HasPrefix(pattern, "/") {
		pattern = filepath.Join(fromDir, pattern)
	}
	pattern = e.fs.Physical(pattern)
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return
	}
	for _, m := range matches {
		if e.canceled() {
			return
		}
		if !e.fs.contains(m) {
			continue
		}
		logical := e.logicalOf(m)
		if fi, err := os.Stat(m); err == nil && !fi.IsDir() {
			e.analyzeLdsoConf(logical, depth+1)
		}
	}
}

// checkLdsoDir reports search directories in writable locations.
func (e *Engine) checkLdsoConf(logical string, line int, dir string) {
	e.checkLdsoDir(logical, line, dir)
}

func (e *Engine) checkLdsoDir(confFile string, line int, dir string) {
	ti := e.InspectTarget(dir)
	e.reference(ti.LogicalPath, "ldso", confFile, line, "ldso-conf-writable-dir", false)
	if !ti.Exists {
		return
	}
	if !ti.IsDir {
		return
	}
	if isTempPath(dir) || ti.DirWorldWrit {
		f := e.baseFinding("ldso-conf-writable-dir", finding.Medium, confFile)
		f.Line = line
		f.Evidence = "library search path is a writable location: " + dir
		f.Target = dir
		f.Trust = ti.Trust
		e.add(f)
	}
}
