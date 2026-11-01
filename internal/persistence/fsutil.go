package persistence

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// limits keep every inspection bounded regardless of what a hostile root
// filesystem contains.
const (
	maxReadFileBytes = 8 << 20  // 8 MiB for hashing/inspection of one file
	maxScanFileBytes = 4 << 20  // 4 MiB for configuration text parsing
	maxLineBytes     = 64 << 10 // 64 KiB per configuration line
	maxDirEntries    = 4096     // per directory listing
	maxTargets       = 8192     // distinct referenced targets per scan
)

// account is one statically parsed /etc/passwd entry.
type account struct {
	Name  string
	UID   int
	GID   int
	Home  string
	Shell string
}

// group is one statically parsed /etc/group entry.
type group struct {
	Name    string
	GID     int
	Members []string
	Line    int
}

// RootFS is a selected root filesystem: the live host when root is "/" (or
// empty) and an offline mounted root otherwise. Every artifact path inside
// the engine is a LOGICAL absolute path ("/etc/cron.d/x"); RootFS maps it to
// the physical path and guarantees no inspection escapes the root.
type RootFS struct {
	root string // "" or "/" means live host
}

// NewRootFS builds a RootFS. An empty argument means the live host.
func NewRootFS(root string) RootFS {
	root = strings.TrimSpace(root)
	if root == "" || root == "/" {
		return RootFS{root: ""}
	}
	return RootFS{root: filepath.Clean(root)}
}

// Root returns the physical root directory ("" for the live host).
func (fs RootFS) Root() string { return fs.root }

// LiveHost reports whether this is the running system itself.
func (fs RootFS) LiveHost() bool { return fs.root == "" }

// Physical maps a logical absolute path to its physical location. A logical
// path that is not absolute maps under the root as a safety net.
func (fs RootFS) Physical(logical string) string {
	logical = filepath.Clean("/" + strings.TrimSpace(logical))
	return filepath.Join(string(filepath.Separator)+fs.root, logical)
}

// contains reports whether the (already physical) path lies inside the root.
// For the live host every path is contained.
func (fs RootFS) contains(physical string) bool {
	if fs.root == "" {
		return true
	}
	clean := filepath.Clean(physical)
	return clean == fs.root || strings.HasPrefix(clean, fs.root+string(filepath.Separator))
}

// resolve maps a logical path to a physical path and collapses symlink
// chains whose targets stay inside the root. The second result reports
// whether the resolved path remained contained; escaped symlinks are
// reported, never followed.
func (fs RootFS) resolve(logical string) (string, bool) {
	phys := fs.Physical(logical)
	for i := 0; i < 8; i++ {
		fi, err := os.Lstat(phys)
		if err != nil || fi.Mode()&os.ModeSymlink == 0 {
			return phys, true
		}
		link, err := os.Readlink(phys)
		if err != nil {
			return phys, true
		}
		var next string
		if filepath.IsAbs(link) {
			next = fs.Physical(link)
		} else {
			next = filepath.Join(filepath.Dir(phys), link)
		}
		if !fs.contains(next) {
			return phys, false
		}
		phys = next
	}
	// Symlink loop: treat as contained at the last hop; Lstat decides.
	return phys, true
}

// fileMode renders a mode in ls-style notation ("-rwxr-xr-x", sticky bit
// rendered as 't').
func fileMode(mode os.FileMode) string {
	var b [10]byte
	switch {
	case mode.IsDir():
		b[0] = 'd'
	case mode&os.ModeSymlink != 0:
		b[0] = 'l'
	default:
		b[0] = '-'
	}
	const rwx = "rwx"
	m := uint32(mode.Perm())
	for i := 0; i < 3; i++ {
		shift := uint32(6 - 3*i)
		bits := (m >> shift) & 7
		for j := 0; j < 3; j++ {
			if bits&(1<<uint(2-j)) != 0 {
				b[1+i*3+j] = rwx[j]
			} else {
				b[1+i*3+j] = '-'
			}
		}
	}
	if mode&os.ModeSticky != 0 {
		if b[9] == 'x' {
			b[9] = 't'
		} else {
			b[9] = 'T'
		}
	}
	return string(b[:])
}

// worldWritable reports whether the owner/others beyond group can write.
// For directories, the sticky bit prevents simple replacement, so a sticky
// world-writable directory (/tmp) is still treated as a writable location
// for PAYLOADS placed inside it by design; the caller decides context.
func worldWritable(mode os.FileMode) bool {
	return mode.Perm()&0o222 != 0 && mode.Perm()&0o002 != 0
}

// groupWritable reports whether group-write permission is set.
func groupWritable(mode os.FileMode) bool {
	return mode.Perm()&0o020 != 0
}

// TargetInfo captures everything Phase 5 records about one referenced
// target. Target paths are logical (root-relative) so offline scans report
// the same paths a live host would.
type TargetInfo struct {
	LogicalPath  string
	Exists       bool
	Accessible   bool
	IsDir        bool
	IsSymlink    bool
	Kind         string // "elf", "script", "text", "binary", "dir", "missing"
	ELFArch      string
	ELFShared    bool
	Interpreter  string
	Hidden       bool
	Mode         string
	Owner        string
	Group        string
	WorldWrit    bool
	GroupWrit    bool
	DirWorldWrit bool
	Size         int64
	ModifiedUTC  string
	SHA256       string
	Err          string
	// provenance (filled by the provenance pass)
	Package string
	Trust   string
}

// hiddenName reports whether the final component (or its immediate parent)
// is dot-prefixed.
func hiddenName(p string) bool {
	base := filepath.Base(p)
	if strings.HasPrefix(base, ".") && base != "." && base != ".." {
		return true
	}
	dir := filepath.Dir(p)
	return strings.HasPrefix(filepath.Base(dir), ".")
}

// sniffKind classifies a file from its first bytes: ELF, script (shebang),
// text or binary. Only the header is read, never executed.
func sniffKind(path string) (kind, elfArch string, shared bool, interp string) {
	f, err := os.Open(path)
	if err != nil {
		return "binary", "", false, ""
	}
	defer f.Close()
	head := make([]byte, 64)
	n, _ := io.ReadFull(f, head)
	head = head[:n]
	if len(head) >= 4 && head[0] == 0x7f && head[1] == 'E' && head[2] == 'L' && head[3] == 'F' {
		arch := "unknown"
		shared = false
		if len(head) >= 20 {
			class := head[4]
			endian := head[5]
			machine := uint32(0)
			if endian == 1 {
				machine = uint32(head[18]) | uint32(head[19])<<8
			} else if endian == 2 {
				machine = uint32(head[19]) | uint32(head[18])<<8
			}
			switch machine {
			case 62:
				arch = "x86-64"
			case 183:
				arch = "aarch64"
			case 3:
				arch = "i386"
			case 40:
				arch = "arm"
			case 8:
				arch = "mips"
			case 2:
				arch = "sparc"
			case 20:
				arch = "ppc"
			case 21:
				arch = "ppc64"
			case 50:
				arch = "ia64"
			case 243:
				arch = "riscv"
			}
			etype := uint16(0)
			if endian == 1 {
				etype = uint16(head[16]) | uint16(head[17])<<8
			} else if endian == 2 {
				etype = uint16(head[17]) | uint16(head[16])<<8
			}
			shared = etype == 3 // ET_DYN: shared objects and PIE both, recorded as context
			_ = class
		}
		return "elf", arch, shared, ""
	}
	if len(head) >= 2 && head[0] == '#' && head[1] == '!' {
		line := string(head)
		if i := strings.IndexAny(line, "\n\r"); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(strings.TrimPrefix(line, "#!"))
		if len(fields) > 0 {
			interp = fields[0]
			// "/usr/bin/env X" style: the payload is the next token.
			if filepath.Base(interp) == "env" && len(fields) > 1 {
				interp = fields[1]
			}
		}
		return "script", "", false, interp
	}
	// Text vs binary: sample for NUL bytes in a bounded window.
	f2, err := os.Open(path)
	if err != nil {
		return "binary", "", false, ""
	}
	defer f2.Close()
	r := bufio.NewReader(io.LimitReader(f2, 4096))
	chunk, _ := io.ReadAll(r)
	if len(chunk) == 0 {
		return "text", "", false, ""
	}
	for _, c := range chunk {
		if c == 0 {
			return "binary", "", false, ""
		}
	}
	return "text", "", false, ""
}

// InspectTarget inspects one logical target path inside the root: existence,
// type, ELF metadata, ownership (against the root's own passwd/group),
// permissions, size, mtime and a bounded SHA-256. Symlinks that resolve
// outside the root are reported as inaccessible, never followed.
func (e *Engine) InspectTarget(logical string) *TargetInfo {
	logical = filepath.Clean("/" + strings.TrimSpace(logical))
	if ti, ok := e.targets[logical]; ok {
		return ti
	}
	if len(e.targets) >= maxTargets {
		// Bounded: report the path without deep inspection.
		return &TargetInfo{LogicalPath: logical, Trust: TrustUnverified}
	}
	ti := &TargetInfo{LogicalPath: logical, Trust: TrustUnverified}
	e.targets[logical] = ti

	phys, contained := e.fs.resolve(logical)
	if !contained {
		ti.Exists = false
		ti.Accessible = false
		ti.Err = "symlink resolves outside the scanned root"
		ti.Trust = TrustUnverified
		return ti
	}
	fi, err := os.Stat(phys)
	if err != nil {
		if os.IsNotExist(err) {
			ti.Exists = false
			ti.Accessible = true
			return ti
		}
		ti.Exists = false
		ti.Accessible = false
		ti.Err = err.Error()
		ti.Trust = TrustInaccessible
		return ti
	}
	ti.Exists = true
	ti.Accessible = true
	ti.IsDir = fi.IsDir()
	if fi.Mode()&os.ModeSymlink != 0 {
		ti.IsSymlink = true
	}
	ti.Hidden = hiddenName(logical)
	ti.Mode = fileMode(fi.Mode())
	ti.WorldWrit = worldWritable(fi.Mode())
	ti.GroupWrit = groupWritable(fi.Mode())
	ti.Size = fi.Size()
	ti.ModifiedUTC = fi.ModTime().UTC().Format("2006-01-02T15:04:05Z")
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && st != nil {
		ti.Owner = e.userName(st.Uid)
		ti.Group = e.groupName(st.Gid)
	}
	if !ti.IsDir {
		kind, arch, shared, interp := sniffKind(phys)
		ti.Kind = kind
		ti.ELFArch = arch
		ti.ELFShared = shared
		ti.Interpreter = interp
		if fi.Size() <= maxReadFileBytes {
			if data, err := os.ReadFile(phys); err == nil {
				sum := sha256.Sum256(data)
				ti.SHA256 = hex.EncodeToString(sum[:])
			} else {
				ti.Accessible = false
				ti.Err = err.Error()
				ti.Trust = TrustInaccessible
			}
		}
	}
	// Directory writability context: the immediate parent.
	parent := e.fs.Physical(filepath.Dir(logical))
	if pfi, err := os.Stat(parent); err == nil {
		ti.DirWorldWrit = worldWritable(pfi.Mode())
	}
	return ti
}

// userName resolves a uid against the root's own passwd database.
func (e *Engine) userName(uid uint32) string {
	if name, ok := e.uidNames[uid]; ok {
		return name
	}
	return strconv.FormatUint(uint64(uid), 10)
}

// groupName resolves a gid against the root's own group database.
func (e *Engine) groupName(gid uint32) string {
	if name, ok := e.gidNames[gid]; ok {
		return name
	}
	return strconv.FormatUint(uint64(gid), 10)
}

// parsePasswd statically parses the root's /etc/passwd. /etc/shadow is never
// opened.
func parsePasswd(fs RootFS) []account {
	f, err := os.Open(fs.Physical("/etc/passwd"))
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []account
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, maxLineBytes), maxLineBytes)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) != 7 {
			continue
		}
		uid, _ := strconv.Atoi(fields[2])
		gid, _ := strconv.Atoi(fields[3])
		out = append(out, account{Name: fields[0], UID: uid, GID: gid, Home: fields[5], Shell: fields[6]})
	}
	return out
}

// parseGroups statically parses the root's /etc/group.
func parseGroups(fs RootFS) []group {
	f, err := os.Open(fs.Physical("/etc/group"))
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []group
	lineNo := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, maxLineBytes), maxLineBytes)
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) != 4 {
			continue
		}
		gid, _ := strconv.Atoi(fields[2])
		members := strings.FieldsFunc(fields[3], func(r rune) bool { return r == ',' || r == ' ' })
		out = append(out, group{Name: fields[0], GID: gid, Members: members, Line: lineNo})
	}
	return out
}

// readTextFile reads a bounded configuration file, returning the contents
// with an error for files that are too large or unreadable. The caller is
// responsible for redacting evidence.
func readTextFile(path string) (string, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", false
	}
	if !fi.Mode().IsRegular() || fi.Size() > maxScanFileBytes {
		return "", false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	return string(data), true
}
