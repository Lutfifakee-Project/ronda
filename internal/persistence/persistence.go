package persistence

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Lutfifakee-Project/ronda/internal/finding"
)

// Engine carries one persistence scan's shared state: the selected root,
// static account databases, the referenced-target cache and collected
// references for correlation.
type Engine struct {
	fs     RootFS
	ctx    context.Context
	users  []account
	groups []group

	uidNames map[uint32]string
	gidNames map[uint32]string

	targets map[string]*TargetInfo
	refs    []targetRef
	refSeen map[string]bool

	findings []finding.Finding
	seen     map[string]bool

	denied     []string
	unverified []string
	notes      []string

	distro    string
	packageDB string // "", "dpkg", "apk", "rpm"
}

// targetRef records that a persistence artifact references a target path.
// Mechanism is the artifact family (systemd, cron, ssh, shell, ldso, pam,
// kmod, udev, account).
type targetRef struct {
	Target     string
	Mechanism  string
	Artifact   string
	Line       int
	Rule       string
	Suspicious bool
}

// Report is the outcome of a persistence scan.
type Report struct {
	Root               string
	LiveHost           bool
	Distribution       string
	PackageDB          string
	InitSystems        []string
	Findings           []finding.Finding
	ArtifactsInspected int
	TargetsInspected   int
	Denied             []string
	Unverified         []string
	Notes              []string
	DeniedCount        int
	UnverifiedCount    int
}

// newEngine prepares the shared state. Account databases are read from the
// scanned root itself so offline roots resolve their own user names.
func newEngine(ctx context.Context, fs RootFS) *Engine {
	e := &Engine{
		fs:       fs,
		ctx:      ctx,
		targets:  make(map[string]*TargetInfo),
		seen:     make(map[string]bool),
		refSeen:  make(map[string]bool),
		uidNames: make(map[uint32]string),
		gidNames: make(map[uint32]string),
	}
	e.users = parsePasswd(fs)
	e.groups = parseGroups(fs)
	for _, u := range e.users {
		if _, ok := e.uidNames[uint32(u.UID)]; !ok {
			e.uidNames[uint32(u.UID)] = u.Name
		}
	}
	for _, g := range e.groups {
		if _, ok := e.gidNames[uint32(g.GID)]; !ok {
			e.gidNames[uint32(g.GID)] = g.Name
		}
	}
	e.distro = detectDistro(fs)
	e.packageDB = detectPackageDB(fs)
	return e
}

// detectDistro reads NAME= from the root's os-release files.
func detectDistro(fs RootFS) string {
	for _, p := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		data, ok := readTextFile(fs.Physical(p))
		if !ok {
			continue
		}
		for _, ln := range strings.Split(data, "\n") {
			ln = strings.TrimSpace(ln)
			if strings.HasPrefix(ln, "NAME=") {
				return strings.Trim(strings.TrimPrefix(ln, "NAME="), `"'`)
			}
		}
	}
	return ""
}

// detectPackageDB identifies the package database available for provenance
// without executing any package manager.
func detectPackageDB(fs RootFS) string {
	if dirOK(fs.Physical("/var/lib/dpkg/info")) {
		return "dpkg"
	}
	if fileOK(fs.Physical("/lib/apk/db/installed")) {
		return "apk"
	}
	if dirOK(fs.Physical("/var/lib/rpm")) || dirOK(fs.Physical("/usr/lib/sysimage/rpm")) {
		return "rpm"
	}
	return ""
}

func dirOK(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

func fileOK(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

// canceled reports whether the caller canceled the scan.
func (e *Engine) canceled() bool { return e.ctx != nil && e.ctx.Err() != nil }

// add appends a finding, filling category and MITRE from the rule registry
// and dropping exact duplicates (same rule, artifact, line and target).
func (e *Engine) add(f finding.Finding) {
	if m, ok := RuleMetadata(f.Rule); ok {
		if f.Category == "" {
			f.Category = m.Category
		}
		if len(f.MITRE) == 0 {
			f.MITRE = m.MITRE
		}
	}
	key := f.Rule + "|" + f.Path + "|" + fmt.Sprint(f.Line) + "|" + f.Target
	if e.seen[key] {
		return
	}
	e.seen[key] = true
	e.findings = append(e.findings, f)
}

// note records a scan-scope observation.
func (e *Engine) note(msg string) { e.notes = append(e.notes, msg) }

// deny records an artifact location that exists but could not be read, so
// reports never present unreadable persistence locations as clean.
func (e *Engine) deny(logical string, reason string) {
	e.denied = append(e.denied, logical+": "+reason)
}

// unverifiedScope records a scope the engine could not inspect reliably.
func (e *Engine) unverifiedScope(logical, reason string) {
	e.unverified = append(e.unverified, logical+": "+reason)
}

// reference records a cross-artifact reference for correlation.
func (e *Engine) reference(target, mechanism, artifact string, line int, rule string, suspicious bool) {
	if strings.TrimSpace(target) == "" {
		return
	}
	// One source line yields one reference: exact duplicates (same
	// target, mechanism, artifact, line, rule, suspicion) are suppressed
	// so correlation evidence stays clean and memory stays bounded.
	key := mechanism + "|" + artifact + "|" + fmt.Sprint(line) + "|" + rule + "|" + fmt.Sprint(suspicious)
	if e.refSeen[key] {
		return
	}
	e.refSeen[key] = true
	e.refs = append(e.refs, targetRef{
		Target:     filepath.Clean("/" + strings.TrimSpace(target)),
		Mechanism:  mechanism,
		Artifact:   artifact,
		Line:       line,
		Rule:       rule,
		Suspicious: suspicious,
	})
}

// artifactLines reads a bounded text artifact and returns its lines with
// 1-based numbers. Unreadable existing files are recorded as denied.
func (e *Engine) artifactLines(logical string) ([]string, bool, bool) {
	phys, contained := e.fs.resolve(logical)
	if !contained {
		e.unverifiedScope(logical, "symlink resolves outside the scanned root")
		return nil, false, false
	}
	f, err := os.Open(phys)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, false // absent: a normal condition for optional artifacts
		}
		e.deny(logical, err.Error())
		return nil, false, false
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		e.deny(logical, err.Error())
		return nil, false, true
	}
	if !fi.Mode().IsRegular() {
		return nil, false, false
	}
	if fi.Size() > maxScanFileBytes {
		e.unverifiedScope(logical, fmt.Sprintf("file exceeds %d bytes inspection limit", maxScanFileBytes))
		return nil, false, true
	}
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, maxLineBytes), maxLineBytes)
	for sc.Scan() {
		lines = append(lines, sc.Text())
		if len(lines) >= 65536 {
			e.unverifiedScope(logical, "file exceeds 65536-line inspection limit")
			break
		}
	}
	return lines, true, true
}

// artifactStat captures owner/perms/mtime of an artifact for finding
// metadata.
func (e *Engine) artifactStat(logical string) (owner, group, perms, modified string) {
	ti := e.InspectTarget(logical)
	return ti.Owner, ti.Group, ti.Mode, ti.ModifiedUTC
}

// userByName finds a static account by name.
func (e *Engine) userByName(name string) (account, bool) {
	for _, u := range e.users {
		if u.Name == name {
			return u, true
		}
	}
	return account{}, false
}

// userByHome finds the account whose home directory matches the path
// (logical or physical normalized to logical).
func (e *Engine) userByHome(logicalHome string) (account, bool) {
	logicalHome = filepath.Clean("/" + strings.TrimSpace(logicalHome))
	for _, u := range e.users {
		if u.Home != "" && filepath.Clean("/"+u.Home) == logicalHome {
			return u, true
		}
	}
	return account{}, false
}

// adminUsers are cloud/distribution default accounts whose passwordless
// sudo is a design decision, not an anomaly.
var adminUsers = []string{
	"ubuntu", "ec2-user", "debian", "admin", "cloud-user", "vagrant",
	"almalinux", "rocky", "fedora", "opc", "azureuser", "garsecur", "core",
}

// Scan runs every persistence analyzer against the selected root and
// returns the correlated report. No analyzer executes anything.
func Scan(ctx context.Context, root string) Report {
	fs := NewRootFS(root)
	e := newEngine(ctx, fs)

	// Artifact analyses. Each is bounded and independent.
	e.analyzeSystemd()
	if e.canceled() {
		return e.report(fs)
	}
	e.analyzeCron()
	if e.canceled() {
		return e.report(fs)
	}
	e.analyzeSSH()
	if e.canceled() {
		return e.report(fs)
	}
	e.analyzeShellStartup()
	if e.canceled() {
		return e.report(fs)
	}
	e.analyzeLinker()
	if e.canceled() {
		return e.report(fs)
	}
	e.analyzePAM()
	if e.canceled() {
		return e.report(fs)
	}
	e.analyzeKernelModules()
	if e.canceled() {
		return e.report(fs)
	}
	e.analyzeUdev()
	if e.canceled() {
		return e.report(fs)
	}
	e.analyzeAccounts()
	if e.canceled() {
		return e.report(fs)
	}

	// Provenance pass, then target-level findings, then correlation.
	e.resolveProvenance()
	e.analyzeTargets()
	e.correlate()

	return e.report(fs)
}

// report assembles the final Report with deterministic ordering.
func (e *Engine) report(fs RootFS) Report {
	sort.Strings(e.denied)
	sort.Strings(e.unverified)
	sort.Strings(e.notes)
	finding.Sort(e.findings)

	inits := detectInitSystems(fs)
	return Report{
		Root:               fs.Root(),
		LiveHost:           fs.LiveHost(),
		Distribution:       e.distro,
		PackageDB:          e.packageDB,
		InitSystems:        inits,
		Findings:           e.findings,
		ArtifactsInspected: e.artifactCount(),
		TargetsInspected:   len(e.targets),
		Denied:             e.denied,
		Unverified:         e.unverified,
		Notes:              e.notes,
		DeniedCount:        len(e.denied),
		UnverifiedCount:    len(e.unverified),
	}
}

// artifactCount reports how many distinct artifact files were parsed.
func (e *Engine) artifactCount() int {
	seen := make(map[string]bool, len(e.refs))
	n := 0
	for _, f := range e.findings {
		if f.Path != "" && !seen[f.Path] {
			seen[f.Path] = true
			n++
		}
	}
	return n
}

// detectInitSystems records which init systems the root appears to use.
func detectInitSystems(fs RootFS) []string {
	var out []string
	if dirOK(fs.Physical("/run/systemd/system")) || dirOK(fs.Physical("/etc/systemd/system")) || dirOK(fs.Physical("/usr/lib/systemd/system")) {
		out = append(out, "systemd")
	}
	if fileOK(fs.Physical("/sbin/openrc")) || dirOK(fs.Physical("/etc/runlevels")) {
		out = append(out, "openrc")
	}
	if dirOK(fs.Physical("/etc/init.d")) {
		out = append(out, "sysvinit")
	}
	if dirOK(fs.Physical("/etc/cron.d")) || fileOK(fs.Physical("/etc/crontab")) || dirOK(fs.Physical("/var/spool/cron")) {
		out = append(out, "cron")
	}
	return out
}

// HasActionable reports whether any persistence finding needs review.
func (r Report) HasActionable() bool {
	for _, f := range r.Findings {
		if f.Severity.Rank() >= finding.Low.Rank() {
			return true
		}
	}
	return false
}
