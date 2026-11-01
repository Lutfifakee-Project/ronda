package persistence

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// resolveProvenance determines package ownership for every inspected target
// using the package databases available in the scanned root. Package
// managers are never executed; only their static metadata files are read.
//
// Supported statically:
//   - dpkg: <root>/var/lib/dpkg/info/<pkg>.list (one owned path per line)
//   - apk:  <root>/lib/apk/db/installed (F:/R: directory/file pairs)
//
// RPM databases are BerkeleyDB format and not safely parseable without the
// rpm tooling; on RPM systems every target stays TrustUnverified and the
// report notes the limitation honestly.
func (e *Engine) resolveProvenance() {
	if len(e.targets) == 0 {
		return
	}
	// Default trust for every target before provenance applies.
	for _, ti := range e.targets {
		switch {
		case !ti.Accessible && ti.Err != "":
			ti.Trust = TrustInaccessible
		case e.packageDB == "":
			ti.Trust = TrustNoPackageDatabase
		case e.packageDB == "rpm":
			ti.Trust = TrustUnverified
		default:
			ti.Trust = TrustUnverified
		}
	}
	switch e.packageDB {
	case "dpkg":
		e.provenanceDPKG()
		for _, ti := range e.targets {
			if ti.Trust == TrustUnverified {
				// The dpkg file lists were consulted and claim nothing for
				// this path: it is unowned, not merely unverified.
				ti.Trust = TrustUnowned
			}
		}
	case "apk":
		e.provenanceAPK()
		for _, ti := range e.targets {
			if ti.Trust == TrustUnverified {
				ti.Trust = TrustUnowned
			}
		}
	}
	if e.packageDB == "rpm" {
		e.note("RPM database detected but not statically parseable without rpm tooling: package provenance is unavailable and targets stay unverified (never unowned)")
	}
}

// provenanceDPKG scans dpkg .list files. The index is a membership set of
// the logical target paths, so memory stays bounded by the target count and
// not by the size of the package database.
func (e *Engine) provenanceDPKG() {
	infoDir := e.fs.Physical("/var/lib/dpkg/info")
	entries, err := os.ReadDir(infoDir)
	if err != nil {
		e.unverifiedScope("/var/lib/dpkg/info", "dpkg metadata unavailable: "+err.Error())
		return
	}
	if len(entries) > 8192 {
		entries = entries[:8192]
	}
	for _, entry := range entries {
		if e.canceled() {
			return
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".list") {
			continue
		}
		pkg := strings.TrimSuffix(entry.Name(), ".list")
		e.scanDPKGList(filepath.Join(infoDir, entry.Name()), pkg)
	}
}

// scanDPKGList reads one .list file and marks matching targets owned.
func (e *Engine) scanDPKGList(path, pkg string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, maxLineBytes), maxLineBytes)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "/")
		if line == "" {
			continue
		}
		// dpkg file lists store image-relative absolute paths (what the
		// installed system sees) — exactly the logical form the engine
		// uses for both live-host and offline roots.
		if ti, ok := e.targets[filepath.Clean("/"+line)]; ok && ti.Trust == TrustUnverified {
			ti.Package = pkg
			ti.Trust = TrustPackageOwned
		}
	}
}

// provenanceAPK scans the Alpine apk installed database (plain text).
func (e *Engine) provenanceAPK() {
	path := e.fs.Physical("/lib/apk/db/installed")
	f, err := os.Open(path)
	if err != nil {
		e.unverifiedScope("/lib/apk/db/installed", "apk metadata unavailable: "+err.Error())
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, maxLineBytes), maxLineBytes)
	pkg := ""
	dir := ""
	for sc.Scan() {
		if e.canceled() {
			return
		}
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "P:"):
			pkg = strings.TrimPrefix(line, "P:")
		case strings.HasPrefix(line, "F:"):
			dir = strings.TrimPrefix(line, "F:")
		case strings.HasPrefix(line, "R:"):
			name := strings.TrimPrefix(line, "R:")
			if dir != "" && pkg != "" {
				logical := filepath.Clean("/" + dir + "/" + name)
				if ti, ok := e.targets[logical]; ok && ti.Trust == TrustUnverified {
					ti.Package = pkg
					ti.Trust = TrustPackageOwned
				}
			}
		case line == "":
			pkg = ""
			dir = ""
		}
	}
}
