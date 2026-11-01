// Package kernel performs a read-only audit of Linux kernel identity and
// installed kernel packages.
//
// Phase 6 scope: distribution and release identification, running kernel
// detection on live hosts, static installed-kernel-package inventory across
// dpkg, apk, rpm and pacman metadata, kernel flavor classification and an
// evidence-based pending-reboot assessment. CVE intelligence lives in
// internal/kernelintel; this package never consults vulnerability feeds and
// never claims a kernel is patched or vulnerable on its own.
//
// RONDA never executes package managers, uname, systemctl or any external
// utility, never modifies the system and never reads kernel images: only
// static metadata files and the procfs interfaces a container can read.
package kernel

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// Ecosystem names the package manager metadata family a distribution uses.
const (
	EcosystemDPKG   = "dpkg"
	EcosystemRPM    = "rpm"
	EcosystemAPK    = "apk"
	EcosystemPacman = "pacman"
)

// Family groups distributions that share kernel packaging conventions.
const (
	FamilyDebian = "debian"
	FamilyRHEL   = "rhel"
	FamilySUSE   = "suse"
	FamilyArch   = "arch"
	FamilyAlpine = "alpine"
)

// Lifecycle states for the distribution release.
const (
	// LifecycleSupported means the release is inside its published regular
	// security support window in the static knowledge table.
	LifecycleSupported = "supported"
	// LifecycleExtended means regular support ended but the vendor operates
	// a published extended security program (Debian LTS, Ubuntu ESM) for the
	// release. Ubuntu ESM additionally needs a subscription, which RONDA
	// cannot verify: output always discloses this.
	LifecycleExtended = "extended-security-support"
	// LifecycleEOL means the published support window has ended according to
	// the static knowledge table. Vendor security maintenance may have
	// stopped: this is disclosed, never used to claim safety.
	LifecycleEOL = "eol"
	// LifecycleRolling means a rolling release (Arch, openSUSE Tumbleweed).
	LifecycleRolling = "rolling"
	// LifecycleUnknown means the static knowledge table has no reliable
	// entry for the release. It is never interpreted as supported.
	LifecycleUnknown = "unknown"
)

// OSRelease is the statically identified distribution of a scanned root.
type OSRelease struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	VersionID string   `json:"versionId"`
	Codename  string   `json:"codename,omitempty"`
	IDLike    []string `json:"idLike,omitempty"`
	Ecosystem string   `json:"ecosystem,omitempty"`
	Family    string   `json:"family,omitempty"`
	// Derivative reports whether the ID was not in the known distribution
	// table and family/ecosystem were derived from ID_LIKE.
	Derivative bool   `json:"derivative,omitempty"`
	Source     string `json:"source,omitempty"`
	// Lifecycle is one of the Lifecycle* constants.
	Lifecycle string `json:"lifecycle"`
	// LifecycleBasis names the vendor-published fact or policy behind
	// the lifecycle classification; empty when unknown.
	LifecycleBasis string   `json:"lifecycleBasis,omitempty"`
	Notes          []string `json:"notes,omitempty"`
}

// Known ecosystems by distribution ID. IDs are the lowercase os-release ID.
var knownDistributions = map[string]struct {
	family    string
	ecosystem string
}{
	"debian":              {FamilyDebian, EcosystemDPKG},
	"ubuntu":              {FamilyDebian, EcosystemDPKG},
	"linuxmint":           {FamilyDebian, EcosystemDPKG},
	"kali":                {FamilyDebian, EcosystemDPKG},
	"devuan":              {FamilyDebian, EcosystemDPKG},
	"raspbian":            {FamilyDebian, EcosystemDPKG},
	"rhel":                {FamilyRHEL, EcosystemRPM},
	"redhat":              {FamilyRHEL, EcosystemRPM},
	"fedora":              {FamilyRHEL, EcosystemRPM},
	"rocky":               {FamilyRHEL, EcosystemRPM},
	"almalinux":           {FamilyRHEL, EcosystemRPM},
	"centos":              {FamilyRHEL, EcosystemRPM},
	"ol":                  {FamilyRHEL, EcosystemRPM},
	"amzn":                {FamilyRHEL, EcosystemRPM},
	"sles":                {FamilySUSE, EcosystemRPM},
	"sle-micro":           {FamilySUSE, EcosystemRPM},
	"opensuse-leap":       {FamilySUSE, EcosystemRPM},
	"opensuse-tumbleweed": {FamilySUSE, EcosystemRPM},
	"opensuse":            {FamilySUSE, EcosystemRPM},
	"arch":                {FamilyArch, EcosystemPacman},
	"manjaro":             {FamilyArch, EcosystemPacman},
	"endeavouros":         {FamilyArch, EcosystemPacman},
	"garuda":              {FamilyArch, EcosystemPacman},
	"alpine":              {FamilyAlpine, EcosystemAPK},
}

// familyFromIDLike resolves a family for unknown derivative distributions by
// looking at their ID_LIKE list, most specific first.
func familyFromIDLike(idLike []string) (family, ecosystem string) {
	// Alpine first: its ecosystem is distinctive.
	for _, like := range idLike {
		if like == "alpine" {
			return FamilyAlpine, EcosystemAPK
		}
	}
	for _, like := range idLike {
		if like == "arch" || like == "archlinux" {
			return FamilyArch, EcosystemPacman
		}
	}
	for _, like := range idLike {
		switch like {
		case "debian", "ubuntu":
			return FamilyDebian, EcosystemDPKG
		case "rhel", "fedora", "centos", "rhel-fedora":
			return FamilyRHEL, EcosystemRPM
		case "suse", "sles", "opensuse":
			return FamilySUSE, EcosystemRPM
		}
	}
	return "", ""
}

// DetectOSRelease statically identifies the distribution of the scanned
// root. It reads /etc/os-release first and /usr/lib/os-release as fallback,
// per the freedesktop specification. When the ID is unknown the family and
// ecosystem are derived from ID_LIKE and flagged as a derivative.
func DetectOSRelease(root string) OSRelease {
	out := OSRelease{Lifecycle: LifecycleUnknown}
	for _, loc := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		fields, ok := parseOSReleaseFile(root, loc)
		if !ok {
			continue
		}
		out.Source = loc
		out.ID = strings.ToLower(strings.TrimSpace(fields["ID"]))
		out.Name = strings.TrimSpace(fields["NAME"])
		out.VersionID = strings.TrimSpace(fields["VERSION_ID"])
		out.Codename = strings.TrimSpace(fields["VERSION_CODENAME"])
		if out.Codename == "" {
			out.Codename = codenameFromVersion(fields["VERSION"])
		}
		out.IDLike = nil
		for _, like := range strings.FieldsFunc(fields["ID_LIKE"], func(r rune) bool {
			return r == ' ' || r == '\t'
		}) {
			like = strings.ToLower(strings.TrimSpace(like))
			if like != "" {
				out.IDLike = append(out.IDLike, like)
			}
		}
		break
	}
	if out.ID == "" {
		out.Notes = append(out.Notes, "no readable os-release: distribution UNVERIFIED")
		return out
	}

	if known, ok := knownDistributions[out.ID]; ok {
		out.Family = known.family
		out.Ecosystem = known.ecosystem
	} else if len(out.IDLike) > 0 {
		out.Family, out.Ecosystem = familyFromIDLike(out.IDLike)
		out.Derivative = out.Family != ""
		if out.Derivative {
			out.Notes = append(out.Notes,
				"unknown distribution ID "+out.ID+"; family derived from ID_LIKE ("+
					strings.Join(out.IDLike, ", ")+")")
		} else {
			out.Notes = append(out.Notes,
				"unknown distribution ID "+out.ID+" with unrecognized ID_LIKE; ecosystem UNVERIFIED")
		}
	} else {
		out.Notes = append(out.Notes,
			"unknown distribution ID "+out.ID+" without ID_LIKE; ecosystem UNVERIFIED")
	}
	out.Lifecycle, out.LifecycleBasis = classifyLifecycle(out.ID, out.VersionID)
	return out
}

// codenameFromVersion extracts a codename from a VERSION line such as
// "12 (bookworm)" when VERSION_CODENAME is missing.
func codenameFromVersion(version string) string {
	version = strings.TrimSpace(version)
	if i := strings.IndexByte(version, '('); i >= 0 {
		if j := strings.IndexByte(version[i:], ')'); j > 0 {
			return strings.TrimSpace(version[i+1 : i+j])
		}
	}
	return ""
}

// parseOSReleaseFile parses KEY=VALUE lines from one os-release location.
func parseOSReleaseFile(root, location string) (map[string]string, bool) {
	f, err := os.Open(filepath.Join(root, location))
	if err != nil {
		return nil, false
	}
	defer f.Close()
	fields := make(map[string]string)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 64<<10)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		val = strings.Trim(val, "\"'")
		fields[key] = val
	}
	return fields, len(fields) > 0
}

// lifecycleEntry records vendor-published support facts for one release:
// the end of regular security maintenance and, where a published extended
// program exists, the end of that program. Month values are 1-12 and mean
// "support ended before this month begins" (e.g. year 2025 month 6 = the
// May 2025 EOL date). Releases not listed classify as unknown, never as
// supported.
type lifecycleEntry struct {
	regularYear, regularMonth   int
	extendedYear, extendedMonth int // 0 when no published program
	policy                      string
}

// lifecycleTable records fixed, vendor-published dates. These are historical
// or formally announced facts; anything uncertain stays out of the table.
var lifecycleTable = map[string]lifecycleEntry{
	// Debian: security team support, then LTS team support (dates published
	// by the Debian security and LTS teams).
	"debian:9": {regularYear: 2020, regularMonth: 8, extendedYear: 2022, extendedMonth: 7,
		policy: "Debian stretch LTS ended 2022-06-30"},
	"debian:10": {regularYear: 2022, regularMonth: 9, extendedYear: 2024, extendedMonth: 7,
		policy: "Debian buster LTS ended 2024-06-30"},
	"debian:11": {regularYear: 2024, regularMonth: 9, extendedYear: 2026, extendedMonth: 9,
		policy: "Debian bullseye LTS ends 2026-08-31"},
	"debian:12": {regularYear: 2026, regularMonth: 7, extendedYear: 2028, extendedMonth: 7,
		policy: "Debian bookworm regular support ended 2026-06-10; LTS until 2028-06-10"},
	// Ubuntu: standard support, then ESM (dates published by Canonical).
	"ubuntu:18.04": {regularYear: 2023, regularMonth: 6, extendedYear: 2028, extendedMonth: 5,
		policy: "Ubuntu 18.04 standard support ended 2023-05-31; ESM until 2028-04 (subscription)"},
	"ubuntu:20.04": {regularYear: 2025, regularMonth: 6, extendedYear: 2030, extendedMonth: 5,
		policy: "Ubuntu 20.04 standard support ended 2025-05-31; ESM until 2030-04 (subscription)"},
	"ubuntu:22.04": {regularYear: 2027, regularMonth: 5, extendedYear: 2032, extendedMonth: 5,
		policy: "Ubuntu 22.04 standard support until 2027-04; ESM until 2032-04 (subscription)"},
	"ubuntu:24.04": {regularYear: 2029, regularMonth: 5, extendedYear: 2034, extendedMonth: 5,
		policy: "Ubuntu 24.04 standard support until 2029-04; ESM until 2034-04 (subscription)"},
	"ubuntu:19.10": {regularYear: 2020, regularMonth: 8, policy: "Ubuntu interim release"},
	"ubuntu:20.10": {regularYear: 2021, regularMonth: 8, policy: "Ubuntu interim release"},
	"ubuntu:21.04": {regularYear: 2022, regularMonth: 2, policy: "Ubuntu interim release"},
	"ubuntu:21.10": {regularYear: 2022, regularMonth: 8, policy: "Ubuntu interim release"},
	"ubuntu:22.10": {regularYear: 2023, regularMonth: 8, policy: "Ubuntu interim release"},
	"ubuntu:23.04": {regularYear: 2024, regularMonth: 2, policy: "Ubuntu interim release"},
	"ubuntu:23.10": {regularYear: 2024, regularMonth: 8, policy: "Ubuntu interim release"},
	"ubuntu:24.10": {regularYear: 2025, regularMonth: 8, policy: "Ubuntu interim release"},
	"ubuntu:25.04": {regularYear: 2026, regularMonth: 2, policy: "Ubuntu interim release"},
	"ubuntu:25.10": {regularYear: 2026, regularMonth: 8, policy: "Ubuntu interim release"},
	// Red Hat Enterprise Linux maintenance support ends (published).
	"rhel:7": {regularYear: 2024, regularMonth: 7, policy: "RHEL 7 maintenance ended 2024-06-30"},
	"rhel:8": {regularYear: 2029, regularMonth: 6, policy: "RHEL 8 maintenance until 2029-05-31"},
	"rhel:9": {regularYear: 2032, regularMonth: 6, policy: "RHEL 9 maintenance until 2032-05-31"},
	// CentOS classic end dates (published).
	"centos:7": {regularYear: 2024, regularMonth: 7, policy: "CentOS 7 ended 2024-06-30"},
	"centos:8": {regularYear: 2021, regularMonth: 13, policy: "CentOS 8 ended 2021-12-31"},
	// Fedora: about 13 months from release (published project policy). The
	// exact day varies, so the classification is month-granular and
	// disclosed as policy-based.
	"fedora:40": {regularYear: 2025, regularMonth: 6, policy: "Fedora 13-month support policy"},
	"fedora:41": {regularYear: 2025, regularMonth: 12, policy: "Fedora 13-month support policy"},
	"fedora:42": {regularYear: 2026, regularMonth: 6, policy: "Fedora 13-month support policy"},
	"fedora:43": {regularYear: 2027, regularMonth: 1, policy: "Fedora 13-month support policy"},
	// Alpine: each stable branch is supported for two years (published
	// project policy), classified month-granular and disclosed as
	// policy-based.
	"alpine:3.17": {regularYear: 2024, regularMonth: 12, policy: "Alpine 2-year branch policy"},
	"alpine:3.18": {regularYear: 2025, regularMonth: 6, policy: "Alpine 2-year branch policy"},
	"alpine:3.19": {regularYear: 2025, regularMonth: 12, policy: "Alpine 2-year branch policy"},
	"alpine:3.20": {regularYear: 2026, regularMonth: 6, policy: "Alpine 2-year branch policy"},
	"alpine:3.21": {regularYear: 2026, regularMonth: 13, policy: "Alpine 2-year branch policy"},
	"alpine:3.22": {regularYear: 2027, regularMonth: 6, policy: "Alpine 2-year branch policy"},
	"alpine:3.23": {regularYear: 2027, regularMonth: 12, policy: "Alpine 2-year branch policy"},
	// openSUSE Leap (announced EOL dates).
	"opensuse-leap:15.4": {regularYear: 2024, regularMonth: 2, policy: "openSUSE Leap 15.4 ended 2024-01-31"},
	"opensuse-leap:15.5": {regularYear: 2025, regularMonth: 1, policy: "openSUSE Leap 15.5 ended 2024-12-31"},
	"opensuse-leap:15.6": {regularYear: 2026, regularMonth: 1, policy: "openSUSE Leap 15.6 ended 2025-12-31"},
}

// classifyLifecycle maps a distribution ID and version to a lifecycle state.
// Rolling releases and anything outside the table stay unknown; unknown is
// never treated as supported.
func classifyLifecycle(id, versionID string) (string, string) {
	if id == "" {
		return LifecycleUnknown, ""
	}
	switch id {
	case "arch", "manjaro", "endeavouros", "garuda", "opensuse-tumbleweed":
		return LifecycleRolling, "rolling release"
	}
	// Point releases like "12.5" or "3.20.3" collapse to the release branch.
	short := versionID
	if parts := strings.Split(versionID, "."); len(parts) > 2 {
		short = strings.Join(parts[:2], ".")
	}
	keys := []string{id + ":" + versionID, id + ":" + short}
	if first := strings.SplitN(versionID, ".", 2)[0]; first != "" && first != short && first != versionID {
		// RHEL-style "9.4" keys on the major release.
		keys = append(keys, id+":"+first)
	}
	for _, key := range keys {
		if e, ok := lifecycleTable[key]; ok {
			nowYear, nowMonth := currentUTC()
			// A release stays supported through the end of its final month.
			supportedThroughYear, supportedThroughMonth := e.regularYear, e.regularMonth-1
			if supportedThroughMonth == 0 {
				supportedThroughYear, supportedThroughMonth = e.regularYear-1, 12
			}
			if nowYear < supportedThroughYear || (nowYear == supportedThroughYear && nowMonth <= supportedThroughMonth) {
				return LifecycleSupported, e.policy
			}
			if e.extendedYear > 0 {
				extThroughYear, extThroughMonth := e.extendedYear, e.extendedMonth-1
				if extThroughMonth == 0 {
					extThroughYear, extThroughMonth = e.extendedYear-1, 12
				}
				if nowYear < extThroughYear || (nowYear == extThroughYear && nowMonth <= extThroughMonth) {
					return LifecycleExtended, e.policy
				}
			}
			return LifecycleEOL, e.policy
		}
	}
	return LifecycleUnknown, ""
}
