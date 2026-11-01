package kernel

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Package kind classes for installed kernel packages.
const (
	KindImage        = "image"   // ships the bootable kernel image
	KindModules      = "modules" // ships /lib/modules for one release
	KindModulesExtra = "modules-extra"
	KindMeta         = "meta" // metapackage tracking a flavor
	KindOther        = "other"
)

// Provenance quality for an inventory entry.
const (
	// ProvenancePackageDB means the entry came from the distribution
	// package database (dpkg status, apk installed, pacman local) with
	// exact name, version and architecture.
	ProvenancePackageDB = "package-db"
	// ProvenanceFilesystem means the entry was derived from /boot and
	// /lib/modules evidence because the package database is not statically
	// parseable (RPM). Package ownership is reported as UNVERIFIED.
	ProvenanceFilesystem = "filesystem-evidence"
)

// KernelPackage is one installed kernel package or one filesystem-derived
// kernel installation.
type KernelPackage struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	Architecture  string `json:"architecture,omitempty"`
	SourcePackage string `json:"sourcePackage,omitempty"`
	Flavor        string `json:"flavor,omitempty"`
	// KernelRelease is the uname-style release this package installs, when
	// derivable from authoritative naming conventions (dpkg image package
	// names, apk flavor mapping, Arch pkgver mapping, RPM NVR mapping).
	KernelRelease string `json:"kernelRelease,omitempty"`
	Kind          string `json:"kind"`
	Ecosystem     string `json:"ecosystem"`
	Provenance    string `json:"provenance"`
	// Evidence records where the entry was read from.
	Evidence string   `json:"evidence"`
	Notes    []string `json:"notes,omitempty"`
}

// maxDBBytes bounds how much package database text is read per file. The
// parser streams line by line, so memory stays bounded even for large
// databases; the cap protects against pathological files.
const maxDBBytes = 64 << 20 // 64 MiB

// maxPackages caps the inventory size per scan.
const maxPackages = 256

// InventoryInstalledKernels collects installed kernel packages from the
// package database of the scanned root. Entries carry their provenance so
// the caller can downgrade honestly when only filesystem evidence exists.
func InventoryInstalledKernels(root, family, ecosystem string) []KernelPackage {
	var pkgs []KernelPackage
	switch {
	case ecosystem == EcosystemDPKG:
		pkgs = inventoryDPKG(root)
	case ecosystem == EcosystemAPK:
		pkgs = inventoryAPK(root)
	case ecosystem == EcosystemPacman:
		pkgs = inventoryPacman(root)
	case ecosystem == EcosystemRPM:
		pkgs = inventoryRPM(root)
	}
	if len(pkgs) == 0 {
		// Fall back to /boot and /lib/modules evidence so a target with an
		// unreadable or absent package database still reports its kernels,
		// clearly marked as filesystem-derived (never package-owned).
		pkgs = inventoryFromBoot(root, family)
	}
	if len(pkgs) > maxPackages {
		pkgs = pkgs[:maxPackages]
	}
	sort.SliceStable(pkgs, func(i, j int) bool {
		if pkgs[i].Name != pkgs[j].Name {
			return pkgs[i].Name < pkgs[j].Name
		}
		return pkgs[i].Version < pkgs[j].Version
	})
	return pkgs
}

// ---------------------------------------------------------------------------
// dpkg (Debian, Ubuntu)
// ---------------------------------------------------------------------------

// inventoryDPKG parses <root>/var/lib/dpkg/status and returns every installed
// kernel image, signed-image, modules and meta package. The Debian "Source:"
// field is used verbatim as the source package when present.
func inventoryDPKG(root string) []KernelPackage {
	f, err := os.Open(filepath.Join(root, "/var/lib/dpkg/status"))
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []KernelPackage
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<16), maxDBBytes)
	var rec map[string]string
	flush := func() {
		if rec == nil {
			return
		}
		if p, ok := dpkgKernelPackage(rec); ok {
			if len(out) < maxPackages*4 {
				out = append(out, p)
			}
		}
		rec = nil
	}
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			flush()
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			continue // continuation lines are not needed for kernel identity
		}
		if i := strings.IndexByte(line, ':'); i > 0 {
			if rec == nil {
				rec = make(map[string]string, 8)
			}
			rec[line[:i]] = strings.TrimSpace(line[i+1:])
		}
	}
	flush()
	return out
}

// dpkgKernelPackage converts one dpkg status record into a KernelPackage.
func dpkgKernelPackage(rec map[string]string) (KernelPackage, bool) {
	name := rec["Package"]
	if name == "" {
		return KernelPackage{}, false
	}
	// Only installed packages count; "deinstall ok config-files" leftovers
	// would fabricate an inventory of packages that are not installed.
	status := rec["Status"]
	if status != "" && !strings.Contains(status, "installed") {
		return KernelPackage{}, false
	}
	if status == "" {
		// A record without a status field is unusual; keep it but flag it.
		// The Notes field tells the caller the state was not confirmed.
	}
	kind, ok := dpkgKernelKind(name)
	if !ok {
		return KernelPackage{}, false
	}
	p := KernelPackage{
		Name:         name,
		Version:      rec["Version"],
		Architecture: rec["Architecture"],
		Kind:         kind,
		Ecosystem:    EcosystemDPKG,
		Provenance:   ProvenancePackageDB,
		Evidence:     "/var/lib/dpkg/status",
	}
	if src := rec["Source"]; src != "" {
		// "Source: linux-signed (6.1.0-1)" -> name without version.
		if i := strings.IndexByte(src, ' '); i > 0 {
			p.SourcePackage = src[:i]
		} else {
			p.SourcePackage = src
		}
	}
	p.Flavor = FlavorFromDpkgName(name)
	p.KernelRelease = dpkgKernelRelease(name)
	if status == "" {
		p.Notes = append(p.Notes, "dpkg record has no Status field; install state unconfirmed")
	}
	return p, true
}

// dpkgKernelKind classifies a Debian/Ubuntu kernel package name.
func dpkgKernelKind(name string) (string, bool) {
	switch {
	case strings.HasPrefix(name, "linux-image-unsigned-"):
		return KindImage, true
	case strings.HasPrefix(name, "linux-image-"):
		rest := strings.TrimPrefix(name, "linux-image-")
		if isDpkgVersionedRelease(rest) {
			return KindImage, true
		}
		return KindMeta, true
	case strings.HasPrefix(name, "linux-modules-extra-"), strings.HasPrefix(name, "linux-image-extra-"):
		return KindModulesExtra, true
	case strings.HasPrefix(name, "linux-modules-iwlwifi-"),
		strings.HasPrefix(name, "linux-modules-nvidia-"),
		strings.HasPrefix(name, "linux-modules-ipu6-"),
		strings.HasPrefix(name, "linux-modules-ivsc-"):
		// Driver module packages ship no core modules; still report as
		// modules-kind for inventory completeness.
		return KindModules, true
	case strings.HasPrefix(name, "linux-modules-"):
		return KindModules, true
	case name == "linux-image-generic", strings.HasPrefix(name, "linux-image-cloud-"),
		strings.HasPrefix(name, "linux-image-virtual"), strings.HasPrefix(name, "linux-image-lowlatency"),
		strings.HasPrefix(name, "linux-image-aws"), strings.HasPrefix(name, "linux-image-azure"),
		strings.HasPrefix(name, "linux-image-gcp"), strings.HasPrefix(name, "linux-image-oracle"),
		strings.HasPrefix(name, "linux-image-rt"), strings.HasPrefix(name, "linux-image-kvm"),
		strings.HasPrefix(name, "linux-image-raspi"):
		return KindMeta, true
	}
	return "", false
}

// isDpkgVersionedRelease reports whether the suffix of a Debian/Ubuntu
// kernel package name embeds a real kernel release: it must start with a
// numeric upstream version ("6.1.0-18-..."), not a flavor word ("generic",
// "cloud-amd64"). This keeps metapackages out of the release mapping.
func isDpkgVersionedRelease(rest string) bool {
	dash := strings.IndexByte(rest, '-')
	if dash <= 0 {
		return false
	}
	upstream := rest[:dash]
	hasDigit := false
	for i := 0; i < len(upstream); i++ {
		c := upstream[i]
		switch {
		case c >= '0' && c <= '9':
			hasDigit = true
		case c == '.':
		default:
			return false // flavor words never parse as versions
		}
	}
	if !hasDigit {
		return false
	}
	abi := rest[dash+1:]
	return abi != "" && abi[0] >= '0' && abi[0] <= '9'
}

// dpkgKernelRelease derives the uname-style release from a versioned Debian
// kernel package name: linux-image-6.1.0-18-amd64 -> 6.1.0-18-amd64,
// linux-image-unsigned-6.8.0-40-generic -> 6.8.0-40-generic,
// linux-modules-extra-6.1.0-18-amd64 -> 6.1.0-18-amd64.
func dpkgKernelRelease(name string) string {
	rest := name
	for _, prefix := range []string{
		"linux-image-unsigned-", "linux-modules-extra-", "linux-modules-", "linux-image-",
	} {
		if strings.HasPrefix(rest, prefix) {
			rest = strings.TrimPrefix(rest, prefix)
			break
		}
	}
	if rest == name || !isDpkgVersionedRelease(rest) {
		return "" // metapackage: no embedded release
	}
	return rest
}

// ---------------------------------------------------------------------------
// apk (Alpine)
// ---------------------------------------------------------------------------

// inventoryAPK parses <root>/lib/apk/db/installed for Alpine kernel flavor
// packages (linux-lts, linux-virt, linux-edge, linux-rpi...).
func inventoryAPK(root string) []KernelPackage {
	f, err := os.Open(filepath.Join(root, "/lib/apk/db/installed"))
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []KernelPackage
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<16), maxDBBytes)
	rec := make(map[string]string)
	flush := func() {
		if p, ok := apkKernelPackage(rec); ok {
			if len(out) < maxPackages*4 {
				out = append(out, p)
			}
		}
		rec = make(map[string]string)
	}
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			flush()
			continue
		}
		if len(line) > 2 && line[1] == ':' {
			key := string(line[0])
			val := line[2:]
			if _, exists := rec[key]; !exists || key == "P" || key == "V" || key == "A" {
				rec[key] = val
			}
		}
	}
	flush()
	return out
}

// apkKernelPackage converts one apk installed record into a KernelPackage.
func apkKernelPackage(rec map[string]string) (KernelPackage, bool) {
	name := rec["P"]
	version := rec["V"]
	if name == "" || version == "" {
		return KernelPackage{}, false
	}
	flavor, ok := apkKernelFlavor(name)
	if !ok {
		return KernelPackage{}, false
	}
	p := KernelPackage{
		Name:          name,
		Version:       version,
		Architecture:  rec["A"],
		SourcePackage: name,
		Flavor:        flavor,
		Kind:          KindImage,
		Ecosystem:     EcosystemAPK,
		Provenance:    ProvenancePackageDB,
		Evidence:      "/lib/apk/db/installed",
	}
	// Alpine kernel package version "6.6.58-r0" installs modules under
	// "6.6.58-0-lts": uname release = <pkgver>-<pkgrel>-<flavor>.
	if pkgver, pkgrel, okRel := strings.Cut(version, "-r"); okRel {
		if _, err := strconv.Atoi(pkgrel); err == nil {
			p.KernelRelease = pkgver + "-" + pkgrel + "-" + flavor
		}
	}
	return p, true
}

// apkKernelFlavor classifies Alpine kernel package names.
func apkKernelFlavor(name string) (string, bool) {
	switch name {
	case "linux-lts":
		return "lts", true
	case "linux-virt":
		return "virt", true
	case "linux-edge":
		return "edge", true
	case "linux-lts-dev":
		return "lts", true
	case "linux-rpi", "linux-rpi4", "linux-rpi2":
		return "rpi", true
	case "linux-xiaomi-elish", "linux-samsung-a52q":
		// Device-specific community kernels: still kernel packages.
		return strings.TrimPrefix(name, "linux-"), true
	}
	if strings.HasPrefix(name, "linux-") && name != "linux-firmware-none" {
		rest := strings.TrimPrefix(name, "linux-")
		if rest != "" && !strings.Contains(rest, "firmware") && !strings.Contains(rest, "headers") {
			return rest, true
		}
	}
	return "", false
}

// ---------------------------------------------------------------------------
// pacman (Arch)
// ---------------------------------------------------------------------------

// inventoryPacman parses <root>/var/lib/pacman/local/*/desc for Arch kernel
// packages (linux, linux-lts, linux-zen, linux-hardened).
func inventoryPacman(root string) []KernelPackage {
	localDir := filepath.Join(root, "/var/lib/pacman/local")
	entries, err := os.ReadDir(localDir)
	if err != nil {
		return nil
	}
	var out []KernelPackage
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		desc, ok := parsePacmanDesc(filepath.Join(localDir, entry.Name(), "desc"))
		if !ok {
			continue
		}
		name := desc["NAME"]
		version := desc["VERSION"]
		if name == "" || version == "" {
			continue
		}
		flavor, ok := pacmanKernelFlavor(name)
		if !ok {
			continue
		}
		p := KernelPackage{
			Name:          name,
			Version:       version,
			Architecture:  desc["ARCH"],
			SourcePackage: name,
			Flavor:        flavor,
			Kind:          KindImage,
			Ecosystem:     EcosystemPacman,
			Provenance:    ProvenancePackageDB,
			Evidence:      "/var/lib/pacman/local/" + entry.Name() + "/desc",
		}
		p.KernelRelease = pacmanKernelRelease(version)
		if len(out) < maxPackages*4 {
			out = append(out, p)
		}
	}
	return out
}

// parsePacmanDesc reads a pacman local database desc file. The format is
// "%SECTION%" headers followed by the section values, one per line; NAME,
// VERSION and ARCH appear as their own sections.
func parsePacmanDesc(path string) (map[string]string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	out := make(map[string]string)
	section := ""
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "%") && strings.HasSuffix(line, "%") {
			section = strings.Trim(line, "%")
			continue
		}
		if section == "" {
			continue
		}
		if _, exists := out[section]; !exists {
			out[section] = line
		}
	}
	return out, len(out) > 0
}

// pacmanKernelFlavor classifies Arch kernel package names.
func pacmanKernelFlavor(name string) (string, bool) {
	switch name {
	case "linux":
		return "default", true
	case "linux-lts":
		return "lts", true
	case "linux-zen":
		return "zen", true
	case "linux-hardened":
		return "hardened", true
	case "linux-rt", "linux-rt-lts":
		return "rt", true
	}
	return "", false
}

// pacmanKernelRelease derives the uname release from an Arch package
// version: "6.6.2.arch1-1" -> "6.6.2-arch1-1" (upstream digits, then the
// Arch suffix with '.' replaced by '-', then the pkgrel).
func pacmanKernelRelease(version string) string {
	pkgver, pkgrel, ok := strings.Cut(version, "-")
	if !ok {
		return ""
	}
	// Find the Arch suffix: the first ".<letter>" boundary after the
	// numeric upstream version ("6.6.2.arch1" -> "6.6.2", "arch1").
	i := 0
	dots := 0
	for ; i < len(pkgver); i++ {
		if pkgver[i] == '.' {
			dots++
			if dots >= 3 && i+1 < len(pkgver) && isLetterByte(pkgver[i+1]) {
				break
			}
		} else if !isDigitByte(pkgver[i]) && pkgver[i] != '.' {
			// Non-standard pkgver: refuse to guess the release mapping.
			return ""
		}
	}
	if i >= len(pkgver) {
		// Pure numeric pkgver ("6.6.2"): release is verbatim plus pkgrel.
		return pkgver + "-" + pkgrel
	}
	upstream := pkgver[:i]
	suffix := strings.ReplaceAll(pkgver[i+1:], ".", "-")
	if upstream == "" || suffix == "" {
		return ""
	}
	return upstream + "-" + suffix + "-" + pkgrel
}

func isLetterByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isDigitByte(c byte) bool { return c >= '0' && c <= '9' }

// ---------------------------------------------------------------------------
// rpm (RHEL, Fedora, Rocky, AlmaLinux, SUSE)
// ---------------------------------------------------------------------------

// inventoryRPM inventories kernels on RPM systems. The RPM database itself
// (BerkeleyDB or sqlite with embedded rpm headers) is not statically
// parseable without the rpm tooling, so provenance comes from /boot and
// /lib/modules and is marked filesystem-evidence. The spec explicitly
// directs RONDA to report such matching as UNVERIFIED instead of guessing
// package ownership.
func inventoryRPM(root string) []KernelPackage {
	pkgs := inventoryFromBoot(root, FamilyRHEL)
	for i := range pkgs {
		pkgs[i].Ecosystem = EcosystemRPM
		pkgs[i].Notes = append(pkgs[i].Notes,
			"RPM database not statically parseable; package ownership UNVERIFIED (kernel release derived from /boot and /lib/modules)")
	}
	return pkgs
}

// inventoryFromBoot derives kernel installations from /boot/vmlinuz-* and
// /lib/modules/* directory names. It never opens or inspects the kernel
// image itself.
func inventoryFromBoot(root, family string) []KernelPackage {
	seen := make(map[string]bool)
	var out []KernelPackage
	add := func(name, release string, evidence string) {
		if release == "" || seen[release] || len(out) >= maxPackages {
			return
		}
		seen[release] = true
		flavor := FlavorFromRelease(release)
		p := KernelPackage{
			Name:          name,
			KernelRelease: release,
			Flavor:        flavor,
			Kind:          KindImage,
			Provenance:    ProvenanceFilesystem,
			Evidence:      evidence,
		}
		if family == FamilyRHEL {
			// uname release "5.14.0-427.13.1.el9_4.x86_64" maps to the RPM
			// NVR version-release "5.14.0-427.13.1.el9_4" for the "kernel"
			// source package. Mapping is evidence-based, never claimed as
			// package ownership.
			p.Name = "kernel"
			p.Version = rpmNVRFromRelease(release)
			p.Architecture = rpmArchFromRelease(release)
			p.Ecosystem = EcosystemRPM
			p.SourcePackage = "kernel"
			p.Kind = KindImage
		}
		if p.Version == "" {
			p.Version = release
		}
		out = append(out, p)
	}
	bootDir := filepath.Join(root, "/boot")
	if entries, err := os.ReadDir(bootDir); err == nil {
		for _, e := range entries {
			if e.IsDir() || !strings.HasPrefix(e.Name(), "vmlinuz-") {
				continue
			}
			add("vmlinuz", strings.TrimPrefix(e.Name(), "vmlinuz-"), "/boot/"+e.Name())
		}
	}
	modDir := filepath.Join(root, "/lib/modules")
	if entries, err := os.ReadDir(modDir); err == nil {
		for _, e := range entries {
			if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			add("modules", e.Name(), "/lib/modules/"+e.Name())
		}
	}
	return out
}

// rpmNVRFromRelease strips the trailing architecture from a uname release:
// "5.14.0-427.13.1.el9_4.x86_64" -> "5.14.0-427.13.1.el9_4".
func rpmNVRFromRelease(release string) string {
	if i := strings.LastIndexByte(release, '.'); i > 0 {
		last := release[i+1:]
		switch last {
		case "x86_64", "i686", "i386", "aarch64", "armv7hl", "ppc64le", "s390x", "riscv64":
			return release[:i]
		}
	}
	return release
}

// rpmArchFromRelease extracts the trailing architecture of a uname release.
func rpmArchFromRelease(release string) string {
	if i := strings.LastIndexByte(release, '.'); i > 0 {
		last := release[i+1:]
		switch last {
		case "x86_64", "i686", "i386", "aarch64", "armv7hl", "ppc64le", "s390x", "riscv64":
			return last
		}
	}
	return ""
}
