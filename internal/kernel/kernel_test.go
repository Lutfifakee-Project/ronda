package kernel

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// writeRoot materializes a synthetic root filesystem for one test.
func writeRoot(t *testing.T, files map[string]string, dirs []string) string {
	t.Helper()
	root := t.TempDir()
	for dir := range dirs2set(dirs) {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for path, content := range files {
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func dirs2set(dirs []string) map[string]bool {
	out := make(map[string]bool, len(dirs))
	for _, d := range dirs {
		out[d] = true
	}
	return out
}

func TestDetectOSReleaseMatrix(t *testing.T) {
	cases := []struct {
		name      string
		id        string
		versionID string
		codename  string
		idLike    string
		version   string
		wantFam   string
		wantEco   string
		wantDeriv bool
	}{
		{"debian", "debian", "12", "bookworm", "", "", FamilyDebian, EcosystemDPKG, false},
		{"ubuntu", "ubuntu", "24.04", "noble", "", "", FamilyDebian, EcosystemDPKG, false},
		{"fedora", "fedora", "41", "", "", "Fedora Linux 41 (Workstation Edition)", FamilyRHEL, EcosystemRPM, false},
		{"rocky", "rocky", "9.4", "", "", "", FamilyRHEL, EcosystemRPM, false},
		{"almalinux", "almalinux", "9.4", "", "", "", FamilyRHEL, EcosystemRPM, false},
		{"rhel", "rhel", "9.4", "", "", "", FamilyRHEL, EcosystemRPM, false},
		{"alpine", "alpine", "3.20.3", "", "", "", FamilyAlpine, EcosystemAPK, false},
		{"arch", "arch", "rolling", "", "", "Arch Linux", FamilyArch, EcosystemPacman, false},
		{"sles", "sles", "15.5", "", "", "", FamilySUSE, EcosystemRPM, false},
		{"leap", "opensuse-leap", "15.6", "", "", "", FamilySUSE, EcosystemRPM, false},
		{"mint derivative", "linuxmint", "22", "", "ubuntu debian", "", FamilyDebian, EcosystemDPKG, false},
		{"unknown derivative", "mydistro", "1.0", "", "debian", "", FamilyDebian, EcosystemDPKG, true},
		{"unknown no likelike", "mystery", "1.0", "", "", "", "", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			content := "NAME=\"" + c.name + "\"\nID=" + c.id + "\nVERSION_ID=" + c.versionID + "\n"
			if c.codename != "" {
				content += "VERSION_CODENAME=" + c.codename + "\n"
			}
			if c.version != "" {
				content += "VERSION=\"" + c.version + "\"\n"
			}
			if c.idLike != "" {
				content += "ID_LIKE=" + c.idLike + "\n"
			}
			root := writeRoot(t, map[string]string{"/etc/os-release": content}, nil)
			out := DetectOSRelease(root)
			if out.ID != c.id {
				t.Errorf("ID = %q, want %q", out.ID, c.id)
			}
			if out.VersionID != c.versionID {
				t.Errorf("VersionID = %q, want %q", out.VersionID, c.versionID)
			}
			if out.Family != c.wantFam {
				t.Errorf("Family = %q, want %q", out.Family, c.wantFam)
			}
			if out.Ecosystem != c.wantEco {
				t.Errorf("Ecosystem = %q, want %q", out.Ecosystem, c.wantEco)
			}
			if out.Derivative != c.wantDeriv {
				t.Errorf("Derivative = %v, want %v", out.Derivative, c.wantDeriv)
			}
			if out.Source != "/etc/os-release" {
				t.Errorf("Source = %q", out.Source)
			}
		})
	}
}

func TestDetectOSReleaseFallbackAndCodename(t *testing.T) {
	root := writeRoot(t, map[string]string{
		"/usr/lib/os-release": "NAME=\"Debian GNU/Linux\"\nID=debian\nVERSION_ID=12\nVERSION=\"12 (bookworm)\"\n",
	}, nil)
	out := DetectOSRelease(root)
	if out.Source != "/usr/lib/os-release" {
		t.Errorf("Source = %q, want /usr/lib/os-release", out.Source)
	}
	if out.Codename != "bookworm" {
		t.Errorf("Codename = %q, want bookworm (from VERSION)", out.Codename)
	}

	missing := DetectOSRelease(filepath.Join(t.TempDir(), "does-not-exist"))
	if missing.ID != "" || missing.Lifecycle != LifecycleUnknown {
		t.Errorf("missing os-release: got %+v", missing)
	}
	if !strings.Contains(strings.Join(missing.Notes, "; "), "UNVERIFIED") {
		t.Errorf("missing os-release must be UNVERIFIED, notes: %v", missing.Notes)
	}
}

func TestLifecycleClassification(t *testing.T) {
	// Fixed reference time inside the test instead of wall clock.
	orig := currentUTC
	defer func() { currentUTC = orig }()

	cases := []struct {
		id, ver string
		y, m    int
		want    string
	}{
		{"debian", "11", 2026, 11, LifecycleEOL},         // bullseye LTS ended 2026-08
		{"debian", "12", 2026, 11, LifecycleExtended},    // bookworm in LTS phase
		{"debian", "12", 2026, 6, LifecycleSupported},    // regular support through June
		{"ubuntu", "20.04", 2026, 11, LifecycleExtended}, // ESM phase
		{"ubuntu", "24.04", 2026, 11, LifecycleSupported},
		{"ubuntu", "25.04", 2026, 11, LifecycleEOL}, // interim ended 2026-01
		{"ubuntu", "25.04", 2026, 1, LifecycleSupported},
		{"rhel", "7", 2026, 11, LifecycleEOL},
		{"rhel", "9.4", 2026, 11, LifecycleSupported},
		{"fedora", "40", 2026, 11, LifecycleEOL},
		{"alpine", "3.20", 2026, 11, LifecycleEOL},
		{"alpine", "3.22.1", 2026, 11, LifecycleSupported}, // point release collapses
		{"arch", "rolling", 2026, 11, LifecycleRolling},
		{"unknownos", "1.0", 2026, 11, LifecycleUnknown},
	}
	for _, c := range cases {
		currentUTC = func() (int, int) { return c.y, c.m }
		got, basis := classifyLifecycle(c.id, c.ver)
		if got != c.want {
			t.Errorf("classifyLifecycle(%s %s @%d-%d) = %q, want %q (basis %q)", c.id, c.ver, c.y, c.m, got, c.want, basis)
		}
		if c.want != LifecycleUnknown && basis == "" {
			t.Errorf("classifyLifecycle(%s %s): basis must name the fact or policy", c.id, c.ver)
		}
	}
	currentUTC = orig
}

func TestFlavorFromRelease(t *testing.T) {
	cases := map[string]string{
		"6.8.0-40-generic":             "generic",
		"6.8.0-40.1-lowlatency":        "lowlatency",
		"5.15.0-1051-aws":              "aws",
		"6.1.0-18-cloud-amd64":         "cloud",
		"5.14.0-427.13.1.el9_4.x86_64": "",
		"6.1.0-13-rt-amd64":            "rt",
		"6.6.58-0-lts":                 "lts",
		"6.6.58-0-virt":                "virt",
		"6.6.2-arch1-1":                "default",
		"6.12.1-zen1-1":                "zen",
		"6.6.21-hardened1-1":           "hardened",
		"6.6.0-12.3-00001-gcr":         "",
		"":                             "",
	}
	for release, want := range cases {
		if got := FlavorFromRelease(release); got != want {
			t.Errorf("FlavorFromRelease(%q) = %q, want %q", release, got, want)
		}
	}
}

func TestInventoryDPKG(t *testing.T) {
	status := `Package: linux-image-6.1.0-18-amd64
Source: linux
Version: 6.1.112-1
Architecture: amd64
Status: install ok installed

Package: linux-image-amd64
Source: linux-signed-amd64 (6.1.112-1)
Version: 6.1.112-1
Architecture: amd64
Status: install ok installed

Package: linux-image-6.1.0-17-amd64
Source: linux
Version: 6.1.94-1
Architecture: amd64
Status: deinstall ok config-files

Package: linux-modules-6.1.0-18-amd64
Source: linux
Version: 6.1.112-1
Architecture: amd64
Status: install ok installed

Package: libc6
Version: 2.36-9+deb12u3
Status: install ok installed
`
	root := writeRoot(t, map[string]string{"/var/lib/dpkg/status": status}, nil)
	pkgs := inventoryDPKG(root)
	if len(pkgs) != 3 {
		t.Fatalf("got %d packages, want 3 (removed package must be excluded, libc6 excluded): %+v", len(pkgs), pkgs)
	}
	byName := map[string]KernelPackage{}
	for _, p := range pkgs {
		byName[p.Name] = p
	}
	img := byName["linux-image-6.1.0-18-amd64"]
	if img.Kind != KindImage || img.SourcePackage != "linux" || img.Version != "6.1.112-1" ||
		img.KernelRelease != "6.1.0-18-amd64" || img.Provenance != ProvenancePackageDB {
		t.Errorf("image package mismatch: %+v", img)
	}
	if img.Flavor != "" {
		t.Errorf("plain Debian image has no flavor, got %q", img.Flavor)
	}
	meta := byName["linux-image-amd64"]
	if meta.Kind != KindMeta || meta.KernelRelease != "" {
		t.Errorf("meta package must not carry a kernel release: %+v", meta)
	}
	mods := byName["linux-modules-6.1.0-18-amd64"]
	if mods.Kind != KindModules || mods.KernelRelease != "6.1.0-18-amd64" {
		t.Errorf("modules package mismatch: %+v", mods)
	}
}

func TestInventoryDPKGUbuntuFlavors(t *testing.T) {
	status := `Package: linux-image-unsigned-6.8.0-40-generic
Source: linux-signed
Version: 6.8.0-40.40
Architecture: amd64
Status: install ok installed

Package: linux-image-6.8.0-1013-aws
Source: linux-aws
Version: 6.8.0-1013.14
Architecture: amd64
Status: install ok installed

Package: linux-image-generic
Version: 6.8.0.40.40
Architecture: amd64
Status: install ok installed

Package: linux-image-generic-hwe-24.04
Version: 6.8.0.40.40
Status: install ok installed
`
	root := writeRoot(t, map[string]string{"/var/lib/dpkg/status": status}, nil)
	pkgs := inventoryDPKG(root)
	if len(pkgs) != 4 {
		t.Fatalf("got %d, want 4: %+v", len(pkgs), pkgs)
	}
	byName := map[string]KernelPackage{}
	for _, p := range pkgs {
		byName[p.Name] = p
	}
	uns := byName["linux-image-unsigned-6.8.0-40-generic"]
	if uns.Kind != KindImage || uns.KernelRelease != "6.8.0-40-generic" || uns.Flavor != "generic" {
		t.Errorf("unsigned image mismatch: %+v", uns)
	}
	if uns.SourcePackage != "linux-signed" {
		t.Errorf("source mapping from Source field lost: %+v", uns)
	}
	aws := byName["linux-image-6.8.0-1013-aws"]
	if aws.Flavor != "aws" || aws.KernelRelease != "6.8.0-1013-aws" {
		t.Errorf("aws image mismatch: %+v", aws)
	}
	gen := byName["linux-image-generic"]
	if gen.Kind != KindMeta || gen.Flavor != "generic" || gen.KernelRelease != "" {
		t.Errorf("generic meta mismatch: %+v", gen)
	}
	hwe := byName["linux-image-generic-hwe-24.04"]
	if hwe.Kind != KindMeta || hwe.Flavor != "generic-hwe" {
		t.Errorf("hwe meta mismatch: %+v", hwe)
	}
}

func TestInventoryAPK(t *testing.T) {
	db := `P:linux-lts
V:6.6.58-r0
A:x86_64
o:main
F:boot
R:vmlinuz-lts

P:linux-virt
V:6.6.56-r1
A:x86_64

P:linux-firmware-none
V:20240909-r0
A:noarch

P:busybox
V:1.36.1-r29
A:x86_64
`
	root := writeRoot(t, map[string]string{"/lib/apk/db/installed": db}, nil)
	pkgs := inventoryAPK(root)
	if len(pkgs) != 2 {
		t.Fatalf("got %d, want 2: %+v", len(pkgs), pkgs)
	}
	if pkgs[0].Name != "linux-lts" || pkgs[0].Version != "6.6.58-r0" || pkgs[0].Flavor != "lts" {
		t.Errorf("lts mismatch: %+v", pkgs[0])
	}
	if pkgs[0].KernelRelease != "6.6.58-0-lts" {
		t.Errorf("apk kernel release mapping wrong: %q", pkgs[0].KernelRelease)
	}
	if pkgs[1].Flavor != "virt" || pkgs[1].KernelRelease != "6.6.56-1-virt" {
		t.Errorf("virt mismatch: %+v", pkgs[1])
	}
}

func TestInventoryPacman(t *testing.T) {
	root := t.TempDir()
	mk := func(dir, content string) {
		full := filepath.Join(root, "/var/lib/pacman/local", dir, "desc")
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mk("linux-6.6.2.arch1-1", "%NAME%\nlinux\n\n%VERSION%\n6.6.2.arch1-1\n\n%ARCH%\nx86_64\n")
	mk("linux-lts-6.6.21.arch1-1", "%NAME%\nlinux-lts\n\n%VERSION%\n6.6.21.arch1-1\n")
	mk("bash-5.2.26-1", "%NAME%\nbash\n\n%VERSION%\n5.2.26-1\n")
	pkgs := inventoryPacman(root)
	if len(pkgs) != 2 {
		t.Fatalf("got %d, want 2: %+v", len(pkgs), pkgs)
	}
	if pkgs[0].Name != "linux" || pkgs[0].KernelRelease != "6.6.2-arch1-1" {
		t.Errorf("arch linux mapping wrong: %+v", pkgs[0])
	}
	if pkgs[0].Flavor != "default" {
		t.Errorf("arch default flavor wrong: %+v", pkgs[0])
	}
	if pkgs[1].KernelRelease != "6.6.21-arch1-1" || pkgs[1].Flavor != "lts" {
		t.Errorf("arch lts mapping wrong: %+v", pkgs[1])
	}
}

func TestInventoryRPMFromBoot(t *testing.T) {
	root := writeRoot(t, map[string]string{}, []string{
		"/boot", "/lib/modules/5.14.0-427.13.1.el9_4.x86_64",
		"/lib/modules/5.14.0-427.24.1.el9_4.x86_64",
	})
	if err := os.WriteFile(filepath.Join(root, "/boot/vmlinuz-5.14.0-427.24.1.el9_4.x86_64"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	pkgs := inventoryRPM(root)
	if len(pkgs) != 2 {
		t.Fatalf("got %d, want 2: %+v", len(pkgs), pkgs)
	}
	for _, p := range pkgs {
		if p.Ecosystem != EcosystemRPM || p.Provenance != ProvenanceFilesystem {
			t.Errorf("RPM provenance must be filesystem-evidence: %+v", p)
		}
	}
	byRel := map[string]KernelPackage{}
	for _, p := range pkgs {
		byRel[p.KernelRelease] = p
	}
	if p := byRel["5.14.0-427.13.1.el9_4.x86_64"]; p.Version != "5.14.0-427.13.1.el9_4" || p.Architecture != "x86_64" {
		t.Errorf("NVR mapping wrong: %+v", p)
	}
	if p := byRel["5.14.0-427.24.1.el9_4.x86_64"]; p.SourcePackage != "kernel" {
		t.Errorf("source package must stay kernel with UNVERIFIED ownership: %+v", p)
	}
}

func TestInventoryFromBootFallbackWithoutPackageDB(t *testing.T) {
	root := writeRoot(t, map[string]string{}, []string{"/lib/modules/6.1.0-18-amd64"})
	pkgs := InventoryInstalledKernels(root, "", "")
	if len(pkgs) != 1 || pkgs[0].KernelRelease != "6.1.0-18-amd64" {
		t.Fatalf("fallback inventory missing: %+v", pkgs)
	}
	if pkgs[0].Provenance != ProvenanceFilesystem {
		t.Errorf("fallback must be filesystem-evidence: %+v", pkgs[0])
	}
}

func TestAssessPendingRebootEvidenceRules(t *testing.T) {
	running := RunningKernel{Available: true, Release: "6.1.0-18-amd64", Arch: "amd64"}

	// Case 1: same running and installed version -> no indicator.
	pkgs := []KernelPackage{
		{Name: "linux-image-6.1.0-18-amd64", Version: "6.1.112-1", KernelRelease: "6.1.0-18-amd64", Flavor: "", Ecosystem: EcosystemDPKG, Kind: KindImage},
	}
	pr := AssessPendingReboot(running, pkgs)
	if pr == nil || pr.Likely || pr.RunningPackage == "" {
		t.Fatalf("same version: got %+v", pr)
	}

	// Case 2: newer same-flavor package installed -> likely pending reboot.
	pkgs = append(pkgs, KernelPackage{
		Name: "linux-image-6.1.0-19-amd64", Version: "6.1.120-1", KernelRelease: "6.1.0-19-amd64", Ecosystem: EcosystemDPKG, Kind: KindImage,
	})
	pr = AssessPendingReboot(running, pkgs)
	if !pr.Likely {
		t.Fatalf("newer installed: got %+v", pr)
	}
	if len(pr.NewerInstalled) != 1 || !strings.Contains(pr.NewerInstalled[0], "6.1.0-19-amd64") {
		t.Errorf("newer package evidence missing: %+v", pr.NewerInstalled)
	}
	if len(pr.Evidence) == 0 {
		t.Errorf("evidence list must not be empty")
	}

	// Case 3: running release matches no installed package -> UNVERIFIED, never a claim.
	pr = AssessPendingReboot(running, []KernelPackage{
		{Name: "linux-image-6.1.0-19-amd64", Version: "6.1.120-1", KernelRelease: "6.1.0-19-amd64", Ecosystem: EcosystemDPKG, Kind: KindImage},
	})
	if pr.Likely {
		t.Errorf("running kernel without installed match must be UNVERIFIED, got %+v", pr)
	}
	if !strings.Contains(pr.Explanation, "UNVERIFIED") {
		t.Errorf("explanation must disclose UNVERIFIED: %q", pr.Explanation)
	}

	// Case 4: multiple old kernels installed (normal!) -> no pending reboot.
	old := RunningKernel{Available: true, Release: "6.1.0-19-amd64"}
	pr = AssessPendingReboot(old, []KernelPackage{
		{Name: "linux-image-6.1.0-19-amd64", Version: "6.1.120-1", KernelRelease: "6.1.0-19-amd64", Ecosystem: EcosystemDPKG, Kind: KindImage},
		{Name: "linux-image-6.1.0-18-amd64", Version: "6.1.112-1", KernelRelease: "6.1.0-18-amd64", Ecosystem: EcosystemDPKG, Kind: KindImage},
		{Name: "linux-image-6.1.0-17-amd64", Version: "6.1.94-1", KernelRelease: "6.1.0-17-amd64", Ecosystem: EcosystemDPKG, Kind: KindImage},
	})
	if pr.Likely {
		t.Errorf("multiple installed kernels are normal and must not imply a reboot: %+v", pr)
	}

	// Case 5: different flavor packages never cross-compare.
	generic := RunningKernel{Available: true, Release: "6.8.0-40-generic", Flavor: "generic"}
	pr = AssessPendingReboot(generic, []KernelPackage{
		{Name: "linux-image-6.8.0-40-generic", Version: "6.8.0-40.40", KernelRelease: "6.8.0-40-generic", Flavor: "generic", Ecosystem: EcosystemDPKG, Kind: KindImage},
		{Name: "linux-image-6.8.0-1013-aws", Version: "6.8.0-1013.14", KernelRelease: "6.8.0-1013-aws", Flavor: "aws", Ecosystem: EcosystemDPKG, Kind: KindImage},
	})
	if pr.Likely {
		t.Errorf("aws flavor must not be compared against generic: %+v", pr)
	}

	// Case 6: offline/missing running kernel -> nil.
	if AssessPendingReboot(RunningKernel{}, []KernelPackage{{Name: "x", Version: "1", Ecosystem: EcosystemDPKG}}) != nil {
		t.Errorf("nil running kernel must yield nil assessment")
	}

	// Case 7: Alpine versions compare with apk semantics.
	alkrn := RunningKernel{Available: true, Release: "6.6.58-0-lts"}
	pr = AssessPendingReboot(alkrn, []KernelPackage{
		{Name: "linux-lts", Version: "6.6.58-r0", KernelRelease: "6.6.58-0-lts", Flavor: "lts", Ecosystem: EcosystemAPK, Kind: KindImage},
		{Name: "linux-lts", Version: "6.6.59-r0", KernelRelease: "6.6.59-0-lts", Flavor: "lts", Ecosystem: EcosystemAPK, Kind: KindImage},
	})
	if !pr.Likely {
		t.Errorf("alpine newer package must trigger pending reboot: %+v", pr)
	}

	// Case 8: RPM NVR versions compare with rpm semantics.
	rpmkr := RunningKernel{Available: true, Release: "5.14.0-427.13.1.el9_4.x86_64"}
	pr = AssessPendingReboot(rpmkr, []KernelPackage{
		{Name: "kernel", Version: "5.14.0-427.13.1.el9_4", KernelRelease: "5.14.0-427.13.1.el9_4.x86_64", Ecosystem: EcosystemRPM, Kind: KindImage},
		{Name: "kernel", Version: "5.14.0-427.24.1.el9_4", KernelRelease: "5.14.0-427.24.1.el9_4.x86_64", Ecosystem: EcosystemRPM, Kind: KindImage},
	})
	if !pr.Likely {
		t.Errorf("rpm newer package must trigger pending reboot: %+v", pr)
	}

	// Case 9: unparseable version syntax -> UNVERIFIED evidence, no verdict.
	weird := RunningKernel{Available: true, Release: "6.1.0-18-amd64"}
	pr = AssessPendingReboot(weird, []KernelPackage{
		{Name: "linux-image-6.1.0-18-amd64", Version: "6.1.112-1", KernelRelease: "6.1.0-18-amd64", Ecosystem: EcosystemDPKG, Kind: KindImage},
		{Name: "linux-image-6.1.0-19-amd64", Version: "broken:", KernelRelease: "6.1.0-19-amd64", Ecosystem: EcosystemDPKG, Kind: KindImage},
	})
	if pr.Likely {
		t.Errorf("unparseable versions must never produce a verdict: %+v", pr)
	}
	if len(pr.Evidence) == 0 || !strings.Contains(strings.Join(pr.Evidence, "; "), "UNVERIFIED") {
		t.Errorf("unparseable comparison must surface UNVERIFIED evidence: %+v", pr.Evidence)
	}

	// Case 10: cross-flavor unknown flavor is never compared against a
	// known flavor line.
	awsOnly := RunningKernel{Available: true, Release: "6.8.0-40-generic", Flavor: "generic"}
	pr = AssessPendingReboot(awsOnly, []KernelPackage{
		{Name: "linux-image-6.8.0-40-generic", Version: "6.8.0-40.40", KernelRelease: "6.8.0-40-generic", Flavor: "generic", Ecosystem: EcosystemDPKG, Kind: KindImage},
		{Name: "kernel", Version: "9:9", KernelRelease: "unknown-release", Ecosystem: EcosystemDPKG, Kind: KindImage},
	})
	if pr.Likely {
		t.Errorf("unknown-flavor package must not trigger a verdict against a flavored running kernel: %+v", pr)
	}
}

func TestAuditOfflineRootFSIsolation(t *testing.T) {
	// Offline target: running kernel must be empty regardless of the
	// scanner host's own /proc.
	root := writeRoot(t, map[string]string{
		"/etc/os-release":      "ID=debian\nVERSION_ID=12\n",
		"/var/lib/dpkg/status": "Package: linux-image-6.1.0-18-amd64\nVersion: 6.1.112-1\nArchitecture: amd64\nStatus: install ok installed\n",
	}, []string{"/lib/modules/6.1.0-18-amd64"})
	rep := Audit(root)
	if rep.Mode != "offline-rootfs" {
		t.Errorf("Mode = %q", rep.Mode)
	}
	if rep.Running.Available || rep.Running.Release != "" {
		t.Errorf("offline target must not report a running kernel: %+v", rep.Running)
	}
	if rep.PendingReboot != nil {
		t.Errorf("offline target must not produce a pending reboot verdict: %+v", rep.PendingReboot)
	}
	if len(rep.Packages) == 0 {
		t.Errorf("offline inventory missing: %+v", rep.Packages)
	}
}

func TestAuditLiveMissingDB(t *testing.T) {
	// "Missing database" must be a controlled condition of the test, not a
	// property of whatever host happens to run it. The live path keeps its
	// uname/proc denial checks (the only host inputs a test can control
	// there); the note behaviour is verified against explicit RootFS
	// fixtures in which the package database is genuinely absent, so the
	// assertions hold on every distribution and development environment.

	// Case 1 - live host: identity reads denied. Running must be
	// unavailable, no pending-reboot verdict may be produced, and the
	// report stays in live mode.
	origUname, origProc := unameFunc, readProcFile
	defer func() { unameFunc, readProcFile = origUname, origProc }()
	unameFunc = func(uts *syscall.Utsname) error { return errors.New("denied") }
	readProcFile = func(string) ([]byte, error) { return nil, errors.New("denied") }
	live := Audit("/")
	if live.Mode != "live" {
		t.Errorf("root \"/\" must audit in live mode, got %q", live.Mode)
	}
	if live.Running.Available {
		t.Errorf("uname and proc denied: Running must be unavailable: %+v", live.Running)
	}
	if live.PendingReboot != nil {
		t.Errorf("no running kernel: PendingReboot must stay nil: %+v", live.PendingReboot)
	}

	// Case 2 - fixture: os-release present, package database absent, no
	// /boot or /lib/modules fallback evidence. The audit must disclose the
	// missing inventory in notes instead of reporting a silent clean result.
	root := writeRoot(t, map[string]string{
		"/etc/os-release": "ID=debian\nVERSION_ID=12\n",
	}, nil)
	rep := Audit(root)
	if rep.Mode != "offline-rootfs" {
		t.Errorf("fixture root must audit as offline-rootfs, got %q", rep.Mode)
	}
	if rep.Running.Available {
		t.Errorf("offline target must not report a running kernel: %+v", rep.Running)
	}
	if len(rep.Packages) != 0 {
		t.Errorf("missing database without filesystem evidence must yield no packages: %+v", rep.Packages)
	}
	joined := strings.Join(rep.Notes, "; ")
	if !strings.Contains(joined, "no installed kernel packages could be identified") {
		t.Errorf("missing package database must be disclosed in notes: %v", rep.Notes)
	}
	if !strings.Contains(joined, "offline RootFS target:") {
		t.Errorf("offline mode must be disclosed in notes: %v", rep.Notes)
	}

	// Case 3 - fixture: nothing identifiable at all (no os-release, no
	// package database, no kernel files). The notes the original test
	// relied on must fire for exactly the reason it assumed.
	empty := t.TempDir()
	erep := Audit(empty)
	if erep.OSRelease.Ecosystem != "" {
		t.Errorf("empty root must leave the ecosystem unidentified: %+v", erep.OSRelease)
	}
	if len(erep.Packages) != 0 {
		t.Errorf("empty root must yield no packages: %+v", erep.Packages)
	}
	ejoined := strings.Join(erep.Notes, "; ")
	if !strings.Contains(ejoined, "package ecosystem not identified") {
		t.Errorf("unidentified ecosystem must be disclosed in notes: %v", erep.Notes)
	}
	if !strings.Contains(ejoined, "no installed kernel packages could be identified") {
		t.Errorf("nothing-identifiable root must be disclosed in notes: %v", erep.Notes)
	}
}

func TestDetectOSReleaseConflicting(t *testing.T) {
	// /etc/os-release wins over /usr/lib/os-release; conflicting values are
	// resolved deterministically and disclosed.
	root := writeRoot(t, map[string]string{
		"/etc/os-release":     "ID=debian\nVERSION_ID=12\n",
		"/usr/lib/os-release": "ID=ubuntu\nVERSION_ID=22.04\n",
	}, nil)
	out := DetectOSRelease(root)
	if out.ID != "debian" || out.VersionID != "12" {
		t.Errorf("conflicting os-release must resolve to /etc first: %+v", out)
	}
	if out.Source != "/etc/os-release" {
		t.Errorf("source must be disclosed: %q", out.Source)
	}
}

func TestInventoryDPKGCorrupted(t *testing.T) {
	// Malformed records must not fabricate packages; intact records survive.
	status := "Package: linux-image-6.1.0-18-amd64\nSource: linux\nVersion: 6.1.112-1\nArchitecture: amd64\nStatus: install ok installed\n\n" +
		"\x00\x01binary garbage without fields\n" +
		"Package: linux-modules-6.1.0-18-amd64\nVersion: 6.1.112-1\nStatus: install ok installed\n"
	root := writeRoot(t, map[string]string{"/var/lib/dpkg/status": status}, nil)
	pkgs := inventoryDPKG(root)
	if len(pkgs) != 2 {
		t.Fatalf("corrupted records must be skipped, intact ones kept: got %d", len(pkgs))
	}
}

func TestInventoryArchitectureMismatch(t *testing.T) {
	// Foreign-architecture image packages stay in the inventory (they ARE
	// installed) but carry their architecture for the reporter.
	status := "Package: linux-image-6.1.0-18-arm64\nSource: linux\nVersion: 6.1.112-1\nArchitecture: arm64\nStatus: install ok installed\n"
	root := writeRoot(t, map[string]string{"/var/lib/dpkg/status": status}, nil)
	pkgs := inventoryDPKG(root)
	if len(pkgs) != 1 || pkgs[0].Architecture != "arm64" {
		t.Fatalf("architecture must be preserved: %+v", pkgs)
	}
}

func TestAuditRPMSystemDisclosesUnverified(t *testing.T) {
	root := writeRoot(t, map[string]string{
		"/etc/os-release": "ID=rocky\nVERSION_ID=9.4\n",
	}, []string{"/lib/modules/5.14.0-427.13.1.el9_4.x86_64"})
	rep := Audit(root)
	if rep.OSRelease.Ecosystem != EcosystemRPM {
		t.Fatalf("ecosystem = %q", rep.OSRelease.Ecosystem)
	}
	joined := strings.Join(rep.Notes, "; ")
	if !strings.Contains(joined, "UNVERIFIED") {
		t.Errorf("RPM system must disclose UNVERIFIED provenance: %v", rep.Notes)
	}
	if len(rep.Packages) != 1 || rep.Packages[0].Provenance != ProvenanceFilesystem {
		t.Errorf("RPM inventory must be filesystem-evidence: %+v", rep.Packages)
	}
}
