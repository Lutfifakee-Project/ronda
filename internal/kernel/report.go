package kernel

import (
	"strconv"
	"strings"
	"time"

	"github.com/Lutfifakee-Project/ronda/internal/versioncmp"
)

// currentUTC is swappable in tests so lifecycle classification is stable.
var currentUTC = func() (int, int) {
	now := time.Now().UTC()
	return now.Year(), int(now.Month())
}

// compareVersions orders two full package version strings per ecosystem.
// It returns an error for syntax the comparator does not understand, which
// callers must surface as UNVERIFIED rather than guess around.
func compareVersions(a, b, ecosystem string) (int, error) {
	switch ecosystem {
	case EcosystemDPKG:
		return versioncmp.CompareDebian(a, b)
	case EcosystemAPK:
		return versioncmp.CompareAlpine(a, b)
	case EcosystemRPM:
		return versioncmp.CompareRPM(a, b)
	case EcosystemPacman:
		return versioncmp.CompareArch(a, b)
	}
	return 0, &ecosystemError{}
}

// ecosystemError marks comparisons that have no comparator for the target.
type ecosystemError struct{}

func (*ecosystemError) Error() string {
	return "version comparison unavailable for this ecosystem"
}

// PendingReboot is the evidence-based assessment of whether a reboot is
// likely required to activate a newly installed kernel. RONDA never claims
// a reboot is definitely pending: the verdict carries its confidence and
// the full evidence trail.
type PendingReboot struct {
	// Likely is true only when the running kernel release maps to an
	// installed package whose version is older than another installed
	// package of the same flavor.
	Likely bool `json:"likely"`
	// RunningRelease is the release the host is currently running.
	RunningRelease string `json:"runningRelease"`
	// RunningPackage is the installed package matching the running release,
	// when identified. Empty when the running kernel does not correspond to
	// any installed package (custom kernel, container host kernel).
	RunningPackage string `json:"runningPackage,omitempty"`
	// NewerInstalled lists the newer same-flavor kernel packages that
	// motivate the assessment.
	NewerInstalled []string `json:"newerInstalled,omitempty"`
	// Evidence lists the concrete observations behind the verdict.
	Evidence []string `json:"evidence,omitempty"`
	// Explanation states what the assessment means and what it does not.
	Explanation string `json:"explanation"`
}

// Report is the outcome of a kernel identity and inventory audit. CVE
// matching lives in internal/kernelintel; Report never claims vulnerability
// or patchedness by itself.
type Report struct {
	Root string `json:"root,omitempty"`
	// Mode is "live" for the running host and "offline-rootfs" otherwise.
	Mode string `json:"mode"`
	// Container lists container indicators when the target appears to be a
	// container. The running kernel of a container belongs to the host.
	Container []string `json:"container,omitempty"`

	OSRelease OSRelease       `json:"osRelease"`
	Arch      string          `json:"arch,omitempty"`
	Running   RunningKernel   `json:"running"`
	Packages  []KernelPackage `json:"packages,omitempty"`

	PendingReboot *PendingReboot `json:"pendingReboot,omitempty"`

	Notes []string `json:"notes,omitempty"`
	// Inaccessible lists locations that could not be read. Coverage is
	// incomplete in that case and the audit is never reported as clean.
	Inaccessible []string `json:"inaccessible,omitempty"`
}

// Audit inspects kernel identity and installed kernel packages for root.
// root "" or "/" is the live host; anything else is an offline mounted
// RootFS. The audit is strictly read-only.
func Audit(root string) *Report {
	rep := &Report{Mode: "live"}
	rep.OSRelease = DetectOSRelease(root)
	if clean := strings.TrimSpace(root); clean != "" && clean != "/" {
		rep.Root = clean
		rep.Mode = "offline-rootfs"
	}

	rep.Running = DetectRunningKernel(root)
	if rep.Mode == "live" {
		rep.Arch = rep.Running.Arch
		rep.Container = ContainerIndicators(root)
	} else {
		// Offline target: the running kernel is NOT_APPLICABLE. The scanner
		// host's own kernel is never attributed to the target.
		rep.Running = RunningKernel{}
		rep.Notes = append(rep.Notes,
			"offline RootFS target: no running kernel is reported and the scanner host's kernel is not used")
	}

	rep.Packages = InventoryInstalledKernels(root, rep.OSRelease.Family, rep.OSRelease.Ecosystem)
	if len(rep.Packages) == 0 {
		rep.Notes = append(rep.Notes,
			"no installed kernel packages could be identified from the available metadata")
	}
	if rep.OSRelease.Ecosystem == EcosystemRPM {
		rep.Notes = append(rep.Notes,
			"RPM systems: package database is not statically readable without rpm tooling; kernel inventory comes from /boot and /lib/modules and package matching stays UNVERIFIED")
	}
	if rep.OSRelease.Ecosystem == "" {
		rep.Notes = append(rep.Notes,
			"package ecosystem not identified: version comparisons are UNVERIFIED for this target")
	}
	if rep.OSRelease.Lifecycle != LifecycleUnknown {
		rep.Notes = append(rep.Notes,
			"release lifecycle ("+rep.OSRelease.Lifecycle+"): "+rep.OSRelease.LifecycleBasis)
	}
	if rep.OSRelease.Lifecycle == LifecycleEOL {
		rep.Notes = append(rep.Notes,
			"this release is past its published support window: missing CVE entries never mean the system is secure")
	}

	if rep.Mode == "live" {
		rep.PendingReboot = AssessPendingReboot(rep.Running, rep.Packages)
	}
	return rep
}

// AssessPendingReboot compares the running kernel against the installed
// kernel packages. Evidence rules, per the Phase 6 spec:
//
//   - The running kernel is only assessed when it matches an installed
//     package's derived release. Multiple installed kernels are normal and
//     never imply a pending reboot by themselves.
//   - Comparison uses the installed package VERSIONS with the ecosystem
//     comparator, grouped by kernel flavor (different flavors are separate
//     packaging lines and are never cross-compared).
//   - When the running release matches no installed package, the result is
//     UNVERIFIED (custom kernel, chroot or container host kernel), never a
//     reboot claim.
func AssessPendingReboot(running RunningKernel, packages []KernelPackage) *PendingReboot {
	if !running.Available || running.Release == "" {
		return nil
	}
	out := &PendingReboot{
		RunningRelease: running.Release,
		Explanation:    "no pending reboot indicator found",
	}
	runningFlavor := FlavorFromRelease(running.Release)
	if runningFlavor == "" {
		runningFlavor = running.Flavor
	}

	// Candidates are grouped by flavor; a candidate only competes on the
	// same flavor line as the running kernel. Two unflavored releases count
	// as one line (plain Debian-style naming); a known flavor never
	// cross-compares against a different or unknown one.
	runningPkg := ""
	newest := make(map[string]KernelPackage) // flavor -> newest installed package
	for _, p := range packages {
		if p.KernelRelease == running.Release {
			if runningPkg == "" {
				runningPkg = p.Name + " " + p.Version
			}
			continue
		}
		if p.Version == "" {
			continue
		}
		flavor := p.Flavor
		if flavor == "" {
			flavor = FlavorFromRelease(p.KernelRelease)
		}
		if !sameFlavorLine(runningFlavor, flavor) {
			continue // separate packaging line: never cross-compared
		}
		cur, ok := newest[flavor]
		if !ok {
			newest[flavor] = p
			continue
		}
		if c, err := compareVersions(p.Version, cur.Version, p.Ecosystem); err == nil && c > 0 {
			newest[flavor] = p
		}
	}

	if runningPkg == "" {
		out.Explanation = "the running kernel release does not match any installed kernel package; pending reboot status UNVERIFIED"
		out.Evidence = append(out.Evidence,
			"running release "+running.Release+" has no matching installed kernel package (custom kernel, chroot or container host kernel)")
		return out
	}
	out.RunningPackage = runningPkg

	for flavor, cand := range newest {
		// Find the version of the installed package that the running
		// release corresponds to; compare candidate versions against it.
		var runningVer string
		for _, p := range packages {
			if p.KernelRelease == running.Release && p.Version != "" {
				runningVer = p.Version
				break
			}
		}
		if runningVer == "" {
			out.Evidence = append(out.Evidence,
				"installed kernel "+cand.Name+" "+cand.Version+" exists but the running kernel's package version is not statically known; comparison UNVERIFIED")
			continue
		}
		c, err := compareVersions(cand.Version, runningVer, cand.Ecosystem)
		if err != nil {
			out.Evidence = append(out.Evidence,
				"could not order running kernel against installed "+cand.release()+" : version comparison UNVERIFIED ("+err.Error()+")")
			continue
		}
		if c > 0 {
			out.Likely = true
			out.NewerInstalled = append(out.NewerInstalled,
				cand.Name+" "+cand.Version+" ("+cand.KernelRelease+")")
			out.Evidence = append(out.Evidence,
				"running kernel "+running.Release+" ("+runningVer+") is older than installed kernel package "+
					cand.Name+" "+cand.Version+" (release "+cand.KernelRelease+", flavor "+flavor+")")
		}
	}
	if out.Likely {
		out.Explanation = "a newer same-flavor kernel package is installed while the running kernel is older: a reboot is likely pending; RONDA never reboots or schedules reboots"
	} else if len(out.Evidence) > 0 {
		out.Explanation = "pending reboot status UNVERIFIED: see evidence"
	} else {
		out.Explanation = "the running kernel corresponds to the newest installed same-flavor kernel package"
	}
	return out
}

// sameFlavorLine reports whether two flavors belong to the same packaging
// line and may be version-compared.
func sameFlavorLine(a, b string) bool {
	if a == "" && b == "" {
		return true
	}
	return a != "" && a == b
}

// release returns a printable kernel release for a package entry.
func (p KernelPackage) release() string {
	if p.KernelRelease != "" {
		return p.KernelRelease
	}
	return p.Version
}

// Summary produces a compact one-line human summary of the report.
func (r *Report) Summary() string {
	var b strings.Builder
	b.WriteString("distribution: ")
	if r.OSRelease.ID != "" {
		b.WriteString(r.OSRelease.ID)
		if r.OSRelease.VersionID != "" {
			b.WriteString(" " + r.OSRelease.VersionID)
		}
	} else {
		b.WriteString("unknown")
	}
	b.WriteString("; lifecycle: " + r.OSRelease.Lifecycle)
	b.WriteString("; arch: ")
	b.WriteString(r.Arch)
	if r.Mode == "live" && r.Running.Available {
		b.WriteString("; running kernel: " + r.Running.Release)
	} else {
		b.WriteString("; running kernel: not applicable (offline target)")
	}
	b.WriteString("; installed kernel packages: " + strconv.Itoa(len(r.Packages)))
	return b.String()
}
