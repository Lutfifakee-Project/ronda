package kernel

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
)

// RunningKernel describes the kernel the process is currently running, read
// through safe OS interfaces only: uname(2) via the Go runtime syscall
// package and the procfs files any process may read. RONDA never invokes the
// uname utility, shells or external inspection tools.
type RunningKernel struct {
	// Available is false for offline RootFS targets, where the procfs of the
	// scanner host must never be attributed to the target.
	Available bool   `json:"available"`
	Release   string `json:"release,omitempty"` // 6.1.0-18-amd64
	Version   string `json:"version,omitempty"` // #1 SMP PREEMPT_DYNAMIC ...
	Machine   string `json:"machine,omitempty"` // x86_64, aarch64, ...
	Arch      string `json:"arch,omitempty"`    // normalized: amd64, arm64, ...
	// Flavor is the kernel flavor when reliably derivable from the release
	// string (generic, cloud, aws, azure, gcp, rt, lowlatency, lts, virt,
	// hardened, zen, default, ...). Empty when unknown.
	Flavor string `json:"flavor,omitempty"`
	// Source names the interface the release came from.
	Source string `json:"source,omitempty"`
	// BuildInfo carries the /proc/version compiler and build timestamp when
	// available. This string is public kernel build metadata, never a
	// credential.
	BuildInfo string `json:"buildInfo,omitempty"`
}

// unameFunc and readProcFile are swappable for tests.
var (
	unameFunc    = syscall.Uname
	readProcFile = os.ReadFile
)

// syscallUtsname aliases the platform uname structure for test stubs.
type syscallUtsname = syscall.Utsname

// DetectRunningKernel identifies the running kernel on the live host. The
// root parameter must be "" or "/" for a live-host scan; any other root is
// an offline target and reports Available=false so scanner-host state is
// never mixed into a RootFS result.
func DetectRunningKernel(root string) RunningKernel {
	if clean := filepath.Clean("/" + strings.TrimSpace(root)); clean != "/" {
		return RunningKernel{}
	}
	out := RunningKernel{}
	var uts syscall.Utsname
	if err := unameFunc(&uts); err == nil {
		out.Available = true
		out.Release = utsToString(uts.Release)
		out.Version = utsToString(uts.Version)
		out.Machine = utsToString(uts.Machine)
		out.Source = "uname(2)"
	}
	// /proc/sys/kernel/osrelease cross-checks uname and serves as fallback
	// when the sandbox denies the uname syscall.
	if b, err := readProcFile("/proc/sys/kernel/osrelease"); err == nil {
		procRel := strings.TrimSpace(string(b))
		if procRel != "" {
			if out.Release == "" {
				out.Release = procRel
				out.Available = true
				out.Source = "/proc/sys/kernel/osrelease"
			} else if out.Release != procRel {
				out.Source = "uname(2) + /proc/sys/kernel/osrelease"
			}
		}
	}
	if out.Version == "" {
		if b, err := readProcFile("/proc/version"); err == nil {
			line := strings.TrimSpace(string(b))
			// "Linux version 6.1.0-18-amd64 (gcc ...) #1 SMP ..."
			if rest, ok := strings.CutPrefix(line, "Linux version "); ok {
				fields := strings.SplitN(rest, " ", 3)
				if len(fields) >= 2 && out.Release == "" {
					out.Release = fields[0]
					out.Available = true
					out.Source = "/proc/version"
				}
				if len(fields) >= 3 {
					out.BuildInfo = strings.TrimSpace(fields[2])
				}
			}
		}
	}
	out.Arch = normalizeMachine(out.Machine)
	if out.Arch == "" {
		out.Arch = runtime.GOARCH
	}
	out.Flavor = FlavorFromRelease(out.Release)
	return out
}

// utsToString converts a syscall.Utsname fixed-size int8 array to a string.
func utsToString(arr [65]int8) string {
	b := make([]byte, 0, len(arr))
	for _, c := range arr {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return strings.TrimSpace(string(b))
}

// normalizeMachine maps uname machine values to Go architecture names.
func normalizeMachine(machine string) string {
	switch machine {
	case "x86_64":
		return "amd64"
	case "aarch64":
		return "arm64"
	case "i686", "i586", "i486", "i386":
		return "386"
	case "armv7l", "armv8l", "arm":
		return "arm"
	case "riscv64":
		return "riscv64"
	case "loongarch64":
		return "loong64"
	case "ppc64le":
		return "ppc64le"
	case "s390x":
		return "s390x"
	case "":
		return ""
	}
	return machine
}

// ContainerIndicators reports whether the current process appears to run
// inside a container. Containers share the host kernel, so the running
// kernel belongs to the host while the installed packages belong to the
// container userspace; the report must state that limitation.
func ContainerIndicators(root string) []string {
	var out []string
	for _, p := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := os.Stat(filepath.Join(root, p)); err == nil {
			out = append(out, p)
		}
	}
	if data, err := readProcFile("/proc/1/cgroup"); err == nil && len(data) > 0 {
		s := string(data)
		if strings.Contains(s, "/docker") || strings.Contains(s, "/containerd") ||
			strings.Contains(s, "/kubepods") || strings.Contains(s, "/lxc") {
			out = append(out, "/proc/1/cgroup")
		}
	}
	return out
}
