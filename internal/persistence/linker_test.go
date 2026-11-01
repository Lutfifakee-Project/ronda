package persistence

import (
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/Lutfifakee-Project/ronda/internal/finding"
)

// elfBytes returns a minimal 64-bit little-endian ELF image header with the
// given e_machine value (62 = x86-64, 183 = aarch64). Only the header is
// ever sniffed; the bytes are never executed.
func elfBytes(machine uint16) string {
	return elfBytesSalted(machine, 0)
}

// elfBytesSalted varies the body so distinct fixtures do not share a
// SHA-256 unless a test deliberately wants copied payloads.
func elfBytesSalted(machine uint16, salt byte) string {
	b := make([]byte, 64)
	b[0] = 0x7f
	b[1] = 'E'
	b[2] = 'L'
	b[3] = 'F'
	b[4] = 2 // ELFCLASS64
	b[5] = 1 // little endian
	b[16] = 3
	b[17] = 0 // e_type = ET_DYN (shared object)
	b[18] = byte(machine)
	b[19] = byte(machine >> 8)
	for i := 20; i < len(b); i++ {
		b[i] = salt + byte(i)
	}
	return string(b)
}

func TestLinkerEmptyPreloadNoFindings(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.mkdirs("/root")
	f.mkdirs("/home/ubuntu")
	f.write("/etc/ld.so.preload", "")
	rep := f.scan()
	if len(rep.Findings) != 0 {
		t.Fatalf("empty preload produced findings: %+v", rep.Findings)
	}
}

func TestLinkerAbsentPreloadNoFindings(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	rep := f.scan()
	for _, fl := range rep.Findings {
		if strings.HasPrefix(fl.Rule, "ldso-") {
			t.Fatalf("absent preload produced %s", fl.Rule)
		}
	}
}

func TestLinkerLegitimateInstrumentedLibrary(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/usr/lib/x86_64-linux-gnu/libjemalloc.so.2", elfBytes(62))
	f.write("/etc/ld.so.preload", "/usr/lib/x86_64-linux-gnu/libjemalloc.so.2\n")
	rep := f.scan()
	countRule(t, rep, "ldso-preload-entry", 1)
	fl := findingsByRule(rep)["ldso-preload-entry"][0]
	if fl.Severity != finding.Info {
		t.Errorf("package-dir instrumentation is context (INFO), got %s", fl.Severity)
	}
	for _, other := range rep.Findings {
		if other.Rule == "ldso-preload-suspicious-path" || other.Rule == "ldso-preload-not-elf" {
			t.Errorf("legitimate library misclassified by %s", other.Rule)
		}
	}
}

func TestLinkerPreloadFromTmp(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/tmp/hook.so", elfBytes(62))
	f.write("/etc/ld.so.preload", "/tmp/hook.so\n")
	rep := f.scan()
	countRule(t, rep, "ldso-preload-suspicious-path", 1)
	fl := findingsByRule(rep)["ldso-preload-suspicious-path"][0]
	if fl.Severity != finding.High {
		t.Errorf("writable-location preload should be HIGH, got %s", fl.Severity)
	}
	if fl.Target != "/tmp/hook.so" {
		t.Errorf("target = %q", fl.Target)
	}
}

func TestLinkerPreloadMissingTarget(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/etc/ld.so.preload", "/usr/lib/libgone.so\n")
	rep := f.scan()
	countRule(t, rep, "ldso-preload-missing", 1)
	countRule(t, rep, "ldso-preload-entry", 1)
}

func TestLinkerPreloadNotELF(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/etc/sabotaged.so", "this is a text file, not a shared object\n")
	f.write("/etc/ld.so.preload", "/etc/sabotaged.so\n")
	rep := f.scan()
	countRule(t, rep, "ldso-preload-not-elf", 1)
}

func TestLinkerPreloadArchitectureMismatchLogic(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	// The comparison helper itself: mismatch requires both archs to be
	// known and different; equal or unknown archs claim nothing.
	if !archMismatch("x86-64", "aarch64") {
		t.Error("x86-64 host loading an aarch64 object is a mismatch")
	}
	if archMismatch("x86-64", "x86-64") || archMismatch("x86-64", "") || archMismatch("", "aarch64") {
		t.Error("equal or unknown archs must not be claimed as mismatches")
	}
	// The live-host mapping is only claimed when the running machine has a
	// known ELF label; offline roots are covered by the offline test above.
	if host := elfArchForHost(); host == "aarch64" && runtime.GOARCH != "arm64" {
		t.Errorf("host mapping %q inconsistent with GOARCH", host)
	}
}

func TestLinkerOfflineRootSkipsArchComparison(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/usr/lib/foreign.so", elfBytes(183))
	f.write("/etc/ld.so.preload", "/usr/lib/foreign.so\n")
	// Scan as an OFFLINE root: no host architecture exists to compare, so
	// no mismatch finding may be fabricated.
	rep := Scan(testContext(), f.Dir)
	countRule(t, rep, "ldso-preload-arch-mismatch", 0)
}

func TestLinkerPreloadSymlinkEscapeNotFollowed(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.symlink("/etc/lib-escape.so", "../../outside-the-root.so")
	f.write("/etc/ld.so.preload", "/etc/lib-escape.so\n")
	rep := f.scan()
	countRule(t, rep, "ldso-preload-suspicious-path", 0)
	// The entry is recorded honestly as uninspectable, never followed.
	entries := findingsByRule(rep)["ldso-preload-entry"]
	if len(entries) != 1 {
		t.Fatalf("expected one context entry, got %d", len(entries))
	}
}

func TestLinkerConfWritableDirectory(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/etc/ld.so.conf", "/usr/local/lib\n/tmp/libs\n")
	f.mkdirs("/tmp/libs")
	rep := f.scan()
	countRule(t, rep, "ldso-conf-writable-dir", 1)
	fl := findingsByRule(rep)["ldso-conf-writable-dir"][0]
	if fl.Target != "/tmp/libs" {
		t.Errorf("target = %q", fl.Target)
	}
}

func TestLinkerConfIncludeExpansion(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/etc/ld.so.conf", "include /etc/ld.so.conf.d/*.conf\n")
	f.write("/etc/ld.so.conf.d/local.conf", "/opt/app/libs\n")
	rep := f.scan()
	// /opt/app/libs does not exist in the fixture: no writable-dir finding,
	// no crash; include expansion must not escape the root.
	for _, fl := range rep.Findings {
		if fl.Rule == "ldso-conf-writable-dir" {
			t.Fatalf("unexpected writable-dir finding: %s", fl.Evidence)
		}
	}
}

func TestLinkerRelativePreloadEntry(t *testing.T) {
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/etc/ld.so.preload", "libhook.so\n")
	rep := f.scan()
	countRule(t, rep, "ldso-relative-path", 1)
}

func TestLinkerPermissionDeniedReported(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission-denied fixtures need a non-root test runner")
	}
	f := newFixtureRoot(t)
	f.addPasswd()
	f.write("/etc/ld.so.preload", "/usr/lib/libx.so\n")
	f.writeFileMode("/etc/ld.so.preload", "/usr/lib/libx.so\n", 0o000)
	rep := f.scan()
	denied := false
	for _, d := range rep.Denied {
		if strings.Contains(d, "/etc/ld.so.preload") {
			denied = true
		}
	}
	if !denied {
		t.Fatalf("unreadable preload file must be reported as denied, got %v", rep.Denied)
	}
}
