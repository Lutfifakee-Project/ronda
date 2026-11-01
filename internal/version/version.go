// Package version exposes build and detection-rule version information.
package version

// These values are overridable at build time with:
//
//	-ldflags "-X .../internal/version.Version=0.1.0 -X .../internal/version.RulesVersion=2026.10.30"
var (
	// Version is the RONDA binary version, always MAJOR.MINOR.PATCH.
	Version = "0.1.0"
	// Commit is the short git commit the binary was built from.
	Commit = "dev"
	// Date is the UTC build date.
	Date = "unknown"
	// RulesVersion tracks the detection rules independently of the binary.
	// builtin-2: lexical-view signal matching, file classification
	// (php-source / embedded-binary / binary-resource / text / unknown),
	// argument-aware assert() signals, invocation-vs-definition separation
	// and the dynamic_ref dispatch indicator (Phase 3.2).
	// builtin-3: Phase 4 behavioral correlation — bounded intra-file
	// source-to-sink flows (request input, decoder chains, remote content,
	// written files, uploaded files), dynamic-callable resolution, webshell
	// behavior chains, non-NUL binary/code-position classification, appended
	// binary polyglot indicator, strongest-evidence line attribution, the
	// structured rule registry and confidence/category metadata.
	// builtin-4: Phase 5 Linux persistence and backdoor detection —
	// systemd units/timers/drop-ins/enablement symlinks, cron/anacron/at,
	// SSH authorized keys and sshd configuration, shell startup files,
	// dynamic linker hijacking (with live-host ELF architecture
	// comparison), PAM stacks (writable modules included), kernel module
	// and udev rules, local account and privilege checks (missing homes
	// for login-capable accounts included), referenced-target inspection
	// (ELF sniffing, SHA-256, permissions, ownership), static package
	// provenance (dpkg/apk; rpm disclosed as unavailable), chained
	// `sh -c` command analysis, write-then-exec correlation within a
	// command line and across artifacts, cross-artifact correlation,
	// MITRE ATT&CK mapping and secret redaction.
	// builtin-5: Phase 6 kernel CVE intelligence — distribution-aware
	// running-kernel and installed-kernel-package inventory (dpkg status,
	// apk installed, pacman local, RPM via /boot and /lib/modules with
	// disclosed UNVERIFIED provenance), os-release ecosystem and lifecycle
	// resolution, Debian/RPM/Alpine/Arch version comparators, vendor feed
	// matching (Debian Security Tracker, Ubuntu OSV, Alpine secdb, Arch
	// AVG, Red Hat security data, AlmaLinux OSV) with persistent cache,
	// evidence-based pending-reboot assessment and upstream-only kernel
	// context separation.
	RulesVersion = "builtin-5"
)

// String returns the human readable version line used by the CLI.
func String() string {
	return "RONDA " + Version
}
