// Package persistence implements the Phase 5 Linux persistence and
// backdoor analysis engine.
//
// It statically inspects systemd units and timers, cron/anacron/at jobs,
// SSH authorized keys and configuration, shell startup scripts, dynamic
// linker configuration, PAM stacks, kernel module loading configuration,
// udev rules and local account configuration inside a selected root
// filesystem (the live host or an offline mounted root), correlates
// references across artifacts and reports findings through the shared
// finding model.
//
// The engine is strictly read-only: it never executes scanned content,
// never invokes system tools (systemctl, crontab, package managers), never
// performs network requests, never reads credential databases such as
// /etc/shadow and never prints secrets found in inspected files. A
// persistence artifact is never judged malicious on its file name,
// directory, timestamp or permissions alone.
package persistence

import (
	"sort"

	"github.com/Lutfifakee-Project/ronda/internal/finding"
)

// Detection categories introduced in Phase 5. They extend the Phase 4
// taxonomy without renaming or reusing any existing category value.
const (
	CatSystemdPersistence  = "SYSTEMD_PERSISTENCE"
	CatScheduledTask       = "SCHEDULED_TASK_PERSISTENCE"
	CatSSHAccess           = "SSH_ACCESS_PERSISTENCE"
	CatShellStartup        = "SHELL_STARTUP_PERSISTENCE"
	CatDynamicLinker       = "DYNAMIC_LINKER_HIJACKING"
	CatPAMAuth             = "PAM_AUTHENTICATION_MODIFICATION"
	CatKernelModule        = "KERNEL_MODULE_PERSISTENCE"
	CatUdev                = "UDEV_PERSISTENCE"
	CatLocalAccount        = "LOCAL_ACCOUNT_MODIFICATION"
	CatSuspiciousExecution = "SUSPICIOUS_EXECUTABLE_REFERENCE"
	CatCrossArtifact       = "CROSS_ARTIFACT_BACKDOOR"
)

// Trust values recorded on referenced targets.
const (
	TrustPackageOwned      = "package-owned"
	TrustPackageOwnedMod   = "package-owned-modified"
	TrustUnowned           = "unowned"
	TrustInaccessible      = "inaccessible"
	TrustUnverified        = "unverified"
	TrustNoPackageDatabase = "no-package-database"
)

// RuleMeta describes one persistence detection rule. The shape mirrors
// analyzer.RuleMeta so reviewers see the same registry semantics; it adds
// the MITRE ATT&CK mapping Phase 5 requires.
type RuleMeta struct {
	ID string
	// Name is a short human-readable rule name.
	Name string
	// Category is one of the Cat* constants above.
	Category string
	// MITRE lists ATT&CK technique identifiers (e.g. "T1543.002"), when the
	// behavior maps to a documented technique.
	MITRE []string
	// Description explains what the rule detects.
	Description string
	// DefaultSeverity is the severity the rule alone can carry.
	DefaultSeverity finding.Severity
	// FPNotes lists the known legitimate patterns reviewers should weigh.
	FPNotes string
}

var ruleRegistry = map[string]RuleMeta{
	// ---- systemd (T1543.002, T1053.006) ----
	"systemd-exec-writable-path": {
		ID:              "systemd-exec-writable-path",
		Name:            "Systemd unit executes from writable path",
		Category:        CatSystemdPersistence,
		MITRE:           []string{"T1543.002"},
		Description:     "An Exec* directive references an executable or script inside /tmp, /dev/shm, /var/tmp or another world-writable location.",
		DefaultSeverity: finding.High,
		FPNotes:         "HIGH is reserved for the execution target or a payload write; a bare mention is LOW context. Build or recovery units may legitimately touch these paths.",
	},
	"systemd-exec-hidden-path": {
		ID:              "systemd-exec-hidden-path",
		Name:            "Systemd unit executes hidden executable",
		Category:        CatSystemdPersistence,
		MITRE:           []string{"T1543.002"},
		Description:     "An Exec* directive references an executable whose file or directory name starts with a dot.",
		DefaultSeverity: finding.Medium,
		FPNotes:         "Some tooling installs dot directories for caches; hidden execution is suspicious mainly combined with writable locations.",
	},
	"systemd-download-exec": {
		ID:              "systemd-download-exec",
		Name:            "Systemd unit downloads then executes",
		Category:        CatSystemdPersistence,
		MITRE:           []string{"T1543.002", "T1105"},
		Description:     "An Exec* directive chains a remote content fetch (curl/wget) into shell or interpreter execution.",
		DefaultSeverity: finding.High,
		FPNotes:         "Bootstrap or installer units can legitimately bootstrap; they are still dangerous defaults for every boot.",
	},
	"systemd-obfuscated-exec": {
		ID:              "systemd-obfuscated-exec",
		Name:            "Systemd unit executes encoded command",
		Category:        CatSystemdPersistence,
		MITRE:           []string{"T1543.002", "T1027"},
		Description:     "An Exec* directive decodes encoded content (base64 and similar) straight into a shell or interpreter.",
		DefaultSeverity: finding.High,
		FPNotes:         "Encoded execution is almost never needed by legitimate services.",
	},
	"systemd-envfile-suspicious": {
		ID:              "systemd-envfile-suspicious",
		Name:            "Systemd EnvironmentFile in writable path",
		Category:        CatSystemdPersistence,
		MITRE:           []string{"T1543.002"},
		Description:     "EnvironmentFile points into a world-writable or temporary location, letting any local writer inject service environment (including LD_PRELOAD).",
		DefaultSeverity: finding.Medium,
		FPNotes:         "Containers sometimes mount environment files from writable locations by design.",
	},
	"systemd-ldpreload-env": {
		ID:              "systemd-ldpreload-env",
		Name:            "Systemd unit sets LD_PRELOAD",
		Category:        CatSystemdPersistence,
		MITRE:           []string{"T1543.002", "T1574.006"},
		Description:     "Service environment sets LD_PRELOAD; severity follows the referenced library location (writable path escalates to HIGH).",
		DefaultSeverity: finding.Info,
		FPNotes:         "LD_PRELOAD is used for legitimate instrumentation and debugging.",
	},
	"systemd-missing-target": {
		ID:              "systemd-missing-target",
		Name:            "Systemd unit references missing target",
		Category:        CatSystemdPersistence,
		MITRE:           []string{"T1543.002"},
		Description:     "An Exec* directive references a path that does not exist or cannot be inspected.",
		DefaultSeverity: finding.Low,
		FPNotes:         "Units may legitimately point at optional payloads; missing target is a weak indicator on its own.",
	},
	"systemd-symlink-escape": {
		ID:              "systemd-symlink-escape",
		Name:            "Systemd unit symlink escapes root",
		Category:        CatSystemdPersistence,
		MITRE:           []string{"T1543.002"},
		Description:     "A unit, drop-in or enablement symlink resolves outside the scanned root filesystem.",
		DefaultSeverity: finding.Medium,
		FPNotes:         "Offline mounted roots may carry absolute symlinks that are legitimate on the live system.",
	},
	"systemd-reverse-shell": {
		ID:              "systemd-reverse-shell",
		Name:            "Systemd unit opens reverse shell",
		Category:        CatSystemdPersistence,
		MITRE:           []string{"T1543.002", "T1059.004"},
		Description:     "An Exec* directive spawns an interactive shell redirected to a network endpoint (/dev/tcp or similar) at boot time.",
		DefaultSeverity: finding.Critical,
		FPNotes:         "No legitimate service unit needs this.",
	},
	"systemd-timer-suspicious": {
		ID:              "systemd-timer-suspicious",
		Name:            "Systemd timer triggers suspicious service",
		Category:        CatSystemdPersistence,
		MITRE:           []string{"T1053.006"},
		Description:     "A timer activates a unit whose execution exhibits suspicious traits (writable path, hidden path, download-exec or encoded execution).",
		DefaultSeverity: finding.High,
		FPNotes:         "Timers routinely schedule maintenance; only trait-bearing targets are reported.",
	},

	// ---- cron / anacron / at (T1053.003, T1053.002) ----
	"cron-exec-writable-path": {
		ID:              "cron-exec-writable-path",
		Name:            "Scheduled job executes from writable path",
		Category:        CatScheduledTask,
		MITRE:           []string{"T1053.003"},
		Description:     "A scheduled command references an executable or script inside a world-writable or temporary location.",
		DefaultSeverity: finding.High,
		FPNotes:         "HIGH is reserved for the execution target or a payload write; a bare mention of a writable path (tests, cat, echo) is LOW context. Maintenance scripts writing logs under /tmp stay worth review.",
	},
	"cron-download-exec": {
		ID:              "cron-download-exec",
		Name:            "Scheduled job downloads then executes",
		Category:        CatScheduledTask,
		MITRE:           []string{"T1053.003", "T1105"},
		Description:     "A scheduled command chains a remote fetch into shell or interpreter execution.",
		DefaultSeverity: finding.High,
		FPNotes:         "Some update agents fetch installers; scheduled fetch-and-run of arbitrary URLs is a classic backdoor pattern.",
	},
	"cron-hidden-target": {
		ID:              "cron-hidden-target",
		Name:            "Scheduled job runs hidden script",
		Category:        CatScheduledTask,
		MITRE:           []string{"T1053.003"},
		Description:     "A scheduled command references a hidden file (dot-prefixed path) as its executable or script.",
		DefaultSeverity: finding.Medium,
		FPNotes:         "Legitimate tooling hides state in dot directories; hidden alone is not malicious.",
	},
	"cron-obfuscated-command": {
		ID:              "cron-obfuscated-command",
		Name:            "Scheduled job runs encoded command",
		Category:        CatScheduledTask,
		MITRE:           []string{"T1053.003", "T1027"},
		Description:     "A scheduled command decodes encoded content straight into a shell or interpreter.",
		DefaultSeverity: finding.High,
		FPNotes:         "Encoded execution in cron is almost never legitimate.",
	},
	"cron-reverse-shell": {
		ID:              "cron-reverse-shell",
		Name:            "Scheduled job opens reverse shell",
		Category:        CatScheduledTask,
		MITRE:           []string{"T1053.003", "T1059.004"},
		Description:     "A scheduled command spawns an interactive shell redirected to a network endpoint.",
		DefaultSeverity: finding.Critical,
		FPNotes:         "No legitimate scheduled job needs this.",
	},
	"cron-spool-anomaly": {
		ID:              "cron-spool-anomaly",
		Name:            "Cron spool file ownership anomaly",
		Category:        CatScheduledTask,
		MITRE:           []string{"T1053.003"},
		Description:     "A user crontab is owned by a different account than its name implies, or carries unsafe permissions.",
		DefaultSeverity: finding.Medium,
		FPNotes:         "Some cron implementations chown spool files at edit time; verify with the package owner before acting.",
	},
	"cron-missing-target": {
		ID:              "cron-missing-target",
		Name:            "Scheduled job references missing target",
		Category:        CatScheduledTask,
		MITRE:           []string{"T1053.003"},
		Description:     "A scheduled command references an executable path that does not exist or cannot be inspected.",
		DefaultSeverity: finding.Low,
		FPNotes:         "Scripts may reference binaries not installed on this root; weak indicator alone.",
	},
	"cron-path-hijack": {
		ID:              "cron-path-hijack",
		Name:            "Scheduled task PATH points to writable directory",
		Category:        CatScheduledTask,
		MITRE:           []string{"T1053.003", "T1574.007"},
		Description:     "A crontab PATH assignment places a world-writable or temporary directory in the search path of every scheduled command.",
		DefaultSeverity: finding.Medium,
		FPNotes:         "System crontabs usually pin PATH to /usr/bin:/bin; unusual PATH values deserve review.",
	},

	// ---- SSH (T1098.004) ----
	"ssh-forced-command": {
		ID:              "ssh-forced-command",
		Name:            "SSH key forces command execution",
		Category:        CatSSHAccess,
		MITRE:           []string{"T1098.004"},
		Description:     "An authorized_keys entry restricts the session to a command targeting an unexpected or writable executable path.",
		DefaultSeverity: finding.High,
		FPNotes:         "Backup and git restricted keys legitimately force commands (rrsync, git-shell); only unexpected targets escalate.",
	},
	"ssh-root-authorized-key": {
		ID:              "ssh-root-authorized-key",
		Name:            "Authorized key present for root",
		Category:        CatSSHAccess,
		MITRE:           []string{"T1098.004"},
		Description:     "root's authorized_keys contains at least one public key; recorded as context, not as proof of unauthorized access.",
		DefaultSeverity: finding.Info,
		FPNotes:         "Cloud images ship root or default-user keys by design; a key without a baseline is not automatically unauthorized.",
	},
	"ssh-unsafe-key-permissions": {
		ID:              "ssh-unsafe-key-permissions",
		Name:            "Unsafe SSH file permissions",
		Category:        CatSSHAccess,
		MITRE:           []string{"T1098.004"},
		Description:     "authorized_keys, ~/.ssh or sshd_config is writable by accounts beyond its owner.",
		DefaultSeverity: finding.Medium,
		FPNotes:         "NFS homes sometimes relax permissions deliberately.",
	},
	"ssh-key-owner-mismatch": {
		ID:              "ssh-key-owner-mismatch",
		Name:            "authorized_keys owner mismatch",
		Category:        CatSSHAccess,
		MITRE:           []string{"T1098.004"},
		Description:     "authorized_keys is owned by a different account than the home directory it resides in.",
		DefaultSeverity: finding.Medium,
		FPNotes:         "Admin tooling run as root can leave root-owned files; verify before acting.",
	},
	"ssh-config-permitroot": {
		ID:              "ssh-config-permitroot",
		Name:            "SSH root login permitted",
		Category:        CatSSHAccess,
		MITRE:           []string{"T1098.004"},
		Description:     "sshd_config sets PermitRootLogin to a value that allows direct root authentication.",
		DefaultSeverity: finding.Medium,
		FPNotes:         "Common on many distributions by default; a hygiene signal, not proof of compromise.",
	},
	"ssh-authorizedkeyscommand": {
		ID:              "ssh-authorizedkeyscommand",
		Name:            "AuthorizedKeysCommand references unexpected path",
		Category:        CatSSHAccess,
		MITRE:           []string{"T1098.004"},
		Description:     "AuthorizedKeysCommand points into a writable, temporary or hidden location, giving that binary root execution at authentication time.",
		DefaultSeverity: finding.High,
		FPNotes:         "Enterprise deployments use helper scripts under /usr or /etc; only unexpected locations escalate.",
	},
	"ssh-malformed-key": {
		ID:              "ssh-malformed-key",
		Name:            "Malformed SSH public key entry",
		Category:        CatSSHAccess,
		MITRE:           []string{"T1098.004"},
		Description:     "authorized_keys contains a line that is neither blank, comment nor a parseable public key.",
		DefaultSeverity: finding.Low,
		FPNotes:         "Some option strings are unusual but valid; only structurally invalid lines are reported.",
	},

	// ---- shell startup (T1546.004, T1037.004) ----
	"shell-download-exec": {
		ID:              "shell-download-exec",
		Name:            "Shell startup downloads then executes",
		Category:        CatShellStartup,
		MITRE:           []string{"T1546.004", "T1105"},
		Description:     "A shell startup file chains a remote fetch into shell or interpreter execution at login time.",
		DefaultSeverity: finding.High,
		FPNotes:         "Version managers occasionally self-update on login; arbitrary-URL fetch+run in startup files remains suspect.",
	},
	"shell-reverse-shell": {
		ID:              "shell-reverse-shell",
		Name:            "Shell startup opens reverse shell",
		Category:        CatShellStartup,
		MITRE:           []string{"T1546.004", "T1059.004"},
		Description:     "A shell startup file spawns an interactive shell redirected to a network endpoint (/dev/tcp or similar).",
		DefaultSeverity: finding.Critical,
		FPNotes:         "No legitimate startup file needs this.",
	},
	"shell-ldpreload-export": {
		ID:              "shell-ldpreload-export",
		Name:            "Shell startup exports LD_PRELOAD",
		Category:        CatShellStartup,
		MITRE:           []string{"T1546.004", "T1574.006"},
		Description:     "A startup file exports LD_PRELOAD; severity follows the referenced library location.",
		DefaultSeverity: finding.Info,
		FPNotes:         "Debuggers and profilers set LD_PRELOAD legitimately.",
	},
	"shell-hidden-exec": {
		ID:              "shell-hidden-exec",
		Name:            "Shell startup executes hidden path",
		Category:        CatShellStartup,
		MITRE:           []string{"T1546.004"},
		Description:     "A startup file invokes an executable or script whose name or parent directory is dot-prefixed (outside well-known tooling).",
		DefaultSeverity: finding.Medium,
		FPNotes:         "nvm, sdkman and similar managers live in dot directories and are excluded from this rule.",
	},
	"shell-writable-exec": {
		ID:              "shell-writable-exec",
		Name:            "Shell startup executes from writable path",
		Category:        CatShellStartup,
		MITRE:           []string{"T1546.004"},
		Description:     "A startup file invokes a payload from a world-writable location.",
		DefaultSeverity: finding.Medium,
		FPNotes:         "Writable startup EXECUTION is a hijack primitive (HIGH); bare mentions of writable paths are LOW context.",
	},
	"shell-suspicious-source": {
		ID:              "shell-suspicious-source",
		Name:            "Shell startup sources suspicious file",
		Category:        CatShellStartup,
		MITRE:           []string{"T1546.004"},
		Description:     "A startup file sources another file from a writable, temporary or unusual location (well-known managers excluded).",
		DefaultSeverity: finding.Medium,
		FPNotes:         "Sourcing /etc/os-release or completion scripts is normal; only risky locations are reported.",
	},
	"shell-path-injection": {
		ID:              "shell-path-injection",
		Name:            "Shell startup prepends writable PATH",
		Category:        CatShellStartup,
		MITRE:           []string{"T1574.007"},
		Description:     "A startup file places a world-writable directory ahead in PATH, enabling binary planting for every login.",
		DefaultSeverity: finding.Medium,
		FPNotes:         "User-local bin directories are standard; only world-writable locations escalate.",
	},
	"shell-encoded-command": {
		ID:              "shell-encoded-command",
		Name:            "Shell startup runs encoded command",
		Category:        CatShellStartup,
		MITRE:           []string{"T1546.004", "T1027"},
		Description:     "A startup file decodes encoded content straight into a shell or interpreter.",
		DefaultSeverity: finding.High,
		FPNotes:         "Encoded execution at login time is almost never legitimate.",
	},

	// ---- dynamic linker (T1574.006) ----
	"ldso-preload-entry": {
		ID:              "ldso-preload-entry",
		Name:            "ld.so.preload entry present",
		Category:        CatDynamicLinker,
		MITRE:           []string{"T1574.006"},
		Description:     "/etc/ld.so.preload lists one or more shared objects; every entry is context worth recording.",
		DefaultSeverity: finding.Info,
		FPNotes:         "Instrumentation (jemalloc, sanitizers, monitoring agents) uses preloads legitimately.",
	},
	"ldso-preload-suspicious-path": {
		ID:              "ldso-preload-suspicious-path",
		Name:            "Preload library in suspicious location",
		Category:        CatDynamicLinker,
		MITRE:           []string{"T1574.006"},
		Description:     "A preloaded object resides in /tmp, /dev/shm, /var/tmp, a hidden path, a user home or another world-writable location.",
		DefaultSeverity: finding.High,
		FPNotes:         "Legitimate preloads live in package directories; home-directory preloads are rare.",
	},
	"ldso-preload-missing": {
		ID:              "ldso-preload-missing",
		Name:            "Preload library missing",
		Category:        CatDynamicLinker,
		MITRE:           []string{"T1574.006"},
		Description:     "A preloaded path does not exist or cannot be inspected.",
		DefaultSeverity: finding.Low,
		FPNotes:         "Stale entries after uninstall are common; still worth review.",
	},
	"ldso-preload-not-elf": {
		ID:              "ldso-preload-not-elf",
		Name:            "Preload target is not a shared object",
		Category:        CatDynamicLinker,
		MITRE:           []string{"T1574.006"},
		Description:     "A preloaded path exists but is not an ELF file.",
		DefaultSeverity: finding.Medium,
		FPNotes:         "Text preload entries break every dynamic launch; deliberate damage is possible.",
	},
	"ldso-conf-writable-dir": {
		ID:              "ldso-conf-writable-dir",
		Name:            "ld.so configuration adds writable directory",
		Category:        CatDynamicLinker,
		MITRE:           []string{"T1574.006"},
		Description:     "ld.so.conf or an include under ld.so.conf.d adds a search directory that is world-writable.",
		DefaultSeverity: finding.Medium,
		FPNotes:         "Flatpak and snap sometimes register writable search paths; verify provenance.",
	},
	"ldso-relative-path": {
		ID:              "ldso-relative-path",
		Name:            "Relative path in ld.so.preload",
		Category:        CatDynamicLinker,
		MITRE:           []string{"T1574.006"},
		Description:     "A preload entry is a relative path; resolution then depends on loader behavior and working context.",
		DefaultSeverity: finding.Low,
		FPNotes:         "Documented entries are absolute in practice; relative entries are configuration errors at best.",
	},
	"ldso-preload-arch-mismatch": {
		ID:              "ldso-preload-arch-mismatch",
		Name:            "Preload library architecture mismatch",
		Category:        CatDynamicLinker,
		MITRE:           []string{"T1574.006"},
		Description:     "A preloaded shared object is built for a machine architecture different from the running host. Live-host scans only: an offline root has no host architecture to compare against.",
		DefaultSeverity: finding.Medium,
		FPNotes:         "Multi-arch emulation hosts legitimately preload foreign libraries; package provenance decides.",
	},

	// ---- PAM ----
	"pam-external-module-path": {
		ID:              "pam-external-module-path",
		Name:            "PAM module outside standard directories",
		Category:        CatPAMAuth,
		MITRE:           []string{"T1556.003"},
		Description:     "A stack references a module path outside the distribution's security module directories and package provenance does not cover it.",
		DefaultSeverity: finding.Medium,
		FPNotes:         "Locally built MFA or LDAP modules live outside package dirs; provenance decides escalation.",
	},
	"pam-writable-module": {
		ID:              "pam-writable-module",
		Name:            "PAM module in writable location",
		Category:        CatPAMAuth,
		MITRE:           []string{"T1556.003"},
		Description:     "A referenced module or pam_exec helper resides in a world-writable or temporary path.",
		DefaultSeverity: finding.High,
		FPNotes:         "Writable authentication modules are a takeover primitive.",
	},
	"pam-missing-module": {
		ID:              "pam-missing-module",
		Name:            "PAM module missing",
		Category:        CatPAMAuth,
		MITRE:           []string{"T1556.003"},
		Description:     "A referenced module file does not exist or cannot be inspected.",
		DefaultSeverity: finding.Low,
		FPNotes:         "Split packages may leave optional modules absent.",
	},
	"pam-bypass-indicator": {
		ID:              "pam-bypass-indicator",
		Name:            "PAM authentication bypass indicator",
		Category:        CatPAMAuth,
		MITRE:           []string{"T1556.003"},
		Description:     "pam_permit (or an equivalent always-succeed module) participates in the auth or password stack of a sensitive service.",
		DefaultSeverity: finding.Medium,
		FPNotes:         "pam_permit is normal in utility stacks (systemd-user, runuser) and in the standard Debian password idiom (pam_deny requisite before an unreachable pam_permit); only sensitive services are reported.",
	},
	"pam-exec-suspicious": {
		ID:              "pam-exec-suspicious",
		Name:            "pam_exec references suspicious helper",
		Category:        CatPAMAuth,
		MITRE:           []string{"T1556.003"},
		Description:     "pam_exec runs a helper from a writable, temporary or hidden location.",
		DefaultSeverity: finding.High,
		FPNotes:         "pam_exec scripts under /usr or /etc are legitimate; location decides.",
	},

	// ---- kernel modules / udev ----
	"kmod-install-suspicious": {
		ID:              "kmod-install-suspicious",
		Name:            "modprobe install directive runs suspicious command",
		Category:        CatKernelModule,
		MITRE:           []string{"T1547.006"},
		Description:     "A modprobe.d install directive executes a helper from a writable, temporary or hidden location.",
		DefaultSeverity: finding.High,
		FPNotes:         "install directives legitimately chain modprobe options; only risky helper locations are reported.",
	},
	"kmod-load-writable-path": {
		ID:              "kmod-load-writable-path",
		Name:            "Kernel module loaded from writable path",
		Category:        CatKernelModule,
		MITRE:           []string{"T1547.006"},
		Description:     "A configuration or rule references a .ko image under a writable or temporary path.",
		DefaultSeverity: finding.High,
		FPNotes:         "Out-of-tree modules usually live under /lib/modules or /usr/lib/modules.",
	},
	"kmod-missing-module": {
		ID:              "kmod-missing-module",
		Name:            "Configured kernel module not found",
		Category:        CatKernelModule,
		MITRE:           []string{"T1547.006"},
		Description:     "A module listed for loading has no .ko image under the kernel module trees of this root.",
		DefaultSeverity: finding.Low,
		FPNotes:         "Modules built but not installed, or hardware-specific modules, may legitimately be absent.",
	},
	"udev-run-suspicious": {
		ID:              "udev-run-suspicious",
		Name:            "Udev rule runs suspicious helper",
		Category:        CatUdev,
		MITRE:           []string{"T1547.002"},
		Description:     "RUN+=/IMPORT{program} references an executable in a writable, temporary or hidden location, or a download-exec chain.",
		DefaultSeverity: finding.High,
		FPNotes:         "Package-owned rules run helpers from /usr/lib/udev or /lib/udev; location and provenance decide.",
	},
	"udev-run-missing": {
		ID:              "udev-run-missing",
		Name:            "Udev helper missing",
		Category:        CatUdev,
		MITRE:           []string{"T1547.002"},
		Description:     "A udev rule references a helper path that does not exist or cannot be inspected.",
		DefaultSeverity: finding.Low,
		FPNotes:         "Rules may target optional hardware tooling.",
	},

	// ---- accounts / privilege ----
	"account-extra-uid0": {
		ID:              "account-extra-uid0",
		Name:            "Additional UID 0 account",
		Category:        CatLocalAccount,
		MITRE:           []string{"T1136.001"},
		Description:     "An account other than root carries UID 0, an alternative superuser invisible in most admin views.",
		DefaultSeverity: finding.High,
		FPNotes:         "Some hardened setups use a renamed root alias; verify intent before acting.",
	},
	"account-unusual-shell": {
		ID:              "account-unusual-shell",
		Name:            "Account shell set to unusual interpreter",
		Category:        CatLocalAccount,
		MITRE:           []string{"T1136.001"},
		Description:     "A regular user's login shell points outside the standard shell list (e.g. into /tmp or a hidden path).",
		DefaultSeverity: finding.High,
		FPNotes:         "nologin/false and distribution shells under /bin, /usr/bin or /sbin are standard; only off-list interpreters are reported.",
	},
	"account-passwd-malformed": {
		ID:              "account-passwd-malformed",
		Name:            "Malformed passwd entry",
		Category:        CatLocalAccount,
		Description:     "A /etc/passwd line does not have the expected seven fields.",
		DefaultSeverity: finding.Low,
		FPNotes:         "Manual edits can corrupt the file; parsing still keeps every parseable entry.",
	},
	"account-sudoers-nopasswd": {
		ID:              "account-sudoers-nopasswd",
		Name:            "Passwordless sudo for account",
		Category:        CatLocalAccount,
		MITRE:           []string{"T1548.003"},
		Description:     "sudoers grants NOPASSWD privilege; severity follows how broad the grant is and whether the user is a known default administrative account.",
		DefaultSeverity: finding.Medium,
		FPNotes:         "Cloud images grant NOPASSWD to their default user (ubuntu, ec2-user, debian, admin, cloud-user, vagrant and similar) by design.",
	},
	"account-sudoers-writable-path": {
		ID:              "account-sudoers-writable-path",
		Name:            "Sudoers command in writable path",
		Category:        CatLocalAccount,
		MITRE:           []string{"T1548.003"},
		Description:     "A sudoers rule authorizes running a command from a world-writable or temporary path, or the rule file itself is writable beyond root.",
		DefaultSeverity: finding.High,
		FPNotes:         "Legitimate deployments rarely authorize writable-path binaries.",
	},
	"account-sudoers-runas-exclusion": {
		ID:              "account-sudoers-runas-exclusion",
		Name:            "Sudoers Runas exclusion pattern",
		Category:        CatLocalAccount,
		MITRE:           []string{"T1548.003"},
		Description:     "A sudoers Runas list excludes root explicitly ((ALL, !root)), a pattern historically tied to uid-resolution bypasses.",
		DefaultSeverity: finding.Medium,
		FPNotes:         "Rarely legitimate; verify with the administrator.",
	},
	"account-admin-group-member": {
		ID:              "account-admin-group-member",
		Name:            "Administrative group membership",
		Category:        CatLocalAccount,
		Description:     "Membership list of an administrative group (wheel/sudo/admin), recorded as context because no baseline of expected members exists.",
		DefaultSeverity: finding.Info,
		FPNotes:         "Group membership alone cannot be judged unauthorized without a trusted baseline.",
	},
	"account-home-permissions": {
		ID:              "account-home-permissions",
		Name:            "World-writable home directory",
		Category:        CatLocalAccount,
		Description:     "A user home directory is writable by accounts beyond its owner, exposing startup files to tampering.",
		DefaultSeverity: finding.Low,
		FPNotes:         "Some shared-workstation setups relax homes deliberately.",
	},
	"account-home-missing": {
		ID:              "account-home-missing",
		Name:            "Login-capable account without home directory",
		Category:        CatLocalAccount,
		MITRE:           []string{"T1136.001"},
		Description:     "An account whose login shell permits interactive sessions has no home directory on disk.",
		DefaultSeverity: finding.Low,
		FPNotes:         "Network-backed homes (LDAP, NIS, autofs) may legitimately be absent from the scanned root; check the account purpose.",
	},

	// ---- referenced target analysis (T1574 family context) ----
	"target-in-writable-dir": {
		ID:              "target-in-writable-dir",
		Name:            "Referenced target in world-writable directory",
		Category:        CatSuspiciousExecution,
		MITRE:           []string{"T1574.007"},
		Description:     "An executable, script or library referenced by a persistence artifact sits in a world-writable directory and is not covered by package provenance.",
		DefaultSeverity: finding.Medium,
		FPNotes:         "/tmp-style locations are sometimes chosen by design for spool helpers; package ownership suppresses escalation.",
	},
	"target-hidden": {
		ID:              "target-hidden",
		Name:            "Hidden referenced target",
		Category:        CatSuspiciousExecution,
		Description:     "A referenced target file name (not a known tooling directory) is dot-prefixed.",
		DefaultSeverity: finding.Info,
		FPNotes:         "Hidden names alone are weak evidence; combine with location and provenance.",
	},
	"target-unowned-executable": {
		ID:              "target-unowned-executable",
		Name:            "Referenced executable not owned by any package",
		Category:        CatSuspiciousExecution,
		Description:     "Package provenance was available and covers the target directory family, but no package claims the referenced executable.",
		DefaultSeverity: finding.Info,
		FPNotes:         "Locally deployed admin scripts are unowned by nature; this is context, not a verdict.",
	},

	// ---- cross-artifact correlation ----
	"correlation-shared-payload": {
		ID:              "correlation-shared-payload",
		Name:            "Multiple persistence mechanisms reference same target",
		Category:        CatCrossArtifact,
		MITRE:           []string{"T1505.003"},
		Description:     "Two or more independent persistence artifacts reference the same target path, forming a cross-artifact backdoor chain.",
		DefaultSeverity: finding.High,
		FPNotes:         "Distributions reference shared helpers across mechanisms; escalation applies only when at least one reference is already suspicious.",
	},
	"correlation-shared-hash": {
		ID:              "correlation-shared-hash",
		Name:            "Same payload hash across mechanisms",
		Category:        CatCrossArtifact,
		MITRE:           []string{"T1505.003"},
		Description:     "Targets referenced by different persistence mechanisms share one SHA-256, linking separate artifacts to a single payload.",
		DefaultSeverity: finding.High,
		FPNotes:         "Standard system binaries can be referenced twice; only non-package-owned or already-suspicious hashes escalate.",
	},
}

// RuleMetadata returns the registry entry for a rule ID. The second result
// is false for unknown IDs; callers must not invent metadata for unknown
// rules.
func RuleMetadata(id string) (RuleMeta, bool) {
	m, ok := ruleRegistry[id]
	return m, ok
}

// RuleIDs returns every registered rule ID in sorted order.
func RuleIDs() []string {
	ids := make([]string, 0, len(ruleRegistry))
	for id := range ruleRegistry {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// Categories returns every Phase 5 category in a stable, display-friendly
// order.
func Categories() []string {
	return []string{
		CatCrossArtifact,
		CatSystemdPersistence,
		CatScheduledTask,
		CatSSHAccess,
		CatShellStartup,
		CatDynamicLinker,
		CatPAMAuth,
		CatKernelModule,
		CatUdev,
		CatLocalAccount,
		CatSuspiciousExecution,
	}
}
