# RONDA compatibility and support matrix (v0.1.0)

Evidence-based only. A capability is claimed as supported **only** where this
document can point to a concrete test; everything else is explicitly
UNVERIFIED. Cross-compilation alone never proves runtime compatibility.

| Capability | Status | Evidence |
|---|---|---|
| Linux amd64 runtime | VERIFIED | Full unit suite (-race), 14-case E2E smoke and live `scan`/`persist`/`system`/`kernel --offline` runs as a native process (Debian 13/trixie container, kernel 5.10.134). |
| Linux arm64 runtime | UNVERIFIED | Static aarch64 ELF is cross-built, checksummed and govulncheck-scanned, but no arm64 hardware or emulator (qemu-user) exists in the test environment to execute it. |
| Static binary (no runtime deps) | VERIFIED | `file` reports "statically linked" for both targets; no Go, PHP, Python or shared-library requirement (README Requirements). |
| Non-root execution | VERIFIED | Entire QA suite runs unprivileged; installer default `$HOME/.local/bin` exercised end-to-end (piped `main.sh`, `--source`). |
| Root execution | UNVERIFIED (logic-tested) | No root account in the test sandbox. The root branch (`/usr/local/bin`, `id -u` selection) is covered by installer-suite fixtures and code review, not by a live root run. |
| Debian-family kernel feeds | VERIFIED | Debian Security Tracker adapter + distribution-aware version comparison covered by unit tests (internal/versioncmp, internal/kernelintel). |
| Ubuntu / Alpine / Arch feeds | VERIFIED (fixtures) | OSV / secdb adapters tested against recorded fixtures; live endpoint calls are explicit user actions. |
| RPM family (RHEL, Rocky, Alma, Fedora, SUSE) | PARTIAL | Kernel inventory from `/boot` and `/lib/modules` works; CVE matching is UNVERIFIED because the rpm database is not statically readable (README Supported platforms). |
| Other distributions | UNVERIFIED runtime | Static binary is expected to run anywhere Linux runs, but only tested environments are claimed. Kernel feeds may answer UNVERIFIED for unknown distros (by design). |
| Filesystems | VERIFIED on overlayfs | All scanning tests run on overlayfs. RONDA is read-only and uses no fs-specific features; ext4/xfs/btrfs are expected to behave identically but were not exercised. |
| Permission behaviors | VERIFIED | Unreadable target directory → report note "coverage is incomplete"; unreadable files → explicit `permission denied` entry in the report's errors plus `skipped` count; never treated as clean. |
| Offline operation | VERIFIED | Full offline suite under `unshare -rn` (no network at all): scan, persist, system, `kernel --offline`, version all pass; network-bound ops fail with explicit messages. |

Upgrade of the release toolchain follows docs/TOOLCHAIN.md; runtime
compatibility of a new toolchain is re-proven by rerunning the suites above.
