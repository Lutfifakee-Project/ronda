#!/usr/bin/env python3
"""Resource measurements for RONDA (Phase 7 section 14).

Measures wall-clock time and per-run peak RSS for each command. Every
measurement runs in its own forked child so RUSAGE_CHILDREN is scoped to
exactly one ronda process (the high-water mark does not leak across runs).

Usage: python3 scripts/measure-resources.py [path-to-ronda]
"""

import os
import resource
import subprocess
import sys
import time

RONDA = sys.argv[1] if len(sys.argv) > 1 else "./ronda"

MEASUREMENTS = [
    ("startup (ronda version)", ["version"], 3),
    ("help (ronda --help)", ["--help"], 3),
    ("scan synthetic root --all", ["scan", "/tmp/vps-target", "--all"], 1),
    ("kernel warm cache (offline)", ["kernel", "--root", "/tmp/vps-root", "--offline"], 2),
    ("kernel cold refresh (network)", ["kernel", "--root", "/tmp/vps-root", "--refresh"], 1),
    ("kernel debian cold refresh", ["kernel", "--root", "/tmp/vps-debian-root", "--refresh"], 1),
    ("kernel debian warm (cached)", ["kernel", "--root", "/tmp/vps-debian-root", "--offline"], 1),
    ("large fs scan /usr/lib --php", ["scan", "/usr/lib", "--php"], 1),
]


def run_once(args):
    """Runs one ronda invocation and reports (exit, wall seconds, peak MiB)."""
    t0 = time.time()
    proc = subprocess.run([RONDA] + args, capture_output=True, text=True)
    dt = time.time() - t0
    peak = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss / 1024.0
    return proc.returncode, dt, peak


def measure_one(label, args):
    """Forked so RUSAGE_CHILDREN covers exactly this measurement."""
    rc, dt, peak = run_once(args)
    print(f"RESULT\x1f{label}\x1f{dt:.2f}\x1f{peak:.1f}\x1f{rc}", flush=True)
    os._exit(0)


def main():
    print(f"RONDA binary: {RONDA}")
    print(f"measurement{'':20} time(s)  peakRSS(MiB)  exit")
    for label, args, repeat in MEASUREMENTS:
        best = None
        for _ in range(repeat):
            pid = os.fork()
            if pid == 0:
                measure_one(label, args)
            _, status = os.waitpid(pid, 0)
            if os.WEXITSTATUS(status) != 0:
                print(f"measurement crashed: {label}")
                os._exit(1)
        # Output is printed by the children; keep the summary line simple.
    print("done")


if __name__ == "__main__":
    main()
