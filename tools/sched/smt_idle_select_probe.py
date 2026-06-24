#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
#
# Runtime heuristic for:
# 25a32e400a14 ("sched/fair: Prefer fully-idle SMT cores in asym-capacity idle selection")
#
# The probe runs a low CPU-count stress-ng workload and samples /proc/stat. If
# two SMT siblings are saturated while another SMT core is fully idle, the
# kernel likely lacks the fix or the behavior was not backported.

import argparse
import math
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time


SYS_CPU = Path("/sys/devices/system/cpu")
PROC_STAT = Path("/proc/stat")


def parse_cpulist(text):
    cpus = set()

    for part in text.strip().split(","):
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            cpus.update(range(int(start), int(end) + 1))
        else:
            cpus.add(int(part))

    return cpus


def format_cpulist(cpus):
    cpus = sorted(cpus)
    if not cpus:
        return ""

    ranges = []
    start = prev = cpus[0]

    for cpu in cpus[1:]:
        if cpu == prev + 1:
            prev = cpu
            continue

        ranges.append(f"{start}" if start == prev else f"{start}-{prev}")
        start = prev = cpu

    ranges.append(f"{start}" if start == prev else f"{start}-{prev}")
    return ",".join(ranges)


def read_text(path):
    try:
        return path.read_text(encoding="ascii").strip()
    except FileNotFoundError:
        return None


def read_smt_active():
    text = read_text(SYS_CPU / "smt" / "active")
    return text == "1" if text is not None else None


def read_online_cpus():
    online = read_text(SYS_CPU / "online")
    if online is None:
        return set()
    return parse_cpulist(online)


def read_thread_sibling_groups(cpus):
    groups = set()

    for cpu in cpus:
        path = SYS_CPU / f"cpu{cpu}" / "topology" / "thread_siblings_list"
        siblings = read_text(path)
        if siblings is None:
            continue

        group = frozenset(parse_cpulist(siblings) & cpus)
        if len(group) > 1:
            groups.add(group)

    return sorted((tuple(sorted(group)) for group in groups), key=lambda g: g[0])


def read_cpu_capacities(cpus):
    capacities = {}

    for cpu in cpus:
        text = read_text(SYS_CPU / f"cpu{cpu}" / "cpu_capacity")
        if text is None:
            continue
        try:
            capacities[cpu] = int(text)
        except ValueError:
            continue

    return capacities


def find_stress_ng(name):
    if "/" in name:
        path = Path(name)
        return str(path) if path.exists() and os.access(path, os.X_OK) else None
    return shutil.which(name)


def read_proc_stat(cpus):
    wanted = {f"cpu{cpu}": cpu for cpu in cpus}
    stats = {}

    with PROC_STAT.open(encoding="ascii") as stat:
        for line in stat:
            fields = line.split()
            if not fields:
                continue

            cpu = wanted.get(fields[0])
            if cpu is None:
                if fields[0] == "intr":
                    break
                continue

            values = [int(value) for value in fields[1:]]
            if len(values) < 8:
                raise RuntimeError(f"unexpected /proc/stat format for CPU {cpu}")

            idle = values[3] + values[4]
            total = sum(values[:8])
            stats[cpu] = (idle, total)

    missing = set(cpus) - set(stats)
    if missing:
        raise RuntimeError(f"missing /proc/stat entries for CPUs {format_cpulist(missing)}")

    return stats


def busy_percent(prev, cur):
    busy = {}

    for cpu, (prev_idle, prev_total) in prev.items():
        cur_idle, cur_total = cur[cpu]
        total_delta = cur_total - prev_total
        idle_delta = cur_idle - prev_idle

        if total_delta <= 0:
            busy[cpu] = 0.0
        else:
            busy[cpu] = max(0.0, 100.0 * (total_delta - idle_delta) / total_delta)

    return busy


def classify_sample(busy, smt_groups, busy_threshold, idle_threshold):
    stacked = []
    idle = []

    for group in smt_groups:
        busy_siblings = tuple(cpu for cpu in group if busy[cpu] >= busy_threshold)
        if len(busy_siblings) >= 2:
            stacked.append(group)

        if all(busy[cpu] <= idle_threshold for cpu in group):
            idle.append(group)

    return stacked, idle


def format_group_busy(group, busy):
    return "[" + ", ".join(f"cpu{cpu}:{busy[cpu]:.0f}%" for cpu in group) + "]"


def format_groups(groups, limit=4):
    if not groups:
        return "none"

    shown = [format_cpulist(group) for group in groups[:limit]]
    if len(groups) > limit:
        shown.append(f"+{len(groups) - limit} more")
    return " ".join(shown)


def sleep_while_running(seconds, proc=None):
    end = time.monotonic() + seconds

    while True:
        remaining = end - time.monotonic()
        if remaining <= 0:
            return
        if proc is not None and proc.poll() is not None:
            return
        time.sleep(min(0.1, remaining))


def terminate_process_group(proc):
    if proc is None or proc.poll() is not None:
        return

    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        return

    try:
        proc.wait(timeout=3)
        return
    except subprocess.TimeoutExpired:
        pass

    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    proc.wait(timeout=3)


def seconds_arg(seconds):
    return f"{seconds:g}s"


def print_environment(cpus, smt_groups, workers, capacities, args):
    print(f"SMT active: yes")
    print(f"Online CPUs in current affinity: {format_cpulist(cpus)} ({len(cpus)} CPUs)")
    print(f"SMT sibling groups: {len(smt_groups)}")

    if args.verbose:
        for group in smt_groups:
            print(f"  siblings: {format_cpulist(group)}")

    print(f"stress-ng workers: {workers}")
    print(
        "thresholds: "
        f"busy >= {args.busy_threshold:g}%, "
        f"fully idle SMT core <= {args.idle_threshold:g}% per sibling"
    )

    if capacities:
        values = sorted(set(capacities.values()))
        if len(values) == 1:
            print(
                "NOTE: visible cpu_capacity values are all equal; this commit "
                "only affects asym-capacity idle selection, so the result is a "
                "heuristic."
            )
        else:
            print(f"Visible cpu_capacity values: {values}")
    else:
        print(
            "NOTE: cpu_capacity is not visible in sysfs; cannot confirm whether "
            "this is an asym-capacity system."
        )


def run_baseline(cpus, smt_groups, args):
    if args.no_baseline:
        return False

    print(f"Taking {args.interval:g}s baseline sample...")
    prev = read_proc_stat(cpus)
    sleep_while_running(args.interval)
    cur = read_proc_stat(cpus)
    busy = busy_percent(prev, cur)
    stacked, idle = classify_sample(
        busy, smt_groups, args.busy_threshold, args.idle_threshold
    )

    if not stacked:
        return False

    print("WARNING: stacked busy SMT siblings were already present before stress-ng:")
    for group in stacked:
        print(f"  {format_group_busy(group, busy)}")
    print(f"  fully idle SMT sibling groups in baseline: {format_groups(idle)}")
    print("  Re-run on a quieter system or pass --no-baseline if this is expected.")

    return True


def run_probe(cpus, smt_groups, workers, stress_ng, baseline_stacked, args):
    cmd = [
        stress_ng,
        "--cpu",
        str(workers),
        "--timeout",
        seconds_arg(args.duration),
        "--quiet",
    ]

    print("Running:", " ".join(cmd))
    proc = None
    suspicious_samples = []
    strong_samples = []
    consecutive = 0
    samples = max(1, math.ceil(args.duration / args.interval))

    try:
        prev = read_proc_stat(cpus)
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )

        for nr in range(1, samples + 1):
            sleep_while_running(args.interval, proc)
            cur = read_proc_stat(cpus)
            busy = busy_percent(prev, cur)
            prev = cur

            stacked, idle = classify_sample(
                busy, smt_groups, args.busy_threshold, args.idle_threshold
            )

            if stacked:
                consecutive += 1
                suspicious_samples.append((nr, stacked, idle, busy))

                print(f"sample {nr}: stacked busy SMT sibling group(s):")
                for group in stacked:
                    print(f"  {format_group_busy(group, busy)}")
                print(f"  fully idle SMT sibling groups: {format_groups(idle)}")

                if idle:
                    strong_samples.append((nr, stacked, idle, busy))

                if consecutive >= args.consecutive:
                    break
            else:
                consecutive = 0
                if args.verbose:
                    max_count = 0
                    max_group = None
                    for group in smt_groups:
                        count = sum(1 for cpu in group if busy[cpu] >= args.busy_threshold)
                        if count > max_count:
                            max_count = count
                            max_group = group
                    if max_group is None:
                        print(f"sample {nr}: no busy SMT siblings")
                    else:
                        print(
                            f"sample {nr}: max busy siblings in one SMT core: "
                            f"{max_count} ({format_group_busy(max_group, busy)})"
                        )

            if proc.poll() is not None:
                break
    except KeyboardInterrupt:
        terminate_process_group(proc)
        raise
    finally:
        terminate_process_group(proc)

    stderr = ""
    if proc is not None:
        try:
            _, stderr = proc.communicate(timeout=1)
        except subprocess.TimeoutExpired:
            pass

    stress_rc = proc.returncode if proc is not None else None
    stress_failed = stress_rc not in (0, -signal.SIGTERM)
    if stress_failed:
        print(f"WARNING: stress-ng exited with status {stress_rc}")
        if stderr:
            print(stderr.rstrip())

    if baseline_stacked:
        print(
            "RESULT: UNKNOWN - SMT sibling stacking was already present "
            "before stress-ng, so the probe cannot attribute it to scheduler "
            "placement."
        )
        return 2

    if workers > len(smt_groups):
        print(
            "RESULT: UNKNOWN - worker count exceeds the number of SMT "
            "cores, so using SMT siblings can be legitimate."
        )
        return 2

    if stress_failed:
        print("RESULT: UNKNOWN - stress-ng did not complete successfully.")
        return 2

    if strong_samples:
        print(
            "RESULT: FAIL - at least two SMT siblings were saturated "
            "while another SMT core was fully idle."
        )
        return 1

    if suspicious_samples:
        print(
            "RESULT: UNKNOWN - saw saturated SMT siblings, but no fully "
            "idle SMT core in the same sample."
        )
        return 2

    print(
        "RESULT: OK"
    )
    return 0


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Probe for SMT sibling stacking under low stress-ng CPU load. "
            "This is a runtime heuristic for commit 25a32e400a14."
        )
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=10.0,
        help="stress-ng runtime in seconds (default: 10)",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help="sampling interval in seconds (default: 1)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=0,
        help="stress-ng CPU workers (default: online CPUs in affinity / 4)",
    )
    parser.add_argument(
        "--busy-threshold",
        type=float,
        default=90.0,
        help="per-CPU busy percentage considered saturated (default: 90)",
    )
    parser.add_argument(
        "--idle-threshold",
        type=float,
        default=20.0,
        help="per-CPU busy percentage considered idle (default: 20)",
    )
    parser.add_argument(
        "--consecutive",
        type=int,
        default=1,
        help="consecutive suspicious samples required before stopping (default: 1)",
    )
    parser.add_argument(
        "--stress-ng",
        default="stress-ng",
        help="stress-ng binary or path (default: stress-ng)",
    )
    parser.add_argument(
        "--no-baseline",
        action="store_true",
        help="skip the pre-stress baseline load check",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="print per-sample placement details",
    )
    args = parser.parse_args()

    if args.duration <= 0:
        parser.error("--duration must be > 0")
    if args.interval <= 0:
        parser.error("--interval must be > 0")
    if args.workers < 0:
        parser.error("--workers must be >= 0")
    if args.consecutive <= 0:
        parser.error("--consecutive must be > 0")

    smt_active = read_smt_active()
    if smt_active is False:
        print("SKIP: SMT is not active (/sys/devices/system/cpu/smt/active != 1).")
        return 2
    if smt_active is None:
        print("SKIP: cannot read /sys/devices/system/cpu/smt/active.")
        return 2

    stress_ng = find_stress_ng(args.stress_ng)
    if stress_ng is None:
        print(f"SKIP: cannot find executable stress-ng binary: {args.stress_ng}")
        return 2

    online = read_online_cpus()
    affinity = set(os.sched_getaffinity(0))
    cpus = sorted(online & affinity)
    if len(cpus) < 2:
        print("SKIP: fewer than two online CPUs are available in current affinity.")
        return 2

    smt_groups = read_thread_sibling_groups(set(cpus))
    if not smt_groups:
        print("SKIP: no online SMT sibling groups are available in current affinity.")
        return 2

    workers = args.workers if args.workers else max(1, len(cpus) // 4)
    capacities = read_cpu_capacities(cpus)

    print_environment(cpus, smt_groups, workers, capacities, args)
    baseline_stacked = run_baseline(cpus, smt_groups, args)
    return run_probe(cpus, smt_groups, workers, stress_ng, baseline_stacked, args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        sys.exit(130)
