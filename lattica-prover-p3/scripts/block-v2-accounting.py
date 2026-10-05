#!/usr/bin/env python3
"""Read exact cgroup-v2 counters during ExecStopPost, before unit collection.

The snapshot includes the main process and cleanup work up to this read. It is
not the final post-cleanup CPU total. It runs even when the main process fails;
an accounting record is never a correctness marker.
"""
import os
from pathlib import Path
import re


def snapshot(root, unit):
    if not re.fullmatch(r"lattica-v2-[\w-]+\.service", unit):
        raise ValueError("unexpected accounting unit")
    values = {}
    for name in ("memory.peak", "memory.swap.peak", "memory.max", "memory.swap.max"):
        value = (root / name).read_text().strip()
        if not value.isdecimal():
            raise ValueError(f"missing/unbounded cgroup value: {name}")
        values[name.replace(".", "_")] = int(value)
    cpu = dict(line.split() for line in (root / "cpu.stat").read_text().splitlines())
    values["cpu_usage_usec"] = int(cpu["usage_usec"])
    if values["cpu_usage_usec"] < 0:
        raise ValueError("negative CPU usage")
    if values["memory_max"] > 44 * 2**30 or values["memory_swap_max"] != 0:
        raise ValueError("stage cgroup limits exceed the benchmark budget")
    if values["memory_peak"] > values["memory_max"] or values["memory_swap_peak"] != 0:
        raise ValueError("stage resource gate failed")
    return dict(unit=unit, scope="exec_stop_post_snapshot", **values)


def main():
    line = next(line for line in Path("/proc/self/cgroup").read_text().splitlines()
                if line.startswith("0::"))
    root = Path("/sys/fs/cgroup") / line[3:].lstrip("/")
    record = snapshot(root, os.environ["LATTICA_V2_ACCOUNTING_UNIT"])
    print("stage_cgroup_accounting " + " ".join(f"{key}={value}" for key, value in record.items()), flush=True)


if __name__ == "__main__":
    main()
