#!/usr/bin/env python3
"""Read-only resource inspection and bounded subprocess execution for container research."""
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import time

ROOT = Path(__file__).resolve().parent
GIB = 1 << 30
RSS_LIMIT = 36 * GIB


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def capture(command, **kwargs):
    return subprocess.check_output(command, text=True, timeout=30, **kwargs).strip()


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def source_files(crate):
    return sorted([
        *(p for p in (crate / "src").rglob("*") if p.is_file()),
        *(crate / p for p in ("Cargo.toml", "Cargo.lock", "build.rs")),
        Path(__file__).resolve(),
    ])


def cgroup():
    relative = next(line[3:] for line in Path("/proc/self/cgroup").read_text().splitlines()
                    if line.startswith("0::"))
    root = Path("/sys/fs/cgroup") / relative.lstrip("/")
    data = {name: (root / name).read_text().strip() for name in (
        "memory.max", "memory.current", "memory.swap.max", "memory.events",
        "cpu.max", "cpuset.cpus.effective")}
    data["path"] = str(root)
    return data


def gpu(uuid):
    keys = ["uuid", "name", "driver_version", "memory.total", "memory.used",
            "memory.free", "utilization.gpu", "temperature.gpu", "power.draw",
            "clocks.sm", "clocks.mem"]
    row = next(csv.reader(io.StringIO(capture([
        "nvidia-smi", "-i", uuid, "--query-gpu=" + ",".join(keys),
        "--format=csv,noheader,nounits"]))))
    processes = list(csv.reader(io.StringIO(capture([
        "nvidia-smi", "-i", uuid, "--query-compute-apps=gpu_uuid,pid,used_memory",
        "--format=csv,noheader,nounits"]))))
    return {"gpu": dict(zip(keys, (v.strip() for v in row))),
            "compute_processes": [[v.strip() for v in p] for p in processes if p]}


def group_rss(pgid):
    """Sum process RSS, not thread RSS, for this runner's new process group."""
    members = {}
    for directory in Path("/proc").glob("[0-9]*"):
        try:
            stat = (directory / "stat").read_text()
            fields = stat[stat.rfind(")") + 2:].split()
            if int(fields[2]) == pgid:
                members[int(directory.name)] = int(fields[21]) * os.sysconf("SC_PAGE_SIZE")
        except (FileNotFoundError, ProcessLookupError):
            pass
    return members


def terminate_group(process):
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            break
        try:
            process.wait(timeout=3)
            break
        except subprocess.TimeoutExpired:
            pass


def check_gpu_processes(processes, members, previous_pid):
    """NVML can expose host PIDs that do not exist in the container's /proc.

    For that case require one stable GPU PID, an idle-device preflight, real
    device work in the test, and an empty GPU process list after child exit.
    Local RSS accounting continues to use the actual child process group.
    """
    if len(processes) > 1:
        raise RuntimeError("multiple GPU compute processes appeared")
    if not processes:
        return previous_pid, None
    pid = int(processes[0][1])
    if previous_pid is not None and pid != previous_pid:
        raise RuntimeError("GPU compute process changed during the benchmark")
    visible_ids = set(members)
    for member in members:
        try:
            for line in Path(f"/proc/{member}/status").read_text().splitlines():
                if line.startswith("NSpid:"):
                    visible_ids.update(map(int, line.split()[1:]))
        except FileNotFoundError:
            pass
    if pid in visible_ids:
        attribution = "process_group_pid"
    elif Path(f"/proc/{pid}").exists():
        raise RuntimeError(f"another visible GPU compute process appeared: PID {pid}")
    else:
        attribution = "host_pid_inferred_from_exclusive_lifecycle"
    return pid, attribution


def events(text):
    return {k: int(v) for k, v in (line.split() for line in text.splitlines())}


def records(path, prefix):
    return [json.loads(line[len(prefix) + 1:]) for line in path.read_text().splitlines()
            if line.startswith(prefix + " ")]


def run_stage(argv, directory, environment, uuid, *, gpu_work=False):
    directory.mkdir()
    before = cgroup()
    if gpu(uuid)["compute_processes"]:
        raise RuntimeError("GPU must be idle before each stage")
    write_json(directory / "command.json", {"argv": list(map(str, argv)),
        "overrides": {k: v for k, v in environment.items() if k.startswith(("LATTICA_", "RAYON_"))},
        "cgroup_before": before})
    start = time.monotonic()
    peak = gpu_peak = charge_peak = 0
    gpu_pid = attribution = None
    next_gpu = last_status = 0
    process = None
    result = {"status": "running"}
    try:
        with (directory / "benchmark.log").open("w") as log, (directory / "telemetry.jsonl").open("w", buffering=1) as telemetry:
            process = subprocess.Popen(list(map(str, argv)), cwd=ROOT, env=environment,
                stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                start_new_session=True)
            while process.poll() is None:
                now = time.monotonic()
                members = group_rss(process.pid)
                rss = sum(members.values())
                peak = max(peak, rss)
                charge = int((Path(before["path"]) / "memory.current").read_text())
                charge_peak = max(charge_peak, charge)
                row = {"seconds": now - start, "rss_bytes": rss, "cgroup_bytes": charge}
                if now >= next_gpu:
                    row.update(gpu(uuid))
                    gpu_pid, observed = check_gpu_processes(row["compute_processes"], members, gpu_pid)
                    attribution = observed or attribution
                    if not gpu_work and row["compute_processes"]:
                        raise RuntimeError("CPU-only stage unexpectedly created GPU work")
                    gpu_peak = max(gpu_peak, float(row["gpu"]["memory.used"]))
                    if gpu_peak > 20 * 1024:
                        raise RuntimeError("GPU usage exceeded the 20 GiB watchdog")
                    next_gpu = now + 1
                telemetry.write(json.dumps(row) + "\n")
                if rss > RSS_LIMIT or charge > int(before["memory.max"]) - 2 * GIB:
                    raise RuntimeError("RAM watchdog stopped the stage before the container limit")
                if now - start > 3600:
                    raise RuntimeError("one-hour stage watchdog expired")
                if now - last_status >= 30:
                    lines = (directory / "benchmark.log").read_text().splitlines()
                    recent = next((line for line in reversed(lines) if line.startswith((
                        "grouped_", "concurrent_", "bounded_gpu_"))), "working")
                    print(f"{directory.name}: {now-start:.0f}s; peak RSS {peak/GIB:.2f} GiB; {recent[:210]}", flush=True)
                    last_status = now
                time.sleep(.1)
            code = process.wait()
        if code:
            raise RuntimeError(f"stage exited {code}; see {directory / 'benchmark.log'}")
        if gpu(uuid)["compute_processes"]:
            raise RuntimeError("GPU compute process remains after stage exit")
        after = cgroup()
        first, last = events(before["memory.events"]), events(after["memory.events"])
        deltas = {k: last[k] - first[k] for k in first}
        if any(deltas.values()):
            raise RuntimeError("container memory-limit event invalidates the sample")
        result.update(status="passed", seconds=time.monotonic() - start,
            peak_rss_bytes=peak, peak_cgroup_bytes=charge_peak, peak_gpu_mib=gpu_peak,
            nvml_pid=gpu_pid, gpu_pid_attribution=attribution, memory_event_deltas=deltas)
        return result
    except BaseException as error:
        if process is not None:
            terminate_group(process)
        result.update(status="failed", error=f"{type(error).__name__}: {error}",
            seconds=time.monotonic() - start, peak_rss_bytes=peak,
            peak_cgroup_bytes=charge_peak, peak_gpu_mib=gpu_peak)
        raise
    finally:
        write_json(directory / "result.json", result)
