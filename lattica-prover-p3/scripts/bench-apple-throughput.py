#!/usr/bin/env python3
"""Minimal Apple research screen: one reference job, then at most two candidates.

Each window includes startup, seven fresh recursive proofs per job, pruning and
independent CPU audit. A concurrent window contributes one throughput sample.
There is no total screen deadline or proving-worker timeout.
"""
import argparse
import contextlib
import fcntl
import stat
import hashlib
import html
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import selectors
import shutil
import signal
import socket
import subprocess
import sys
import tarfile
import time

ROOT = Path(__file__).resolve().parents[1]
GIB = 1 << 30
spec = importlib.util.spec_from_file_location("apple_baseline", ROOT / "scripts/bench-apple-metal.py")
baseline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(baseline)
diagnostic_spec = importlib.util.spec_from_file_location("apple_diagnostics", ROOT / "scripts/apple_diagnostics.py")
diagnostics = importlib.util.module_from_spec(diagnostic_spec)
diagnostic_spec.loader.exec_module(diagnostics)
StackSampler = diagnostics.StackSampler


def digest(path):
    with Path(path).open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def save(path, data):
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(data, indent=2) + "\n")
    temp.replace(path)


TUNING = {
    "pipeline": ("LATTICA_V2_METAL_PIPELINE", "resident", ("reference", "resident")),
    "poseidon_diagonal": ("LATTICA_V2_METAL_POSEIDON_DIAGONAL", "reference", ("reference", "specialized")),
    "ntt_tables": ("LATTICA_V2_METAL_NTT_TABLES", "auto", ("auto", "off", "on")),
    "ntt_tile_log2": ("LATTICA_V2_METAL_NTT_TILE_LOG2", "12", ("10", "11", "12")),
    "quotient": ("LATTICA_V2_METAL_QUOTIENT", "auto", ("auto", "cpu", "gpu")),
    "prefix_store": ("LATTICA_V2_METAL_PREFIX_STORE", "separate", ("separate", "fused")),
    "direct_readback": ("LATTICA_V2_GPU_DIRECT_READBACK", "0", ("0", "1")),
    "denominator_cache": ("LATTICA_V2_GPU_OPENING_DENOMINATOR_CACHE", "0", ("0", "1")),
    "query_gather": ("LATTICA_V2_GPU_QUERY_GATHER", "0", ("0", "1")),
    "compact_data": ("LATTICA_V2_GPU_COMPACT_PROVER_DATA", "auto", ("auto", "0", "1")),
}


def candidate_options(args):
    return {key: getattr(args, "candidate_" + key, default) for key, (_, default, _) in TUNING.items()}


def validate_candidate_workers(workers, options):
    if workers not in (1, 2, 3, 4, 5):
        raise ValueError("workers must be one, two, three, four or five")
    if workers >= 3 and options["pipeline"] != "reference":
        raise ValueError("three through five workers require the compact reference pipeline")
    if workers > 1 and options["pipeline"] == "reference":
        required = {"compact_data": "1", "query_gather": "1", "quotient": "cpu"}
        if any(options.get(key) != value for key, value in required.items()):
            raise ValueError("concurrent reference-pipeline workers require compact data, query gathering and CPU quotient")


def wait_for_preprocessing(owned, worker, log_path, samplers):
    """Stagger startup at a real phase boundary while retaining resource checks."""
    with log_path.open() as log:
        partial = ""
        while True:
            owned.sample()
            for sampler in samplers:
                sampler.poll()
            lines = (partial + log.read()).split("\n")
            partial = lines.pop()
            if any(line.startswith("proof_start ") for line in lines):
                return
            if worker.poll() is not None:
                raise RuntimeError("preceding worker exited before preprocessing completed")
            time.sleep(0.25)


def verify_tuning(text, environment):
    resident = environment["LATTICA_V2_METAL_PIPELINE"] == "resident"
    tables = environment["LATTICA_V2_METAL_NTT_TABLES"]
    quotient = environment["LATTICA_V2_METAL_QUOTIENT"]
    expected = {
        "poseidon_diagonal": environment["LATTICA_V2_METAL_POSEIDON_DIAGONAL"],
        "ntt_tables": str(tables == "on" or (tables == "auto" and resident and environment["LATTICA_V2_METAL_KERNEL_VARIANT"] == "optimized")).lower(),
        "ntt_tile_log2": environment["LATTICA_V2_METAL_NTT_TILE_LOG2"],
        "prefix_store": environment["LATTICA_V2_METAL_PREFIX_STORE"],
        "quotient": "gpu" if quotient == "gpu" or (quotient == "auto" and resident) else "cpu",
    }
    observed = [dict(part.split("=", 1) for part in line.split()[1:])
                for line in text.splitlines() if line.startswith("metal_tuning ")]
    if not observed or any(row != expected for row in observed):
        raise RuntimeError("worker tuning did not match requested controls")


def policy(workers, candidate, scratch, variant, workgroup, diagnostic_profile=False, options=None):
    if workers not in (1, 2, 3, 4, 5):
        raise ValueError("workers must be one, two, three, four or five")
    selected = {key: default for key, (_, default, _) in TUNING.items()}
    for key, value in (options or {}).items():
        if key not in TUNING or str(value) not in TUNING[key][2]:
            raise ValueError("invalid candidate tuning: " + key)
        selected[key] = str(value)
    if not candidate:
        selected.update(pipeline="reference", poseidon_diagonal="reference", ntt_tables="off",
                        ntt_tile_log2="12", quotient="cpu", prefix_store="separate",
                        direct_readback="0", denominator_cache="0", query_gather="0", compact_data="0")
    if workers >= 3:
        validate_candidate_workers(workers, selected)
    resident = selected["pipeline"] == "resident"
    # Preserve the resident pipeline's compact default unless explicitly
    # controlled; adding a tuning key must not restore full host matrices.
    if selected["compact_data"] == "auto":
        selected["compact_data"] = "1" if resident else "0"
    config = baseline.arm("shared", 18 // workers,
                          "quotient-compact-deferred" if resident else "quotient-deferred")
    if resident: config["readback"] = 0
    env = baseline.environment(config, scratch, True)
    env.update({"LATTICA_V2_METAL_KERNEL_VARIANT": variant if candidate else "reference",
                "LATTICA_V2_METAL_WORKGROUP": str(workgroup if candidate else 256),
                "LATTICA_V2_METAL_BATCH": "8" if resident else "1",
                "LATTICA_V2_METAL_COORDINATOR_PID": str(os.getpid()),
                "LATTICA_V2_METAL_TIMEOUT_SECONDS": "none",
                "LATTICA_PROFILE_TIMELINE": str(int(diagnostic_profile))})
    env.update({TUNING[key][0]: value for key, value in selected.items()})
    if resident:
        env.pop("LATTICA_SPILL_MAX_BYTES", None)
    return env


def plan_workers(physical_bytes, requested=None, memory_policy=None):
    """Choose concurrency before startup; these estimates never cap allocations.

    Scratch mappings are part of tracked backing, so the two estimates overlap.
    Runtime/driver headroom is additional and system reserve is shared.
    """
    policy = baseline.MEMORY_POLICY if memory_policy is None else memory_policy
    keys = ("resident_backing_estimate_bytes", "resident_scratch_estimate_bytes",
            "resident_runtime_headroom_bytes", "system_reserve_bytes")
    estimates = {key: policy[key] for key in keys}
    for key, value in {"physical_memory_bytes": physical_bytes, **estimates}.items():
        if type(value) is not int or not 0 < value < 1 << 64:
            raise ValueError(f"{key} must be a positive u64 byte count")
    if requested is not None and (type(requested) is not int or requested not in (1, 2)):
        raise ValueError("requested worker maximum must be one or two")
    per_worker = max(estimates["resident_backing_estimate_bytes"],
                     estimates["resident_scratch_estimate_bytes"]) + estimates["resident_runtime_headroom_bytes"]
    capacity = max(0, physical_bytes - estimates["system_reserve_bytes"]) // per_worker
    selected = min(capacity, requested or 2, 2)
    return {"physical_memory_bytes": physical_bytes, **estimates,
            "per_worker_estimate_bytes": per_worker, "estimated_workers": capacity,
            "requested_max_workers": requested, "screen_max_workers": 2,
            "selected_workers": selected, "threads_per_worker": 18 // selected if selected else 0,
            "allocation_limits_enforced": False}


def resident_worker_plan(requested=None):
    physical_bytes = int(subprocess.check_output(["/usr/sbin/sysctl", "-n", "hw.memsize"], text=True))
    plan = plan_workers(physical_bytes, requested)
    print("RESIDENT_WORKER_PLAN", json.dumps(plan, sort_keys=True), flush=True)
    if not plan["selected_workers"]:
        raise RuntimeError("resident memory estimates leave no worker capacity; revise the planning estimates or system reserve before launch")
    return plan


def observations():
    def command(args):
        return subprocess.check_output(args, text=True).strip()
    swap = command(["/usr/sbin/sysctl", "-n", "vm.swapusage"])
    match = re.search(r"used\s*=\s*([0-9.]+)([MG])", swap)
    if not match:
        raise RuntimeError("cannot read swap usage")
    pressure = int(command(["/usr/sbin/sysctl", "-n", "kern.memorystatus_vm_pressure_level"]))
    return {"swap_used_bytes": int(float(match[1]) * (GIB if match[2] == "G" else 1 << 20)),
            "pressure": pressure, "utc_ns": time.time_ns()}


class OwnedProcesses:
    def __init__(self, resources):
        self.children = []
        self.resources = resources
        self.peak = 0
        self.worker_peaks = {}
        self.before = observations()
        self.swap_peak = self.before["swap_used_bytes"]
        self.pressure_incident = self.before["pressure"] != 1
        self.last_heartbeat = time.monotonic()
        self.last_vm_snapshot = 0.0

    def spawn(self, args, env, log, *, pass_fds=(), role="cpu", limit=None):
        process = subprocess.Popen(list(map(str, args)), env=env, stdout=log, stderr=subprocess.STDOUT,
                                   start_new_session=True, pass_fds=pass_fds)
        self.children.append((process, role, limit))
        return process

    def sample(self):
        live = [(p, role, limit) for p, role, limit in self.children if p.poll() is None]
        pids = [os.getpid(), *[p.pid for p, _, _ in live]]
        result = subprocess.run(["/bin/ps", "-o", "pid=,rss=", "-p", ",".join(map(str, pids))],
                                text=True, capture_output=True, check=True)
        rss = {int(pid): int(kib) * 1024 for pid, kib in (l.split() for l in result.stdout.splitlines())}
        if os.getpid() not in rss:
            raise RuntimeError("coordinator RSS sampling unavailable")
        total = sum(rss.values())
        self.peak = max(self.peak, total)
        if baseline.AGGREGATE_RSS_LIMIT_BYTES is not None and total > baseline.AGGREGATE_RSS_LIMIT_BYTES:
            raise RuntimeError("configured aggregate RSS budget exceeded")
        for p, role, limit in live:
            size = rss.get(p.pid)
            if size is None and p.poll() is None:
                raise RuntimeError("child RSS sampling unavailable")
            if size is not None:
                self.worker_peaks[str(p.pid)] = max(size, self.worker_peaks.get(str(p.pid), 0))
                if limit is not None and size > limit:
                    raise RuntimeError(f"{role} RSS budget exceeded")
        obs = observations()
        if os.environ.get("LATTICA_APPLE_MEMORY_RECLAIM") == "1" and (obs["pressure"] != 1 or time.monotonic() - self.last_vm_snapshot >= 10):
            obs["vm_stat"] = subprocess.check_output(["/usr/bin/vm_stat"], text=True)
            self.last_vm_snapshot = time.monotonic()
        self.swap_peak = max(self.swap_peak, obs["swap_used_bytes"])
        self.pressure_incident |= obs["pressure"] != 1
        self.resources.write(json.dumps({"monotonic": time.monotonic(), "rss": rss,
                                         "aggregate_rss": total, **obs}) + "\n")
        self.resources.flush()
        if obs["pressure"] != 1:
            raise RuntimeError("memory pressure invalidates screen")
        if time.monotonic() - self.last_heartbeat >= 20:
            print(f"PROGRESS aggregate peak RSS {self.peak / GIB:.2f} GiB", flush=True)
            self.last_heartbeat = time.monotonic()

    def wait(self, process):
        while process.poll() is None:
            self.sample()
            time.sleep(0.25)
        if process.returncode:
            raise RuntimeError(f"child failed: {process.args[0]} exit={process.returncode}")

    def close(self):
        errors = []
        for process, _, _ in self.children:
            if process.poll() is None:
                try: os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError: pass
                except PermissionError:
                    # Some macOS launch policies deny process-group signaling.
                    # The direct Popen child is still owned and must be reaped.
                    try: process.terminate()
                    except ProcessLookupError: pass
                    except PermissionError as error: errors.append(str(error))
        end = time.monotonic() + 3
        for process, _, _ in self.children:
            try: process.wait(timeout=max(0.01, end - time.monotonic()))
            except subprocess.TimeoutExpired:
                try: process.kill()
                except ProcessLookupError: pass
                except PermissionError as error: errors.append(str(error))
                try: process.wait(timeout=3)
                except subprocess.TimeoutExpired: errors.append(f"unable to reap owned PID {process.pid}")
        if errors:
            print("Worker cleanup: " + "; ".join(errors), file=sys.stderr)


def run_window(args, out, binaries, external, candidate):
    count = args.workers if candidate else 1
    options = candidate_options(args)
    if candidate:
        validate_candidate_workers(count, options)
    launch_phase = getattr(args, "worker_launch_phase", "immediate") if candidate else "immediate"
    if launch_phase not in ("immediate", "after-preprocessing"):
        raise ValueError("invalid worker launch phase")
    label = ("resident" if options["pipeline"] == "resident" else "candidate-reference") if candidate else "reference"
    directory = out / label
    directory.mkdir()
    jobs = []
    for index in range(count):
        job = directory / f"job-{index}"
        job.mkdir()
        (job / "scratch").mkdir()
        for name in baseline.FIXTURE_NAMES:
            shutil.copy2(out / "fixture" / name, job / name)
        jobs.append(job)
    started = time.monotonic()
    handles = []
    samplers = []
    worker_processes = []
    sockets = []
    ready = selectors.DefaultSelector()
    result = {"label": label, "workers": count, "threads_total": count * (18 // count), "cpu_core_budget": 18, "jobs": [],
              "status": "RUNNING", "timing_boundary": "startup through independent CPU audit",
              "worker_launch_phase": launch_phase, "worker_launches": []}
    with (directory / "resources.jsonl").open("w") as resource_log:
        owned = OwnedProcesses(resource_log)
        try:
            for index, job in enumerate(jobs):
                if index and launch_phase == "after-preprocessing":
                    wait_for_preprocessing(owned, worker_processes[-1], jobs[index - 1] / "worker.log", samplers)
                env = policy(count, candidate, job / "scratch", args.kernel_variant, args.workgroup,
                             getattr(args, "diagnostic_profile", False), options)
                cpu_env = baseline.environment(baseline.arm("cpu", 18 // count), job / "scratch", False)
                cpu_env["LATTICA_V2_METAL_PIPELINE"] = "reference"
                log = (job / "check.log").open("w"); handles.append(log)
                check = owned.spawn([binaries["cpu"], "check-registered", job, *external], cpu_env, log,
                                    limit=2 * GIB)
                owned.wait(check)
                parent, child = socket.socketpair()
                sockets.extend([parent, child])
                env["LATTICA_V2_METAL_CONTROL_FD"] = str(child.fileno())
                log = (job / "worker.log").open("w"); handles.append(log)
                worker = owned.spawn([binaries["metal"], "--metal-worker"], env, log,
                                     pass_fds=(child.fileno(),), role="worker", limit=baseline.WORKER_RSS_LIMIT_BYTES)
                worker_processes.append(worker)
                launched = time.monotonic() - started
                result["worker_launches"].append({"index": index, "pid": worker.pid, "seconds": launched,
                    "threads": int(env["RAYON_NUM_THREADS"]),
                    "managed_bytes": int(env["LATTICA_V2_GPU_MANAGED_BYTES"]) if "LATTICA_V2_GPU_MANAGED_BYTES" in env else None})
                print(f"WORKER_START job={index} pid={worker.pid} elapsed={launched:.2f}s "
                      f"threads={env['RAYON_NUM_THREADS']} launch_phase={launch_phase}", flush=True)
                child.close()
                if getattr(args, "diagnostic_profile", False):
                    samplers.append(StackSampler(owned, worker, job, handles))
                parent.sendall((json.dumps({"sequence": 0, "args": ["aggregate-all", str(job), *external]}) + "\n").encode())
                parent.setblocking(False)
                ready.register(parent, selectors.EVENT_READ, (index, job, worker, cpu_env))
            buffers = {s: b"" for s in ready.get_map()}
            while ready.get_map():
                for sampler in samplers:
                    sampler.poll()
                owned.sample()
                for key, _ in ready.select(timeout=0.25):
                    index, job, worker, cpu_env = key.data
                    data = key.fileobj.recv(16384)
                    if not data:
                        raise RuntimeError(f"worker {index} closed its private channel before completion")
                    frame = buffers.get(key.fd, b"") + data
                    if len(frame) > 16384:
                        raise RuntimeError("oversize worker response")
                    buffers[key.fd] = frame
                    if b"\n" not in frame: continue
                    if not frame.endswith(b"\n") or frame.count(b"\n") != 1:
                        raise RuntimeError("invalid worker frame")
                    response = json.loads(frame)
                    if response.get("status") != "PROVED" or response.get("sequence") != 0:
                        raise RuntimeError("worker response mismatch")
                    ready.unregister(key.fileobj)
                    key.fileobj.setblocking(True)
                    key.fileobj.sendall(b'{"stop":true}\n')
                    owned.wait(worker)
                    text = (job / "worker.log").read_text()
                    verify_tuning(text, policy(count, candidate, job / "scratch", args.kernel_variant, args.workgroup,
                                             getattr(args, "diagnostic_profile", False), options))
                    nodes = re.findall(r"grouped_node_complete artifact=(\S+) resumed=(\S+)", text)
                    if len(nodes) != 7 or any(resumed != "false" for _, resumed in nodes):
                        raise RuntimeError("job did not produce seven fresh recursive proofs")
                    requested = options if candidate else {"quotient": "cpu", "pipeline": "reference"}
                    expected_gpu = requested["quotient"] == "gpu" or (requested["quotient"] == "auto" and requested["pipeline"] == "resident")
                    observed_gpu = "metal_quotient " in text and "gpu=true" in text
                    if observed_gpu != expected_gpu:
                        raise RuntimeError("quotient backend did not match the requested policy")
                    log = (job / "prune.log").open("w"); handles.append(log)
                    prune = owned.spawn([binaries["cpu"], "remove-inners", job, *external], cpu_env, log, limit=2 * GIB)
                    owned.wait(prune)
                    bundle = job / "root-only"; bundle.mkdir()
                    for name in [*baseline.FIXTURE_NAMES[:4], "node.3.0"]:
                        shutil.copy2(job / name, bundle / name)
                    log = (job / "audit.log").open("w"); handles.append(log)
                    audit = owned.spawn([binaries["audit"], "root-eight", bundle, *external], cpu_env, log, limit=2 * GIB)
                    owned.wait(audit)
                    if "grouped_artifact_audit=PASS" not in (job / "audit.log").read_text():
                        raise RuntimeError("independent audit marker missing")
                    result["jobs"].append({"index": index, "verified": True,
                        "proof_seconds": response["seconds"], "audited_completion_seconds": time.monotonic() - started,
                        "worker_peak_rss_bytes": owned.worker_peaks.get(str(worker.pid), 0),
                        "root_sha256": digest(bundle / "node.3.0"),
                        "worker_log_sha256": digest(job / "worker.log"), "audit_log_sha256": digest(job / "audit.log"),
                        "metal": [line for line in text.splitlines() if line.startswith(("metal_resident ", "metal_tuning ", "metal_checkpoint ", "metal_preprocessing_cache "))]})
                for process, role, _ in owned.children:
                    if role == "worker" and process.poll() not in (None, 0):
                        raise RuntimeError("worker failed before audit")
            result.update(status="VERIFIED", seconds=time.monotonic() - started,
                          aggregate_peak_rss_bytes=owned.peak,
                          swap_growth_bytes=max(0, owned.swap_peak-owned.before["swap_used_bytes"]),
                          memory_pressure_incident=owned.pressure_incident)
            result["verified_jobs_per_hour"] = count * 3600 / result["seconds"]
            result["valid_comparison"] = not result["swap_growth_bytes"] and not result["memory_pressure_incident"]
        except BaseException as error:
            result.update(status="FAILED", failure=str(error), seconds=time.monotonic()-started,
                          aggregate_peak_rss_bytes=owned.peak, worker_peaks=owned.worker_peaks,
                          swap_growth_bytes=max(0,owned.swap_peak-owned.before["swap_used_bytes"]),
                          memory_pressure_incident=owned.pressure_incident)
            save(directory / "result.json",result)
            raise
        finally:
            owned.close()
            if samplers:
                result["diagnostic_samples"] = [row for sampler in samplers for row in sampler.summary()]
                if result["status"] == "FAILED":
                    save(directory / "result.json", result)
            ready.close()
            for s in sockets: s.close()
            for handle in handles: handle.close()
    result["resources_sha256"] = digest(directory / "resources.jsonl")
    return result


def render(report, destination):
    windows = report.get("windows", [])
    scale = max((w["verified_jobs_per_hour"] for w in windows), default=1)
    bars = "".join(f'<div class="row"><b>{html.escape(w["label"])} · {w["workers"]} worker(s)</b>'
        f'<div class="track"><div class="bar throughput-bar" style="width:{100*w["verified_jobs_per_hour"]/scale:.2f}%"></div></div>'
        f'<strong>{w["verified_jobs_per_hour"]:.2f} verified jobs/hour</strong>'
        f'<small>{w["seconds"]:.2f}s window · {w["aggregate_peak_rss_bytes"]/GIB:.2f} GiB aggregate peak RSS · '
        f'{len(w["jobs"])} independent CPU audit(s)</small></div>' for w in windows)
    attempts = windows + report.get("failed_windows", [])
    memory_scale_gib = max(1, max(((w["aggregate_peak_rss_bytes"] + GIB - 1) // GIB for w in attempts), default=1))
    memory_scale = memory_scale_gib * GIB
    rss_limit = report.get("aggregate_rss_limit_bytes", 44 * GIB)
    rss_policy = "no fixed aggregate RSS cap" if rss_limit is None else f"{rss_limit/GIB:g} GiB aggregate RSS budget"
    memory_bars = "".join(f'<div class="row"><b>{html.escape(w["label"])} · {w["workers"]} worker(s) · {html.escape(w["status"])}</b>'
        f'<div class="track"><div class="bar memory-bar" style="width:{100*w["aggregate_peak_rss_bytes"]/memory_scale:.2f}%"></div></div>'
        f'<strong>{w["aggregate_peak_rss_bytes"]/GIB:.2f} GiB sampled aggregate peak RSS</strong>'
        f'<small>{w["seconds"]:.2f}s elapsed · {html.escape(w.get("failure_detail", w.get("failure", "audited window")))}</small></div>' for w in attempts)
    rows = "".join(f'<tr><td>{html.escape(w["label"])} / {j["index"]}</td><td>{j["proof_seconds"]:.2f}</td>'
        f'<td>{j["audited_completion_seconds"]:.2f}</td><td>{j["worker_peak_rss_bytes"]/GIB:.2f}</td><td>PASS</td></tr>'
        for w in windows for j in w["jobs"])
    table = ('<div class="table-scroll"><table><thead><tr><th>Job</th><th>Proof seconds</th><th>Audited completion seconds</th><th>Worker GiB</th><th>CPU audit</th></tr></thead><tbody>' + rows + '</tbody></table></div>') if rows else ''
    gain = report.get("throughput_ratio")
    verdict = f'{gain:.2f}× observed throughput; 2× target {"met" if report.get("target_met") else "not met"}.' if gain else "Screen incomplete; no throughput comparison claimed."
    if not windows:
        bars = '<p>No job completed its independent audit, so verified throughput is unavailable.</p>'
    followup = html.escape(report.get("post_screen_changes", ""))
    planning = report.get("resident_worker_plan")
    planning_note = (f'<p>Resident worker planning: {planning["selected_workers"]} worker(s), '
        f'{planning["per_worker_estimate_bytes"]/GIB:g} GiB estimated per worker and '
        f'{planning["system_reserve_bytes"]/GIB:g} GiB reserved for the system. '
        'Scratch overlaps tracked backing. Estimates select concurrency before startup; '
        'resident allocations are tracked without a fixed backing or scratch ceiling.</p>') if planning else ''
    time_note = ('<p>No total screen deadline or proving-worker timeout. Memory-pressure monitoring remains active.</p>'
        if "benchmark_budget_seconds" in report and report["benchmark_budget_seconds"] is None
        and "worker_timeout_seconds" in report and report["worker_timeout_seconds"] is None else '')
    evidence = json.dumps(report).replace("<", "\\u003c")
    destination.write_text(f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Lattica · Apple GPU throughput screen</title><style>
body{{font:16px/1.6 system-ui;color:#e9eef8;background:#101724;max-width:1000px;margin:40px auto;padding:0 24px}}h1{{line-height:1.2}}.row{{margin:28px 0}}.track{{background:#283345;border-radius:5px;margin:8px 0;height:30px}}.bar{{background:#67c9ba;height:100%;border-radius:5px}}small{{display:block;color:#b4c2d7}}table{{border-collapse:collapse;width:100%;font-size:14px}}.table-scroll{{overflow-x:auto}}td,th{{text-align:left;border-bottom:1px solid #394555;padding:8px}}pre{{white-space:pre-wrap;overflow-wrap:anywhere}}button{{padding:10px;background:#67c9ba;border:0;border-radius:4px}}
</style><h1>Lattica on Apple Silicon</h1><p>GPU throughput screening · 18 CPU threads total · {rss_policy}</p>
{planning_note}
{time_note}
<p><strong>{html.escape(verdict)}</strong></p><p>{html.escape(report["status"])}. {html.escape(report.get("failure", ""))}</p>
<h2>Verified throughput</h2>{bars}<h2>Sampled RSS during the attempts</h2>
<p>Horizontal scale: 0–{memory_scale_gib} GiB, sized to the observed peaks. Failed attempts ended early, so these peaks are not a completed-workload memory comparison. macOS may account GPU pages in footprint differently from process RSS.</p>
{memory_bars}<p>{followup}</p>{table}
<p>One timing window per configuration, with no statistical confidence claim. Throughput counts completed eight-wallet recursive aggregations, not accepted blockchain transactions. Both configurations use this Mac’s unified memory; the comparison tests the implementation and concurrency together and does not isolate a hardware architecture effect.</p>
<p>Window timing includes process startup, checks, proof generation, pruning and independent CPU auditing. GPU timing counters overlap CPU phases; shared-buffer and RSS accounting overlap and must not be added. Resource limits are sampled watchdog limits.</p>
<p>Base Git commit (implementation changes are recorded by the source hashes): <code>{html.escape(report["git_commit"])}</code>; exact source and binary hashes are included below.</p>
<button id="download">Download evidence JSON</button><details><summary>Evidence and provenance</summary><pre id="details"></pre></details>
<script id="evidence" type="application/json">{evidence}</script><script>
const data=JSON.parse(document.getElementById('evidence').textContent);document.getElementById('details').textContent=JSON.stringify(data,null,2);document.getElementById('download').onclick=()=>{{const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([JSON.stringify(data,null,2)],{{type:'application/json'}}));a.download='apple-gpu-throughput.json';a.click();setTimeout(()=>URL.revokeObjectURL(a.href),0)}};
</script></html>''')


@contextlib.contextmanager
def coordinator_lease():
    path=Path("/tmp") / f"lattica-metal-throughput-{os.getuid()}.lock"
    fd=os.open(path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        info=os.fstat(fd)
        if info.st_uid != os.getuid() or not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
            raise RuntimeError("unsafe coordinator lease")
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workers", type=int, choices=(1, 2),
                        help="maximum resident workers; default estimates capacity, up to two")
    parser.add_argument("--threads-total", type=int, choices=(18,), default=18)
    parser.add_argument("--screen", action="store_true", required=True)
    parser.add_argument("--diagnostic-profile", action="store_true",
                        help="record host/GPU timelines and two short CPU stack samples per job")
    parser.add_argument("--worker-launch-phase", choices=("immediate", "after-preprocessing"), default="immediate",
                        help="optionally start the second candidate after the first worker's initial preprocessing")
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--linux", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--html", type=Path, required=True)
    parser.add_argument("--kernel-variant", choices=("reference", "optimized"), default="reference")
    parser.add_argument("--kernel-screen", type=Path)
    parser.add_argument("--qualification", type=Path, required=True)
    parser.add_argument("--workgroup", type=int, choices=(128, 256), default=256)
    for key, (_, default, choices) in TUNING.items():
        parser.add_argument("--candidate-" + key.replace("_", "-"), choices=choices, default=default)
    args = parser.parse_args()
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        parser.error("requires Apple Silicon macOS")
    worker_plan = resident_worker_plan(args.workers)
    args.workers = worker_plan["selected_workers"]
    try:
        validate_candidate_workers(args.workers, candidate_options(args))
    except ValueError as error:
        parser.error(str(error))
    out = args.output.resolve(); out.mkdir(parents=True, exist_ok=False)
    build = json.loads(args.build.read_text())
    for name, sha in build["source_hashes"].items():
        if digest(ROOT / name) != sha: raise RuntimeError("build source changed: " + name)
    qualification = json.loads(args.qualification.read_text())
    if qualification["status"] != "PASS" or qualification["proof_source_sha256"] != build["source_hashes"]:
        raise RuntimeError("resident qualification does not match build sources")
    binary_names = {"cpu": "block-v2-grouped-probe", "audit": "block-v2-grouped-artifact-audit", "metal": "block-v2-metal-grouped-probe"}
    (out / "bin").mkdir(); binaries = {}
    for role, name in binary_names.items():
        entry = build["binaries"][name]
        if digest(entry["path"]) != entry["sha256"]: raise RuntimeError("binary hash mismatch")
        binaries[role] = out / "bin" / name; shutil.copy2(entry["path"], binaries[role])
    linux = json.loads(args.linux.read_text())
    external = linux["benchmark_plan"]["config"]["external"]
    (out / "fixture").mkdir()
    for name in baseline.FIXTURE_NAMES:
        source = args.fixture / name
        if source.is_symlink() or not source.is_file(): raise RuntimeError("invalid fixture")
        shutil.copy2(source, out / "fixture" / name)
    for name in baseline.FIXTURE_NAMES[:4]:
        if digest(out / "fixture" / name) != linux["benchmark_plan"]["source_artifacts"][name]["sha256"]:
            raise RuntimeError("fixture registry differs from pinned Linux source")
    sources = [ROOT / n for n in build["source_hashes"]]
    sources += list((ROOT / "scripts").glob("*.py"))
    with tarfile.open(out / "source.tar.gz", "w:gz") as archive:
        for source in sources: archive.add(source, arcname=str(source.relative_to(ROOT)))
    report = {"schema": "apple-metal-throughput-v1", "status": "RUNNING", "windows": [], "build": build,
              "git_commit": build["git_commit"], "source_archive_sha256": digest(out / "source.tar.gz"),
              "fixture_sha256": {n: digest(out / "fixture" / n) for n in baseline.FIXTURE_NAMES},
              "controller_sha256": digest(__file__), "external": external,
              "kernel_variant": args.kernel_variant, "workgroup": args.workgroup,
              "candidate_options": candidate_options(args),
              "aggregate_rss_limit_bytes": baseline.AGGREGATE_RSS_LIMIT_BYTES,
              "worker_rss_limit_bytes": baseline.WORKER_RSS_LIMIT_BYTES,
              "resident_worker_plan": worker_plan,
              "hardware": subprocess.check_output(["/usr/sbin/sysctl", "machdep.cpu.brand_string", "hw.memsize", "hw.ncpu"], text=True),
              "benchmark_budget_seconds": None, "worker_timeout_seconds": None, "production_ready": False,
              "diagnostic_profile": args.diagnostic_profile,
              "qualification": qualification,
              "kernel_screen": json.loads(args.kernel_screen.read_text()) if args.kernel_screen else None}
    save(out / "result.json", report)
    def interrupted(signum, frame): raise KeyboardInterrupt(f"controller signal {signum}")
    signal.signal(signal.SIGTERM, interrupted)
    try:
        for candidate in (False, True):
            print("START", ("candidate " + args.candidate_pipeline) if candidate else "reference", flush=True)
            report["windows"].append(run_window(args, out, binaries, external, candidate))
            save(out / "result.json", report)
        ref, candidate = report["windows"]
        report["throughput_ratio"] = candidate["verified_jobs_per_hour"] / ref["verified_jobs_per_hour"]
        report["valid_comparison"] = all(w["valid_comparison"] for w in report["windows"])
        report["target_met"] = report["valid_comparison"] and report["throughput_ratio"] >= 2
        report["status"] = "COMPLETE_VERIFIED_SCREEN" if report["valid_comparison"] else "INVALID_RESOURCE_COMPARISON"
    except BaseException as error:
        report["failed_windows"]=[json.loads(p.read_text()) for p in out.glob("*/result.json")]
        report.update(status="FAILED", failure=str(error))
        raise
    finally:
        save(out / "result.json", report)
        render(report, args.html)


if __name__ == "__main__":
    with coordinator_lease():
        main()
