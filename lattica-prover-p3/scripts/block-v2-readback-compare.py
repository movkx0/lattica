#!/usr/bin/env python3
"""Compare banded and direct readback with equal assigned worker limits."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import statistics
import subprocess
import sys
import time

FIXTURE_NAMES = ["height", "key.1", "key.2", "key.3", *[f"wallet.{i}" for i in range(8)]]


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def save(path, value):
    temporary = path.with_suffix(path.suffix + ".new")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


def validate_configs(configs, runner):
    signatures = []
    for layout in ("banded", "direct"):
        config = configs[layout]
        if (config.get("version") != 1 or config.get("max_concurrency") != 1 or
                config.get("worker_slots") != 1 or config.get("qualification_mode") is not True or
                len(config.get("gpu_uuids", [])) != 1 or len(config.get("jobs", [])) != 1):
            raise ValueError("each arm requires one GPU, one job and qualification-mode limits")
        workload = config["workload"]
        geometry = dict(workload["geometry"])
        if geometry.pop("host_readback_layout", "banded") != layout:
            raise ValueError("configuration does not select its declared readback layout")
        job = config["jobs"][0]
        if job.get("gpu_uuid", config["gpu_uuids"][0]) != config["gpu_uuids"][0]:
            raise ValueError("job is pinned to a different GPU")
        paths = [config[key] for key in ("gpu_binary", "cpu_binary", "auditor")]
        paths += [str(Path(job["source"]) / name) for name in FIXTURE_NAMES]
        paths.append(str(runner.resolve()))
        pins = {path: config["pins"][path] for path in paths}
        if any(digest(path) != sha for path, sha in pins.items()):
            raise ValueError("binary, runner or fixture pin changed")
        signatures.append({"gpu_uuids": config["gpu_uuids"], "pins": pins,
            "source": job["source"], "external": job["external"],
            "scratch": config["scratch"], "geometry": geometry,
            "workload": {key: workload[key] for key in ("version", "height", "page_bytes", "phases")}})
    if signatures[0] != signatures[1]:
        raise ValueError("arms must share binaries, fixture, geometry and conservative resource model")


def budget_signature(budget):
    if budget.get("qualification_capacity_test") is not True:
        raise ValueError("comparison requires qualification-mode worker limits")
    fields = {
        "gpu": ("uuid", "managed_bytes", "context_bytes", "total_bytes", "max_allocation_bytes"),
        "cpu": ("rayon_threads", "quota_percent", "allowed_cpus"),
        "host": ("worker_bytes", "spill_bytes", "swap_bytes", "tmpfs", "scratch_device", "scratch_path"),
    }
    return {section: {key: budget[section][key] for key in keys} for section, keys in fields.items()}


def validate_result(directory, summary, expected_layout):
    if (summary.get("status") != "succeeded" or len(summary.get("results", [])) != 1 or
            not summary["results"][0].get("cpu_audited")):
        raise ValueError("one successful, independently CPU-audited job is required")
    result = summary["results"][0]
    if result.get("status") != "succeeded":
        raise ValueError("worker did not succeed")
    if result["budget"].get("readback_layout", "banded") != expected_layout:
        raise ValueError("actual worker used the wrong readback layout")
    attempts = [p for p in directory.iterdir() if p.is_dir() and (p / "result.json").is_file()]
    if len(attempts) != 1:
        raise ValueError("comparison requires exactly one preserved worker result")
    attempt = attempts[0]
    preserved = json.loads((attempt / "result.json").read_text())
    # The runner's summary enriches the immutable worker result. Reconstruct
    # those fields from their own evidence rather than dropping them before
    # comparing: alterations to either the proof result or telemetry must fail.
    accounting = json.loads((attempt / "accounting.json").read_text())
    samples = [json.loads(line) for line in (attempt / "telemetry.jsonl").read_text().splitlines()]
    if not samples:
        raise ValueError("comparison requires preserved worker telemetry")
    preserved["accounting"] = accounting
    preserved["gpu_process_peak_bytes"] = max(
        sum(process["bytes"] for process in sample["gpu_processes"]) for sample in samples)
    if preserved != result:
        raise ValueError("worker result differs from the preserved summary")
    for record in [accounting, *samples]:
        if "memory.events" not in record:
            if record is accounting:
                raise ValueError("missing final worker memory events")
            continue  # The final telemetry sample may follow cgroup removal.
        events = dict(line.split() for line in record["memory.events"].splitlines())
        required = {"high", "max", "oom", "oom_kill", "oom_group_kill"}
        if not required.issubset(events) or any(int(value) != 0 for value in events.values()):
            raise ValueError("worker memory-limit events invalidate the timing comparison")
    if not 0 < int(accounting["memory.peak"]) <= preserved["budget"]["host"]["worker_bytes"]:
        raise ValueError("worker peak memory is outside its assigned limit")
    nodes = []
    for stage in ("pairs", "merges"):
        layouts = []
        for line in (attempts[0] / (stage + ".log")).read_text().splitlines():
            if line.startswith("grouped_node_complete "):
                nodes.append(dict(word.split("=", 1) for word in line.split()[1:]))
            elif line.startswith("bounded_lde_readback_layout "):
                layouts.append(dict(word.split("=", 1) for word in line.split()[1:])["layout"])
        if not layouts or set(layouts) != {expected_layout.title()}:
            raise ValueError("GPU execution logs do not confirm the requested readback layout")
    expected = {"node.1.0", "node.1.1", "node.1.2", "node.1.3", "node.2.0", "node.2.1", "node.3.0"}
    if len(nodes) != 7 or {n["artifact"] for n in nodes} != expected or any(n["resumed"] != "false" for n in nodes):
        raise ValueError("comparison requires seven fresh recursive proofs")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--banded-config", type=Path, required=True)
    parser.add_argument("--direct-config", type=Path, required=True)
    parser.add_argument("--runner", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--rounds", type=int, default=5)
    args = parser.parse_args()
    if args.rounds < 1:
        parser.error("rounds must be positive")
    configs = {name: json.loads(path.read_text()) for name, path in
               (("banded", args.banded_config), ("direct", args.direct_config))}
    runner = args.runner.resolve()
    validate_configs(configs, runner)
    os.umask(0o077)
    out = args.evidence.resolve()
    out.mkdir(parents=True, exist_ok=False)
    shutil.copy2(__file__, out / "comparison-controller.py")
    save(out / "input.json", {"configs": configs, "runner": str(runner), "runner_sha256": digest(runner),
                               "controller_sha256": digest(out / "comparison-controller.py"), "rounds": args.rounds})
    report = {"schema": "lattica-readback-comparison-v1", "status": "running", "rounds_requested": args.rounds,
              "trials": [], "production_ready": False,
              "timing_boundary": "worker elapsed includes checks, wrapping, merging and independent CPU root audit; controller elapsed also includes startup, fixture copying and cleanup",
              "cache_policy": "fresh recursive proofs per job; no OS or driver cache flush; preprocessing may be reused within each process"}
    signature = None
    roots = set()
    save(out / "summary.json", report)
    try:
        for repeat in range(1, args.rounds + 1):
            for layout in (("banded", "direct") if repeat % 2 else ("direct", "banded")):
                validate_configs(configs, runner)
                name = f"{repeat:02d}-{layout}"
                config = copy.deepcopy(configs[layout])
                config["jobs"][0]["id"] = name
                cfg, directory = out / (name + "-config.json"), out / name
                save(cfg, config)
                trial = {"repeat": repeat, "layout": layout, "status": "planning", "directory": str(directory)}
                report["trials"].append(trial)
                save(out / "summary.json", report)
                with (out / (name + "-plan-stderr.log")).open("w") as error:
                    plan = json.loads(subprocess.check_output([sys.executable, runner, "--config", cfg, "--plan"],
                                                             text=True, stderr=error))
                save(out / (name + "-plan.json"), plan)
                if plan["admitted_workers"] != 1 or len(plan["budgets"]) != 1:
                    raise ValueError("comparison requires exactly one admitted worker")
                budget = next(iter(plan["budgets"].values()))
                proposed = budget_signature(budget)
                if signature is not None and proposed != signature:
                    raise ValueError("assigned resource limits changed before trial; comparison stopped")
                if budget.get("readback_layout", "banded") != layout:
                    raise ValueError("planned layout differs from requested layout")
                trial["status"] = "running"
                save(out / "summary.json", report)
                print("START", name, flush=True)
                started = time.monotonic()
                try:
                    with (out / (name + "-controller.log")).open("w") as log:
                        subprocess.run([sys.executable, runner, "--config", cfg, "--evidence", directory],
                            stdout=log, stderr=subprocess.STDOUT, check=True,
                            env={**os.environ, "LATTICA_BENCHMARK_REPORT_DEFER": "1"})
                finally:
                    trial["controller_elapsed_seconds"] = time.monotonic() - started
                    save(out / "summary.json", report)
                summary = json.loads(subprocess.check_output([sys.executable, runner, "--summarize", directory], text=True))
                save(out / (name + "-worker-summary.json"), summary)
                result = validate_result(directory, summary, layout)
                actual = budget_signature(result["budget"])
                if actual != proposed or (signature is not None and actual != signature):
                    raise ValueError("actual worker limits changed; timing comparison is invalid")
                root = result["artifacts"]["node.3.0"]
                if root in roots:
                    raise ValueError("repeated root proof; fresh randomness required")
                roots.add(root)
                signature = actual
                trial.update(status="succeeded", worker_elapsed_seconds=result["elapsed_seconds"],
                             root_sha256=root, cpu_audited=True, budget=actual)
                save(out / "summary.json", report)
                print("PASS", name, result["elapsed_seconds"], flush=True)
        medians = {layout: statistics.median(t["worker_elapsed_seconds"] for t in report["trials"]
                                             if t["layout"] == layout) for layout in ("banded", "direct")}
        report.update(status="succeeded", median_worker_seconds=medians,
                      worker_time_reduction_percent=100 * (1 - medians["direct"] / medians["banded"]))
    except BaseException as error:
        report.update(status="failed", failure=f"{type(error).__name__}: {error}")
        if report["trials"] and report["trials"][-1]["status"] != "succeeded":
            report["trials"][-1]["status"] = "failed"
        raise
    finally:
        save(out / "summary.json", report)
        from block_v2_report_export import export_after_run
        export_after_run(out)


if __name__ == "__main__":
    main()
