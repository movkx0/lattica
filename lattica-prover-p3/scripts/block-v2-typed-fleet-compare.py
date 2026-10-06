#!/usr/bin/env python3
"""Repeat fixed-allocation, CPU-audited mixed roots sequentially and concurrently.

Each GPU solves an independent root. Worker windows exclude registry preparation,
wallet proving and durable host application. Failed attempts remain evidence and
stop the campaign. Render the benchmark report only after this controller exits.
"""

import argparse
import importlib.util
import json
import math
import os
from pathlib import Path
import statistics
import sys

SPEC = importlib.util.spec_from_file_location("typed_fleet", Path(__file__).with_name("block-v2-typed-multi-gpu-run.py"))
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)
C, T, G = F.C, F.T, F.G


def trial_order(number):
    return ("sequential", "concurrent") if number % 2 else ("concurrent", "sequential")


def checked_fleet(directory, mode, construction, count, assignment, gpu_sha, cpu_sha, profile_sha, fixture_pins):
    summary_path = directory / "summary.json"
    summary = json.loads(summary_path.read_text())
    uuids = set(assignment["limits_by_gpu"])
    if (summary.get("schema") != "lattica-typed-fleet-v1" or summary.get("status") != "succeeded"
            or summary.get("mode") != mode or summary.get("construction") != construction
            or summary.get("count_per_root") != count or summary.get("ram_admission") != "compact"
            or summary.get("worker_slots") != len(uuids) or summary.get("cpu_audited_roots") != len(uuids)
            or summary.get("cleanup_failures")):
        raise ValueError("fleet identity, CPU audits or cleanup did not qualify")
    assigned_path = directory / "resource-assignment.json"
    if (json.loads(assigned_path.read_text()) != assignment
            or summary["resource_assignment"]["sha256"] != G.digest(assigned_path)):
        raise ValueError("fleet changed the fixed resource assignment")
    T.check_pins(summary["input_pins"])
    controller = Path(F.__file__).resolve()
    if summary["input_pins"].get(str(controller)) != G.digest(controller):
        raise ValueError("fleet controller differs from the pinned comparison controller")
    deltas = F.event_deltas(summary["parent_memory_events_before"], summary["parent_memory_events_after"])
    if summary.get("parent_memory_event_deltas") != deltas:
        raise ValueError("fleet memory-event accounting differs")
    if (len(summary["attempts"]) != len(uuids)
            or {a["uuid"] for a in summary["attempts"]} != uuids
            or any(a["status"] != "succeeded" for a in summary["attempts"])):
        raise ValueError("fleet attempts did not all succeed")
    if len(summary["trials"]) != len(uuids) or {t["gpu_uuid"] for t in summary["trials"]} != uuids:
        raise ValueError("fleet trial coverage differs")
    checked, starts, finishes = [], [], []
    pins = {str(summary_path): G.digest(summary_path), str(assigned_path): G.digest(assigned_path)}
    for trial in summary["trials"]:
        local = Path(trial["summary_source"]["path"]).parent
        if local.resolve().parent != directory.resolve():
            raise ValueError("worker evidence is outside its fleet directory")
        local_assignment_path = local / "resource-assignment.json"
        local_assignment = json.loads(local_assignment_path.read_text())
        if local_assignment.get("limits") != assignment["limits_by_gpu"][trial["gpu_uuid"]]:
            raise ValueError("worker allocation differs from its assigned GPU")
        verified = C.checked_trial(local, construction, count, local_assignment,
                                   G.digest(local_assignment_path), gpu_sha)
        for key in ("worker_seconds", "fresh_proofs", "root_bytes", "root_sha256", "cpu_audited"):
            if verified[key] != trial[key]:
                raise ValueError("fleet summary differs from audited worker result")
        result = json.loads((local / "001-typed/result.json").read_text())
        if result["profile_sha256"] != profile_sha:
            raise ValueError("worker proof profile changed")
        config = json.loads((local / "config.json").read_text())
        if config["pins"].get(config["cpu_binary"]) != cpu_sha:
            raise ValueError("worker CPU audit binary changed")
        actual_fixture = {path.name: G.digest(path) for path in T.fixture_files(
            Path(config["fixture"]), count, construction)}
        if actual_fixture != fixture_pins:
            raise ValueError("worker public inputs or wallet fixtures changed")
        for source in (trial["summary_source"], trial["result_source"]):
            if G.digest(Path(source["path"])) != source["sha256"]:
                raise ValueError("fleet worker evidence changed")
            pins[source["path"]] = source["sha256"]
        telemetry_path = local / "001-typed/telemetry.jsonl"
        stamps = [json.loads(line)["time_ns"] for line in telemetry_path.read_text().splitlines()]
        if (not stamps or any(type(t) is not int or t <= 0 for t in stamps)
                or any(later < earlier for earlier, later in zip(stamps, stamps[1:]))):
            raise ValueError("worker timestamps are missing or not ordered")
        starts.append(stamps[0])
        finishes.append(stamps[-1])
        for name, expected in result["artifacts"].items():
            pins[str(local / "001-typed/root-only" / name)] = expected
        for path in (telemetry_path, local / "config.json", local / "plan.json", local_assignment_path,
                     *(local / "001-typed" / name for name in ("prove.log", "audit.log", "accounting.json"))):
            pins[str(path)] = G.digest(path)
        checked.append(trial)
    if summary["fresh_recursive_proofs"] != sum(t["fresh_proofs"] for t in checked):
        raise ValueError("fleet proof count differs from complete workers")
    elapsed = summary.get("execution_elapsed_seconds")
    if type(elapsed) not in (int, float) or not math.isfinite(elapsed) or elapsed <= 0:
        raise ValueError("fleet timing is not a finite positive duration")
    return {"mode": mode, "execution_elapsed_seconds": elapsed, "trials": checked,
            "first_worker_sample_ns": min(starts), "last_worker_sample_ns": max(finishes),
            "cpu_audited_roots": len(checked), "fresh_recursive_proofs": summary["fresh_recursive_proofs"],
            "source": C.pin(summary_path), "pins": pins}


def pair_measurement(number, trials):
    if len(trials) != 2 or [t["mode"] for t in trials] != list(trial_order(number)):
        raise ValueError("matched pair requires the prescribed alternating trial order")
    if trials[0]["last_worker_sample_ns"] >= trials[1]["first_worker_sample_ns"]:
        raise ValueError("matched pair timestamps overlap or contradict the prescribed order")
    times = {t["mode"]: t["execution_elapsed_seconds"] for t in trials}
    if any(type(v) not in (int, float) or not math.isfinite(v) or v <= 0 for v in times.values()):
        raise ValueError("matched pair requires finite positive durations")
    return {"pair": number, "order": list(trial_order(number)), "execution_elapsed_seconds": times,
            "within_pair_reduction_percent": 100 * (1 - times["concurrent"] / times["sequential"]),
            "sources": [t["source"] for t in trials]}


def aggregate(pairs):
    if not pairs:
        return None
    values = [p["within_pair_reduction_percent"] for p in pairs]
    return {"matched_pairs": len(pairs),
            "median_execution_elapsed_seconds": {mode: statistics.median(
                p["execution_elapsed_seconds"][mode] for p in pairs) for mode in ("sequential", "concurrent")},
            "median_within_pair_reduction_percent": statistics.median(values),
            "within_pair_reduction_range_percent": [min(values), max(values)],
            "concurrent_faster_pairs": sum(v > 0 for v in values)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gpu-binary", type=Path, required=True)
    parser.add_argument("--cpu-binary", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--gpu-uuid", action="append", required=True)
    parser.add_argument("--resource-assignment", type=Path, required=True)
    parser.add_argument("--calibration-trial", type=Path, action="append", required=True)
    parser.add_argument("--workload", type=Path, default=Path(__file__).with_name("block-v2-multi-gpu-direct-readback-workload.json"))
    parser.add_argument("--construction", choices=T.CONSTRUCTIONS, default="finalizer")
    parser.add_argument("--count", type=int, choices=T.COUNTS, default=4)
    parser.add_argument("--pairs", type=int, default=5)
    parser.add_argument("--trial-timeout", type=int, default=14400)
    parser.add_argument("--initial-sequential", type=Path)
    parser.add_argument("--initial-concurrent", type=Path)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.pairs <= 10 or args.trial_timeout <= 0:
        parser.error("pairs must be 1..10 and the trial timeout must be positive")
    if len(args.gpu_uuid) != 2 or len(set(args.gpu_uuid)) != 2:
        parser.error("the comparison requires two distinct GPU UUIDs")
    if bool(args.initial_sequential) != bool(args.initial_concurrent):
        parser.error("adopting the initial pair requires both execution modes")
    os.umask(0o077)
    out = args.evidence.resolve()
    out.mkdir(parents=True, exist_ok=False)
    report = {"schema": "lattica-typed-fleet-comparison-v1", "status": "preparing",
              "construction": args.construction, "count_per_root": args.count,
              "requested_pairs": args.pairs, "pairs": [], "trials": [], "active_trial": None,
              "repeat_qualified": False, "production_ready": False, "delivered_transactions_measured": False,
              "scope": "Two independent mixed roots under one fixed assignment; this is recursive aggregation qualification.",
              "timing_boundary": "Fleet execution includes launch, fixture copy, fresh proving, CPU audits, telemetry and cleanup. Registry preparation, wallet proving and durable application are excluded."}
    G.durable(out / "summary.json", report, True)
    try:
        assignment = json.loads(args.resource_assignment.read_text())
        if set(assignment.get("limits_by_gpu", {})) != set(args.gpu_uuid):
            raise ValueError("fixed assignment differs from requested GPU UUIDs")
        profile = T.resource_profile(args.workload, args.construction, "compact")
        gpu_sha = G.digest(args.gpu_binary)
        cpu_sha = G.digest(args.cpu_binary)
        profile_sha = G.profile_digest({"workload": profile})
        fixture_pins = {path.name: G.digest(path) for path in T.fixture_files(args.fixture, args.count, args.construction)}
        calibrations, calibration_pins = F.load_calibrations(args.calibration_trial, gpu_sha, profile,
            args.construction, args.count, assignment, args.gpu_uuid)
        inputs = [args.gpu_binary, args.cpu_binary, args.resource_assignment, args.workload,
                  Path(__file__), Path(F.__file__), Path(C.__file__), Path(T.__file__), Path(G.__file__), Path(F.R.__file__),
                  *T.fixture_files(args.fixture, args.count, args.construction)]
        pins = {**calibration_pins, **dict(T.pin(p.resolve(strict=True)) for p in inputs)}
        report.update(status="running", input_pins=pins, resource_assignment=assignment,
                      gpu_sha256=gpu_sha, cpu_sha256=cpu_sha, profile_sha256=profile_sha,
                      fixture_pins=fixture_pins, context_calibrations=calibrations)
        G.durable(out / "summary.json", report)
        for number in range(1, args.pairs + 1):
            pair_trials = []
            for mode in trial_order(number):
                adopted = getattr(args, "initial_" + mode) if number == 1 else None
                directory = adopted.resolve(strict=True) if adopted else out / f"pair-{number:02d}-{mode}"
                report["active_trial"] = {"pair": number, "mode": mode, "directory": str(directory), "adopted": bool(adopted)}
                G.durable(out / "summary.json", report)
                T.check_pins(pins)
                if not adopted:
                    command = [sys.executable, str(Path(F.__file__)), "--construction", args.construction,
                        "--ram-admission", "compact", "--gpu-binary", str(args.gpu_binary.resolve()),
                        "--cpu-binary", str(args.cpu_binary.resolve()), "--fixture", str(args.fixture.resolve()),
                        "--count", str(args.count), "--mode", mode, "--resource-assignment", str(args.resource_assignment.resolve()),
                        "--workload", str(args.workload.resolve()), "--evidence", str(directory)]
                    for uuid in args.gpu_uuid:
                        command += ["--gpu-uuid", uuid]
                    for trial in args.calibration_trial:
                        command += ["--calibration-trial", str(trial.resolve())]
                    print(json.dumps({"event": "fleet_trial_started", "pair": number, "mode": mode, "directory": str(directory)}), flush=True)
                    C.execute_controller(command, out / f"pair-{number:02d}-{mode}.controller.log", args.trial_timeout)
                trial = checked_fleet(directory, mode, args.construction, args.count, assignment,
                                      gpu_sha, cpu_sha, profile_sha, fixture_pins)
                pins.update(trial["pins"])
                pair_trials.append(trial)
                report["trials"].append(dict(trial, pair=number, adopted=bool(adopted)))
                report["active_trial"] = None
                G.durable(out / "summary.json", report)
            report["pairs"].append(pair_measurement(number, pair_trials))
            report["aggregate"] = aggregate(report["pairs"])
            G.durable(out / "summary.json", report)
            print(json.dumps({"event": "matched_pair_completed", **report["pairs"][-1]}), flush=True)
        T.check_pins(pins)
        report.update(status="succeeded", repeat_qualified=len(report["pairs"]) >= 5,
                      cpu_audited_roots=sum(t["cpu_audited_roots"] for t in report["trials"]),
                      fresh_recursive_proofs=sum(t["fresh_recursive_proofs"] for t in report["trials"]))
    except BaseException as error:
        report.update(status="failed", failure=f"{type(error).__name__}: {error}")
        raise
    finally:
        G.durable(out / "summary.json", report)
    print(json.dumps({"status": report["status"], "repeat_qualified": report["repeat_qualified"],
                      "aggregate": report["aggregate"]}), flush=True)


if __name__ == "__main__":
    main()
