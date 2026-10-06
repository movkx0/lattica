#!/usr/bin/env python3
"""Alternate fresh typed constructions under one checked resource assignment.

This measures recursive solving latency on identical public inputs. Wallet
proving, registration, durable host application and delivered throughput are
outside the timed boundary. Import results into the report after all trials stop.
"""

import argparse
import importlib.util
import json
import math
import os
from pathlib import Path
import signal
import statistics
import subprocess
import sys
import time

SPEC = importlib.util.spec_from_file_location("typed_runner", Path(__file__).with_name("block-v2-typed-gpu-run.py"))
T = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(T)


def pin(path):
    path = Path(path).resolve(strict=True)
    return {"path": str(path), "sha256": T.G.digest(path), "bytes": path.stat().st_size}


def validate_public_fixtures(fixtures, count):
    if len(fixtures) != 2:
        raise ValueError("comparison requires two distinct constructions")
    for construction, directory in fixtures.items():
        T.fixture_files(directory, 64, construction)
    baseline, candidate = fixtures.values()
    names = ["body.json", *(f"wallet.{index}" for index in range(64))]
    public = {name: T.G.digest(baseline / name) for name in names}
    if any(T.G.digest(candidate / name) != sha for name, sha in public.items()):
        raise ValueError("both constructions must use the same 64 public leaves and body")
    heights = [json.loads((directory / "height.json").read_text()) for directory in fixtures.values()]
    if heights[0] != heights[1]:
        raise ValueError("both constructions must use the same shared proof height")
    body = json.loads((baseline / "body.json").read_text())
    kinds = [entry["kind"] for entry in body["transactions"][:count]]
    if len(kinds) != count:
        raise ValueError("public fixture does not contain the requested ordered prefix")
    return {"identical_files": public, "height": heights[0], "ordered_input_kinds": kinds,
            "user_inputs": sum(kind != "issuance" for kind in kinds),
            "issuance_inputs": sum(kind == "issuance" for kind in kinds)}


def trial_order(pair, baseline="reference", candidate="finalizer"):
    return (baseline, candidate) if pair % 2 else (candidate, baseline)


def checked_trial(directory, construction, count, assignment, assignment_sha, gpu_sha):
    summary = json.loads((directory / "summary.json").read_text())
    result_path = directory / "001-typed/result.json"
    result = json.loads(result_path.read_text())
    if (summary.get("status") != "succeeded" or result.get("status") != "succeeded"
            or summary.get("result") != result
            or summary.get("schema") != "lattica-typed-gpu-bootstrap-v1"
            or result.get("schema") != "lattica-typed-gpu-bootstrap-v1"):
        raise ValueError("worker and controller did not both succeed with the same result")
    spec = T.construction_spec(construction)
    if (result.get("construction") != construction or result.get("registry_keys") != spec["keys"]
            or result.get("count") != count or result.get("cpu_audited") is not True
            or result.get("binary_sha256") != gpu_sha
            or result.get("resource_assignment_sha256") != assignment_sha):
        raise ValueError("trial identity, independent CPU audit or assignment provenance differs")
    if T.resource_signature(result["budget"]) != assignment["limits"]:
        raise ValueError("trial changed the fixed resource assignment")
    T.validate_accounting(summary["accounting"], result["budget"])
    plan = json.loads((directory / "plan.json").read_text())
    T.validate_plan(plan, construction)
    T.validate_fresh_nodes(plan, directory / "001-typed/prove.log", directory / "001-typed/prove.log")
    if result.get("fresh_proofs") != plan["fresh_proofs"]:
        raise ValueError("trial did not produce the planned number of fresh proofs")
    bundle = directory / "001-typed/root-only"
    required = {*T.public_names(construction), "expected.json", "node.6.0"}
    if set(result["artifacts"]) != required or {p.name for p in bundle.iterdir()} != required:
        raise ValueError("root-only audit bundle contains unexpected or missing artifacts")
    for name, sha in result["artifacts"].items():
        path = bundle / name
        if path.is_symlink() or not path.is_file() or T.G.digest(path) != sha:
            raise ValueError("root-only audit artifact changed")
    if not 0 < result["root_bytes"] <= 2 * T.R.MIB or (bundle / "node.6.0").stat().st_size != result["root_bytes"]:
        raise ValueError("root size does not match the retained artifact or the 2 MiB limit")
    audits = T.public_events(directory / "001-typed/audit.log", "independent_cpu_root_audit")
    if (len(audits) != 1 or audits[0].get("passed") is not True
            or audits[0].get("count") != count or audits[0].get("depth") != 6
            or audits[0].get("root_bytes") != result["root_bytes"]):
        raise ValueError("independent CPU audit event does not match the retained root")
    for key in ("elapsed_seconds", "proving_seconds", "cpu_audit_seconds"):
        value = result[key]
        if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
            raise ValueError("trial timing must be finite and positive")
    return {"construction": construction, "worker_seconds": result["elapsed_seconds"],
            "proving_seconds": result["proving_seconds"], "cpu_audit_seconds": result["cpu_audit_seconds"],
            "fresh_proofs": result["fresh_proofs"], "cpu_audited": True,
            "root_bytes": result["root_bytes"], "root_sha256": result["artifacts"]["node.6.0"],
            "peak_charged_ram_bytes": int(summary["accounting"]["memory.peak"]),
            "context_measurement": summary["context_measurement"],
            "result_source": pin(result_path), "summary_source": pin(directory / "summary.json")}


def pair_measurement(number, trials, baseline="reference", candidate="finalizer"):
    if baseline == candidate or len(trials) != 2 or {t["construction"] for t in trials} != {baseline, candidate}:
        raise ValueError("a matched pair requires both constructions")
    times = {trial["construction"]: trial["worker_seconds"] for trial in trials}
    if any(type(v) not in (int, float) or not math.isfinite(v) or v <= 0 for v in times.values()):
        raise ValueError("matched pair requires finite positive timings")
    return {"pair": number, "order": [trial["construction"] for trial in trials],
            "worker_seconds": times,
            "worker_reduction_percent": 100 * (1 - times[candidate] / times[baseline])}


def aggregate(pairs, baseline="reference", candidate="finalizer"):
    if not pairs:
        return None
    reductions = [pair["worker_reduction_percent"] for pair in pairs]
    return {"matched_pairs": len(pairs),
            "median_worker_seconds": {name: statistics.median(pair["worker_seconds"][name] for pair in pairs)
                for name in (baseline, candidate)},
            "median_within_pair_reduction_percent": statistics.median(reductions),
            "within_pair_reduction_range_percent": [min(reductions), max(reductions)],
            f"{candidate}_faster_pairs": sum(value > 0 for value in reductions)}


def execute_controller(command, log, timeout):
    with log.open("x") as stream:
        process = subprocess.Popen(command, stdout=stream, stderr=subprocess.STDOUT,
                                   env=T.clean_environment(), start_new_session=True)
        try:
            code = process.wait(timeout=timeout)
        except BaseException:
            if process.poll() is None:
                process.send_signal(signal.SIGINT)
                # The child controller owns cgroup cleanup. Never launch another
                # trial if that cleanup cannot be confirmed.
                process.wait(timeout=60)
            raise
    if code != 0:
        raise subprocess.CalledProcessError(code, command)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", choices=T.CONSTRUCTIONS, default="reference")
    parser.add_argument("--candidate", choices=T.CONSTRUCTIONS, default="finalizer")
    parser.add_argument("--ram-admission", choices=("full", "compact"), default="full")
    for role, legacy in (("baseline", "reference"), ("candidate", "finalizer")):
        for kind in ("gpu", "cpu", "fixture"):
            parser.add_argument(f"--{role}-{kind}", f"--{legacy}-{kind}", dest=f"{role}_{kind}", type=Path, required=True)
    parser.add_argument("--gpu-uuid", required=True)
    parser.add_argument("--count", type=int, choices=T.COUNTS, default=4)
    parser.add_argument("--pairs", type=int, default=5)
    parser.add_argument("--scratch", type=Path, default=Path("/tmp"))
    parser.add_argument("--workload", type=Path,
                        default=Path(__file__).with_name("block-v2-multi-gpu-direct-readback-workload.json"))
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--trial-timeout", type=int, default=7200)
    args = parser.parse_args()
    if args.baseline == args.candidate:
        parser.error("baseline and candidate must be distinct constructions")
    if not 1 <= args.pairs <= 10 or args.trial_timeout <= 0:
        parser.error("pairs must be between 1 and 10 and trial timeout must be positive")
    os.umask(0o077)
    out = args.evidence.resolve()
    out.mkdir(parents=True, exist_ok=False)
    report = {"schema": "lattica-typed-comparison-v1", "status": "preparing", "count": args.count,
              "baseline_construction": args.baseline, "candidate_construction": args.candidate,
              "ram_admission": args.ram_admission,
              "requested_pairs": args.pairs, "trials": [], "pairs": [], "active_trial": None,
              "production_ready": False, "delivered_transactions_measured": False,
              "timing_boundary": "Worker fixture copy, fresh recursive proving and independent CPU root audit; wallet proving, registration and durable host application excluded."}
    started = time.monotonic()
    try:
        roles = {args.baseline: "baseline", args.candidate: "candidate"}
        fixtures = {name: getattr(args, f"{role}_fixture").resolve(strict=True) for name, role in roles.items()}
        binaries = {name: {kind: getattr(args, f"{role}_{kind}").resolve(strict=True) for kind in ("gpu", "cpu")}
                    for name, role in roles.items()}
        inputs = [Path(__file__), Path(T.__file__), Path(T.G.__file__), Path(T.R.__file__), args.workload]
        for name, directory in fixtures.items():
            inputs.extend(T.fixture_files(directory, 64, name))
            inputs.extend(binaries[name].values())
        pins = dict(T.pin(path) for path in inputs)
        report["input_pins"] = pins
        report["public_fixture"] = validate_public_fixtures(fixtures, args.count)
        locks = T.G.lock_fleet()
        try:
            if json.loads(T.G.systemctl("list-units", "lattica-v2-multi-*.service", "--state=active,activating,deactivating", "--output=json", "--no-pager")):
                raise ValueError("another worker is active during comparison preparation")
            T.G.systemctl("start", T.G.SLICE)
            host = T.G.detect_worker_host(str(args.scratch.resolve(strict=True)))
            devices = [d for d in T.R.detect_gpus(str(binaries[args.baseline]["gpu"])) if d["uuid"] == args.gpu_uuid]
            if len(devices) != 1:
                raise ValueError("comparison GPU UUID was not uniquely detected")
            profiles = {name: T.resource_profile(args.workload, name, args.ram_admission) for name in fixtures}
            automatic = T.assigned_budget(host, devices[0], profiles[args.baseline])
            assignment = T.comparison_assignment(automatic, profiles[args.baseline])
            for name, profile in profiles.items():
                T.apply_resource_assignment(T.assigned_budget(host, devices[0], profile), assignment, profile)
            T.G.durable(out / "initial-admission.json", {"host": host, "device": devices[0], "automatic_budget": automatic}, True)
            assignment_path = out / "resource-assignment.json"
            T.G.durable(assignment_path, assignment, True)
        finally:
            for lock in locks:
                os.close(lock)
        report["resource_assignment"] = pin(assignment_path)
        report["resource_limits"] = assignment["limits"]
        pins.update(dict([T.pin(assignment_path)]))
        report["status"] = "running"
        T.G.durable(out / "summary.json", report, True)
        print(json.dumps({"status": "running", "assignment": report["resource_assignment"],
                          "worker_bytes": assignment["limits"]["host"]["worker_bytes"],
                          "rayon_threads": assignment["limits"]["cpu"]["rayon_threads"]}), flush=True)
        for number in range(1, args.pairs + 1):
            pair_trials = []
            for name in trial_order(number, args.baseline, args.candidate):
                T.check_pins(pins)
                directory = out / f"pair-{number:02d}-{name}"
                command = [sys.executable, str(Path(T.__file__)), "--construction", name,
                    "--ram-admission", args.ram_admission,
                           "--gpu-binary", str(binaries[name]["gpu"]), "--cpu-binary", str(binaries[name]["cpu"]),
                           "--fixture", str(fixtures[name]), "--gpu-uuid", args.gpu_uuid,
                           "--count", str(args.count), "--scratch", str(args.scratch.resolve()),
                           "--workload", str(args.workload.resolve()), "--resource-assignment", str(assignment_path),
                           "--evidence", str(directory)]
                active = {"pair": number, "construction": name, "directory": str(directory), "command": command}
                report["active_trial"] = active
                T.G.durable(out / "summary.json", report)
                print(json.dumps({"event": "trial_started", "pair": number, "construction": name, "directory": str(directory)}), flush=True)
                execute_controller(command, out / f"pair-{number:02d}-{name}.controller.log", args.trial_timeout)
                T.check_pins(pins)
                trial = checked_trial(directory, name, args.count, assignment,
                                      report["resource_assignment"]["sha256"], pins[str(binaries[name]["gpu"])])
                trial["pair"] = number
                report["trials"].append(trial)
                pair_trials.append(trial)
                report["active_trial"] = None
                T.G.durable(out / "summary.json", report)
                print(json.dumps({"event": "trial_succeeded", "pair": number, "construction": name,
                                  "worker_seconds": trial["worker_seconds"], "fresh_proofs": trial["fresh_proofs"]}), flush=True)
            report["pairs"].append(pair_measurement(number, pair_trials, args.baseline, args.candidate))
            report["comparison"] = aggregate(report["pairs"], args.baseline, args.candidate)
            T.G.durable(out / "summary.json", report)
        T.check_pins(pins)
        report.update(status="succeeded", input_pins_unchanged=True,
                      cpu_audited_roots=len(report["trials"]),
                      fresh_recursive_proofs=sum(trial["fresh_proofs"] for trial in report["trials"]))
    except BaseException as error:
        report.update(status="failed", failure=f"{type(error).__name__}: {error}")
        raise
    finally:
        report["controller_elapsed_seconds"] = time.monotonic() - started
        T.G.durable(out / "summary.json", report)
        print(json.dumps({"status": report["status"], "completed_pairs": len(report["pairs"]),
                          "completed_trials": len(report["trials"])}), flush=True)


if __name__ == "__main__":
    main()
