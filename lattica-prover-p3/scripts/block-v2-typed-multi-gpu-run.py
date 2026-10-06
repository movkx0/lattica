#!/usr/bin/env python3
"""Qualify one fresh mixed root per selected GPU under a shared host budget.

Sequential and concurrent modes use the same number of planned worker slots.
Reuse resource-assignment.json for a later matched run; changed live capacity
rejects that assignment. These are independent research roots, not deliveries.
"""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import time

SPEC = importlib.util.spec_from_file_location("typed_comparison", Path(__file__).with_name("block-v2-typed-compare.py"))
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)
T, G, R = C.T, C.T.G, C.T.R


def calibration_assignment(directory, config, result):
    """Resolve either a pinned fixed assignment or a retained automatic budget."""
    configured = config.get("resource_assignment")
    if configured is not None:
        if not isinstance(configured, str) or not configured:
            raise ValueError("invalid calibration resource assignment path")
        path = Path(configured).resolve(strict=True)
        sha = G.digest(path)
        if (config["pins"].get(str(path)) != sha
                or config.get("resource_assignment_sha256") != sha):
            raise ValueError("calibration resource assignment is unpinned or differs from the recorded hash")
        return json.loads(path.read_text()), sha, [path]
    if (config.get("resource_assignment_sha256") is not None
            or result.get("resource_assignment_sha256") is not None):
        raise ValueError("automatic calibration budget has an unexplained assignment hash")
    budget_path = directory / "001-typed/budget.json"
    admission_path, attempt_path = directory / "admission.json", directory / "001-typed/attempt.json"
    budget = json.loads(budget_path.read_text())
    admission, attempt = json.loads(admission_path.read_text()), json.loads(attempt_path.read_text())
    if (budget != result.get("budget") or budget != admission.get("budget")
            or budget != attempt.get("budget") or config != attempt.get("config")):
        raise ValueError("automatic calibration budget or config differs across retained worker records")
    return ({"schema": "lattica-typed-resource-assignment-v1", "limits": T.resource_signature(budget)},
            None, [budget_path, admission_path, attempt_path])


def validate_backend_result(config, result):
    """Bind the retained result to the requested execution path and teardown."""
    if result.get("execution_backend", "bootstrap") != config.get("execution_backend", "bootstrap"):
        raise ValueError("worker result uses a different execution backend")
    T.validate_execution_result(config, result.get("execution_result", {}))


def load_calibrations(directories, gpu_sha, profile, construction, count, assignment, uuids,
                      execution_backend="bootstrap"):
    """Reuse context measurements only from complete, pinned trials of this allocation."""
    if not assignment or assignment.get("schema") != "lattica-typed-fleet-assignment-v1":
        raise ValueError("context calibration requires a fixed fleet assignment")
    if set(assignment.get("limits_by_gpu", {})) != set(uuids):
        raise ValueError("calibration assignment differs from selected GPU UUIDs")
    expected_profile = G.profile_digest({"workload": profile})
    calibrations, pins, seen = {}, {}, set()
    for candidate in directories:
        directory = candidate.resolve(strict=True)
        if directory in seen:
            raise ValueError("duplicate calibration trial")
        seen.add(directory)
        config_path = directory / "config.json"
        config = json.loads(config_path.read_text())
        T.check_pins(config["pins"])
        if config.get("execution_backend", "bootstrap") != execution_backend:
            raise ValueError("calibration trial uses a different execution backend")
        if (G.profile_digest(config) != expected_profile
                or config.get("ram_admission", "full") != profile.get("typed_ram_admission", "full")):
            raise ValueError("calibration trial uses a different proof profile")
        result = json.loads((directory / "001-typed/result.json").read_text())
        validate_backend_result(config, result)
        local, local_sha, assignment_paths = calibration_assignment(directory, config, result)
        C.checked_trial(directory, construction, count, local, local_sha, gpu_sha)
        if result.get("profile_sha256") != expected_profile:
            raise ValueError("calibration result uses a different proof profile")
        budget = result["budget"]
        uuid = budget["gpu"]["uuid"]
        if uuid not in assignment["limits_by_gpu"]:
            raise ValueError("calibration trial uses an unselected GPU")
        if budget["gpu"]["managed_bytes"] != assignment["limits_by_gpu"][uuid]["gpu"]["managed_bytes"]:
            raise ValueError("context calibration cannot change managed GPU capacity")
        measured = T.measured_context(directory / "001-typed/prove.log", uuid)
        if (type(measured["peak_context_bytes"]) is not int or measured["peak_context_bytes"] < 0
                or type(measured["samples"]) is not int or measured["samples"] <= 0):
            raise ValueError("invalid context measurements")
        identity = {"uuid": uuid, "driver": budget["detected_gpu"]["nvidia"]["driver"],
                    "runtime": budget["detected_gpu"]["opencl"]["driver"],
                    "binary_sha256": gpu_sha, "profile_sha256": expected_profile}
        calibration = calibrations.setdefault(uuid, {**identity, "peak_context_bytes": 0,
                                                     "samples": 0, "trials": []})
        if any(calibration[key] != value for key, value in identity.items()):
            raise ValueError("calibration trials use different GPU drivers or runtime")
        calibration["peak_context_bytes"] = max(calibration["peak_context_bytes"], measured["peak_context_bytes"])
        calibration["samples"] += measured["samples"]
        calibration["trials"].append(C.pin(directory / "summary.json"))
        pins.update(config["pins"])
        files = [config_path, *assignment_paths, directory / "summary.json", directory / "plan.json",
                 *(directory / "001-typed" / name for name in
                   ("result.json", "accounting.json", "prove.log", "audit.log")),
                 *(directory / "001-typed/root-only").iterdir()]
        pins.update(dict(T.pin(path) for path in files))
    if set(calibrations) != set(uuids):
        raise ValueError("complete context calibration is required for every selected GPU")
    return calibrations, pins


def plan_budgets(host, devices, profile, assignment=None, calibrations=None):
    uuids = [device["uuid"] for device in devices]
    if not uuids or len(uuids) != len(set(uuids)):
        raise ValueError("one distinct selected GPU is required for each worker slot")
    budgets = R.plan(host, devices, len(devices), profile, calibrations)
    # Reserve against total RAM so later increases in free RAM do not change
    # the coordinator allowance needed for a repeated fixed assignment.
    coordinator = R.up(max(512 * R.MIB, (host["physical_bytes"] + 49) // 50))
    for budget in budgets.values():
        memory = budget["host"]
        memory["coordinator_bytes"] = coordinator
        memory["worker_bytes"] = R.down((memory["fleet_bytes"] - coordinator) // len(devices))
        if memory["tmpfs"]:
            memory["spill_bytes"] = min(memory["spill_bytes"], memory["worker_bytes"])
        T.admit_budget(budget, profile)
    if assignment is not None:
        if (assignment.get("schema") != "lattica-typed-fleet-assignment-v1"
                or set(assignment.get("limits_by_gpu", {})) != set(budgets)):
            raise ValueError("fixed fleet assignment differs from selected GPU UUIDs")
        budgets = {uuid: T.apply_resource_assignment(budget,
                   {"schema": "lattica-typed-resource-assignment-v1", "limits": assignment["limits_by_gpu"][uuid]}, profile)
                   for uuid, budget in budgets.items()}
    fleets = {b["host"]["fleet_bytes"] for b in budgets.values()}
    reserves = {b["host"]["coordinator_bytes"] for b in budgets.values()}
    if len(fleets) != 1 or len(reserves) != 1:
        raise ValueError("workers must share one fleet cap and coordinator reserve")
    if sum(b["host"]["worker_bytes"] for b in budgets.values()) + next(iter(reserves)) > next(iter(fleets)):
        raise ValueError("worker RAM reservations exceed the shared fleet cap")
    return budgets


def event_counters(path):
    return {name: int(value) for name, value in (line.split() for line in path.read_text().splitlines())}


def event_deltas(before, after):
    if set(before) != set(after) or any(after[key] < before[key] for key in before):
        raise ValueError("fleet memory accounting changed or counters reset during execution")
    delta = {key: after[key] - before[key] for key in before}
    if any(delta.values()):
        raise ValueError(f"fleet memory-limit events occurred: {delta}")
    return delta


def cleanup(attempt, budget, observed_pids):
    unit = attempt["unit"]
    state = G.unit_state(unit)
    if not G.terminated(state):
        G.systemctl("stop", unit)
    for _ in range(20):
        if G.terminated(G.unit_state(unit)) and not any(pid in observed_pids for pid, _, _ in G.gpu_processes()):
            break
        time.sleep(0.5)
    else:
        raise ValueError("worker or GPU context still exists; scratch retained")
    link = Path(attempt["directory"]) / "scratch"
    expected = Path(budget["host"]["scratch_path"]) / unit.removesuffix(".service")
    if link.is_symlink():
        if link.resolve() != expected:
            raise ValueError("unexpected scratch target; retained")
        if expected.is_dir():
            shutil.rmtree(expected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--construction", choices=T.CONSTRUCTIONS, default="finalizer")
    parser.add_argument("--execution-backend", choices=("bootstrap", "typed-dag", "typed-process-dag"), default="bootstrap")
    parser.add_argument("--ram-admission", choices=("full", "compact"), default="compact")
    parser.add_argument("--gpu-binary", type=Path, required=True)
    parser.add_argument("--cpu-binary", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--gpu-uuid", action="append", required=True)
    parser.add_argument("--count", type=int, choices=T.COUNTS, default=4)
    parser.add_argument("--mode", choices=("sequential", "concurrent"), default="sequential")
    parser.add_argument("--scratch", type=Path, default=Path("/tmp"))
    parser.add_argument("--workload", type=Path,
                        default=Path(__file__).with_name("block-v2-multi-gpu-direct-readback-workload.json"))
    parser.add_argument("--resource-assignment", type=Path)
    parser.add_argument("--calibration-trial", type=Path, action="append", default=[],
                        help="Completed typed worker directory; repeat to cover all selected GPUs")
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    if len(args.gpu_uuid) != len(set(args.gpu_uuid)):
        parser.error("duplicate selected GPU UUID")
    if args.execution_backend != "bootstrap" and args.construction != "paired":
        parser.error("typed-dag execution requires --construction paired")
    os.umask(0o077)
    out = args.evidence.resolve()
    out.mkdir(parents=True, exist_ok=False)
    report = {"schema": "lattica-typed-fleet-v1", "status": "preparing", "mode": args.mode,
              "construction": args.construction, "ram_admission": args.ram_admission,
              "execution_backend": args.execution_backend,
              "count_per_root": args.count, "worker_slots": len(args.gpu_uuid), "attempts": [], "trials": [],
              "production_ready": False, "delivered_transactions_measured": False,
              "scope": "One fresh independently CPU-audited mixed root per GPU, using existing public wallet proofs. Registry preparation and durable host application are excluded."}
    locks, launched, observed, worker_reports, budgets = [], set(), {}, {}, {}
    started = time.monotonic()
    try:
        locks = G.lock_fleet()
        if json.loads(G.systemctl("list-units", "lattica-v2-multi-*.service", "--state=active,activating,deactivating", "--output=json", "--no-pager")):
            raise ValueError("another worker is active")
        fixture = args.fixture.resolve(strict=True)
        gpu, cpu = args.gpu_binary.resolve(strict=True), args.cpu_binary.resolve(strict=True)
        profile = T.resource_profile(args.workload, args.construction, args.ram_admission)
        paths = [*T.fixture_files(fixture, args.count, args.construction), gpu, cpu, Path(__file__),
                 Path(C.__file__), Path(T.__file__), Path(G.__file__), Path(R.__file__), args.workload]
        if args.resource_assignment:
            paths.append(args.resource_assignment)
        pins = dict(T.pin(path) for path in paths)
        expected, plan = out / "template-expected.json", out / "template-plan.json"
        T.execute_logged([cpu, "expected", fixture, args.count, expected], out / "expected.log", T.clean_environment())
        T.execute_logged([cpu, "plan", fixture, expected], plan, T.clean_environment())
        T.validate_plan(json.loads(plan.read_text()), args.construction)
        pins.update(dict(T.pin(path) for path in (expected, plan)))
        G.systemctl("start", G.SLICE)
        host = G.detect_worker_host(str(args.scratch.resolve(strict=True)))
        inventory = {device["uuid"]: device for device in R.detect_gpus(str(gpu))}
        if any(uuid not in inventory for uuid in args.gpu_uuid):
            raise ValueError("a selected GPU UUID was not detected")
        devices = [inventory[uuid] for uuid in sorted(args.gpu_uuid)]
        fixed = json.loads(args.resource_assignment.read_text()) if args.resource_assignment else None
        calibrations = None
        if args.calibration_trial:
            calibrations, calibration_pins = load_calibrations(args.calibration_trial,
                pins[str(gpu)], profile, args.construction, args.count, fixed, args.gpu_uuid,
                args.execution_backend)
            pins.update(calibration_pins)
            report["context_calibrations"] = calibrations
        budgets = plan_budgets(host, devices, profile, fixed, calibrations)
        assignment = {"schema": "lattica-typed-fleet-assignment-v1",
                      "limits_by_gpu": {uuid: T.resource_signature(budget) for uuid, budget in budgets.items()}}
        G.durable(out / "resource-assignment.json", assignment, True)
        G.durable(out / "admission.json", {"host": host, "devices": devices, "budgets": budgets}, True)
        pins.update(dict([T.pin(out / "resource-assignment.json")]))
        report.update(input_pins=pins, resource_assignment=C.pin(out / "resource-assignment.json"))
        jobs = []
        for index, uuid in enumerate(sorted(budgets), 1):
            root = out / f"gpu-{index:02d}"
            root.mkdir()
            for src, name in ((expected, "expected.json"), (plan, "plan.json")):
                shutil.copyfile(src, root / name)
            local_assignment = {"schema": "lattica-typed-resource-assignment-v1", "limits": assignment["limits_by_gpu"][uuid]}
            G.durable(root / "resource-assignment.json", local_assignment, True)
            local_pins = {**pins, **dict(T.pin(root / name) for name in ("expected.json", "plan.json", "resource-assignment.json"))}
            budget = budgets[uuid]
            budget["unit"] = f"lattica-v2-multi-{os.getpid()}-typed-{index}.service"
            config = {"gpu_binary": str(gpu), "cpu_binary": str(cpu), "fixture": str(fixture),
                      "execution_backend": args.execution_backend,
                      "count": args.count, "construction": args.construction, "ram_admission": args.ram_admission,
                      "workload": profile, "pins": local_pins, "expected": str(root / "expected.json"),
                      "plan": str(root / "plan.json"), "resource_assignment": str(root / "resource-assignment.json"),
                      "resource_assignment_sha256": local_pins[str(root / "resource-assignment.json")]}
            G.durable(root / "config.json", config, True)
            G.durable(root / "admission.json", {"host": host, "device": inventory[uuid], "budget": budget}, True)
            attempt = {"unit": budget["unit"], "uuid": uuid, "directory": str(root / "001-typed"), "status": "preparing"}
            report["attempts"].append(attempt)
            worker_reports[uuid] = {"schema": "lattica-typed-gpu-bootstrap-v1", "status": "preparing",
                "count": args.count, "construction": args.construction, "ram_admission": args.ram_admission,
                "attempt": attempt, "production_ready": False, "cold_full64_qualified": False,
                "durable_host_applied": False, "timing_boundary": "Worker fixture copy, recursive proving and independent CPU root audit; registry preparation excluded"}
            G.durable(root / "summary.json", worker_reports[uuid], True)
            jobs.append((uuid, root, config, attempt, local_assignment))
            observed[uuid] = set()
        common = next(iter(budgets.values()))["host"]
        G.systemctl("set-property", "--runtime", G.SLICE, f"MemoryMax={common['fleet_bytes']}",
                    "MemorySwapMax=0", "MemoryAccounting=yes")
        group = G.systemctl("show", G.SLICE, "--property=ControlGroup", "--value").strip()
        events_path = Path("/sys/fs/cgroup") / group.lstrip("/") / "memory.events"
        before = event_counters(events_path)
        report.update(status="running", parent_memory_events_before=before)
        G.durable(out / "summary.json", report, True)
        execution_started = time.monotonic()
        rounds = [jobs] if args.mode == "concurrent" else [[job] for job in jobs]
        for batch in rounds:
            active = {job[0]: job for job in batch}
            for uuid, root, config, attempt, local_assignment in batch:
                T.check_pins(config["pins"])
                attempt["status"] = worker_reports[uuid]["status"] = "running"
                G.durable(root / "summary.json", worker_reports[uuid])
                # launch can fail after creating the unit, so cleanup must cover
                # every attempted launch, not just successful systemd-run calls.
                launched.add(uuid)
                G.launch(config, {"id": f"typed-{uuid}"}, budgets[uuid], Path(attempt["directory"]), worker_script=Path(T.__file__))
                print(json.dumps({"event": "worker_started", "uuid": uuid, "directory": str(root)}), flush=True)
            G.durable(out / "summary.json", report)
            while active:
                for uuid, (unused, root, config, attempt, local_assignment) in list(active.items()):
                    directory = Path(attempt["directory"])
                    sample = G.telemetry(attempt, budgets[uuid])
                    observed[uuid].update(sample.get("pids", []))
                    with (directory / "telemetry.jsonl").open("a") as stream:
                        stream.write(json.dumps(sample) + "\n")
                    if not G.terminated(sample["unit"]) or any(pid in observed[uuid] for pid, _, _ in G.gpu_processes()):
                        continue
                    if not G.attempt_succeeded(directory, sample["unit"]):
                        raise ValueError(f"typed worker failed on {uuid}; no automatic retry")
                    result = json.loads((directory / "result.json").read_text())
                    validate_backend_result(config, result)
                    accounting = json.loads((directory / "accounting.json").read_text())
                    T.validate_accounting(accounting, budgets[uuid])
                    context = T.measured_context(directory / "prove.log", uuid)
                    context.update(binary_sha256=pins[str(gpu)], profile_sha256=G.profile_digest(config),
                                   driver=inventory[uuid]["nvidia"]["driver"], runtime=inventory[uuid]["opencl"]["driver"])
                    worker_reports[uuid].update(status="succeeded", result=result, accounting=accounting,
                                                 context_measurement=context, all_mixed_counts_qualified=False)
                    attempt["status"] = "succeeded"
                    G.durable(root / "summary.json", worker_reports[uuid])
                    try:
                        trial = C.checked_trial(root, args.construction, args.count, local_assignment,
                                                config["resource_assignment_sha256"], pins[str(gpu)])
                        T.check_pins(config["pins"])
                        cleanup(attempt, budgets[uuid], observed[uuid])
                    except BaseException as error:
                        attempt["status"] = worker_reports[uuid]["status"] = "failed"
                        worker_reports[uuid]["failure"] = f"{type(error).__name__}: {error}"
                        G.durable(root / "summary.json", worker_reports[uuid])
                        raise
                    trial["gpu_uuid"] = uuid
                    trial["execution_backend"] = args.execution_backend
                    trial["execution_result"] = result.get("execution_result")
                    report["trials"].append(trial)
                    launched.remove(uuid)
                    del active[uuid]
                    G.durable(out / "summary.json", report)
                    print(json.dumps({"event": "worker_succeeded", "uuid": uuid,
                                      "worker_seconds": trial["worker_seconds"]}), flush=True)
                if active:
                    time.sleep(0.5)
        report["execution_elapsed_seconds"] = time.monotonic() - execution_started
        after = event_counters(events_path)
        report["parent_memory_events_after"] = after
        report["parent_memory_event_deltas"] = event_deltas(before, after)
        T.check_pins(pins)
        report.update(status="succeeded", cpu_audited_roots=len(report["trials"]),
                      fresh_recursive_proofs=sum(trial["fresh_proofs"] for trial in report["trials"]))
    except BaseException as error:
        report.update(status="failed", failure=f"{type(error).__name__}: {error}")
        raise
    finally:
        cleanup_errors = []
        for attempt in report["attempts"]:
            uuid = attempt["uuid"]
            if uuid in launched:
                try:
                    cleanup(attempt, budgets[uuid], observed[uuid])
                except BaseException as error:
                    cleanup_errors.append(f"{uuid}: {type(error).__name__}: {error}")
            if attempt["status"] in ("preparing", "running"):
                attempt["status"] = worker_reports[uuid]["status"] = "failed"
                worker_reports[uuid]["failure"] = report.get("failure", "fleet did not complete")
            G.durable(Path(attempt["directory"]).parent / "summary.json", worker_reports[uuid])
        if cleanup_errors:
            report.update(status="failed", cleanup_failures=cleanup_errors)
        report["controller_elapsed_seconds"] = time.monotonic() - started
        G.durable(out / "summary.json", report)
        for lock in locks:
            os.close(lock)
        print(json.dumps({"status": report["status"], "completed_roots": len(report["trials"])}), flush=True)
        if cleanup_errors:
            raise RuntimeError("fleet cleanup incomplete; scratch retained")


if __name__ == "__main__":
    main()
