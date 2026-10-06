#!/usr/bin/env python3
"""Run one bounded typed GPU bootstrap with a separately launched CPU root audit.

Requires a CPU-registered public fixture. Each invocation gets a fresh evidence
directory, native host/GPU admission, pinned inputs, cgroup accounting, and fresh
recursive proofs. It does not qualify durable application or the pilot.
"""
import argparse
import copy
from fractions import Fraction
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

import block_v2_resources as R

SPEC = importlib.util.spec_from_file_location("grouped_runner", Path(__file__).with_name("block-v2-multi-gpu-run.py"))
G = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(G)
WORKLOAD = "typed-depth-six-bootstrap-v1"
COUNTS = (1, 2, 3, 4, 8, 16, 32, 63, 64)
PUBLIC_NAMES = ("body.json", "height.json", *(f"key.{mode}" for mode in range(1, 6)))
CONSTRUCTIONS = {
    "reference": {"keys": 5, "workload": WORKLOAD,
                  "compact_workload": "typed-compact-depth-six-bootstrap-v1", "driver": "typed-reference-v1"},
    "finalizer": {"keys": 6, "workload": "typed-finalizer-depth-six-bootstrap-v1",
                  "compact_workload": "typed-finalizer-compact-depth-six-bootstrap-v1", "driver": "typed-finalizer-v1"},
    "paired": {"keys": 12, "workload": "typed-paired-depth-six-bootstrap-v1",
               "compact_workload": "typed-paired-compact-depth-six-bootstrap-v1", "driver": "typed-paired-v1"},
}


def construction_spec(name="reference"):
    if name not in CONSTRUCTIONS:
        raise ValueError("unknown typed construction")
    return CONSTRUCTIONS[name]


def public_names(construction="reference"):
    keys = construction_spec(construction)["keys"]
    return ("body.json", "height.json", *(f"key.{mode}" for mode in range(1, keys + 1)))


def validate_plan(plan, construction):
    spec = construction_spec(construction)
    if (plan.get("construction", "typed-reference-v1") != spec["driver"]
            or plan.get("registry_keys", 5) != spec["keys"]):
        raise ValueError("typed plan differs from the selected construction")



def pin(path):
    path = Path(path).resolve(strict=True)
    return str(path), G.digest(path)


def check_pins(pins):
    for name, expected in pins.items():
        if G.digest(name) != expected:
            raise ValueError(f"typed input changed: {name}")


def clean_environment():
    return {key: value for key, value in os.environ.items()
            if not key.startswith(("LATTICA_", "RAYON_"))}


def fixture_files(source, count, construction="reference"):
    if count not in COUNTS:
        raise ValueError("typed count is outside the qualification contract")
    paths = [source / name for name in (*public_names(construction), *(f"wallet.{i}" for i in range(count)))]
    if any(not path.is_file() or path.is_symlink() for path in paths):
        raise ValueError("typed fixture requires nonsymlink public inputs and every registered key")
    if json.loads((source / "height.json").read_text()) != 262144:
        raise ValueError("typed GPU bootstrap resource model covers height 262144 only")
    return paths


def resource_profile(path, construction="reference", ram_admission="full"):
    if ram_admission not in ("full", "compact"):
        raise ValueError("unknown typed RAM admission model")
    profile = json.loads(path.read_text())
    # This is a conservative bootstrap model for the same MachineAir geometry,
    # not a transferred measurement or qualification of a different registry.
    expected = {"logical_lde_rows": 8388608, "retained_quotient_rows": 4194304,
                "degree_prefix_rows": 524288, "main_columns": 98,
                "preprocessing_columns": 200, "permutation_columns_upper_bound": 55,
                "quotient_matrices": 16, "host_readback_layout": "direct"}
    R.query_readback_layout(profile)
    R.opening_denominator_cache(profile)
    geometry = dict(profile.get("geometry", {}))
    geometry.pop("query_readback_layout", None)
    geometry.pop("opening_denominator_cache", None)
    if profile.get("height") != 262144 or geometry != expected:
        raise ValueError("unsupported typed bootstrap resource geometry")
    profile = copy.deepcopy(profile)
    profile["name"] = construction_spec(construction)["compact_workload" if ram_admission == "compact" else "workload"]
    profile["typed_ram_admission"] = ram_admission
    profile["geometry"]["registry_programs"] = construction_spec(construction)["keys"]
    profile["geometry"]["tree_depth"] = 6
    return profile


def minimum_ram(profile):
    mode = profile.get("typed_ram_admission", "full")
    if mode == "full":
        return 31675383808
    if mode != "compact":
        raise ValueError("unknown typed RAM admission model")
    geometry = profile["geometry"]
    half_rows = geometry["logical_lde_rows"] // 2
    degree_rows = geometry["degree_prefix_rows"]
    main, prep, permutation = (geometry[key] for key in
        ("main_columns", "preprocessing_columns", "permutation_columns_upper_bound"))
    # Goldilocks extension degree three plus four random codewords. The Rust
    # compiled-geometry check independently derives and checks this payload.
    evaluation = half_rows * (main + prep + permutation)
    opening = half_rows * prep + degree_rows * (main + permutation + 7 * geometry["quotient_matrices"] + 7)
    return 8 * max(evaluation, opening)


def admit_budget(budget, profile):
    required = minimum_ram(profile)
    if budget["host"]["worker_bytes"] < required:
        raise ValueError(f"typed bootstrap cannot fit its {required}-byte retained-storage admission bound")
    if not R.workload_fits(budget, profile):
        raise ValueError("typed phase-aware RAM/spill/GPU model does not fit assigned resources")
    budget["qualification_capacity_test"] = True
    budget["workload_kind"] = profile["name"]
    budget["typed_ram_admission"] = profile.get("typed_ram_admission", "full")
    budget["slice"] = G.SLICE
    return budget


def assigned_budget(host, device, profile):
    return admit_budget(R.plan(host, [device], 1, profile)[device["uuid"]], profile)


def resource_signature(budget):
    """Assigned limits and stable device identity, excluding live occupancy."""
    device = budget["detected_gpu"]
    signature = {
        "cpu": copy.deepcopy(budget["cpu"]),
        "host": copy.deepcopy(budget["host"]),
        "gpu": {key: value for key, value in budget["gpu"].items()
                if key != "available_bytes"},
        "drivers": {name: device[name]["driver"] for name in ("nvidia", "opencl")},
    }
    return json.loads(json.dumps(signature))


def apply_resource_assignment(budget, assignment, profile):
    """Use fixed comparison limits only when the current system admits them."""
    if assignment.get("schema") != "lattica-typed-resource-assignment-v1":
        raise ValueError("invalid typed comparison resource assignment")
    limits = assignment.get("limits")
    current = resource_signature(budget)
    if not isinstance(limits, dict) or set(limits) != set(current):
        raise ValueError("comparison assignment has incomplete resource limits")
    # Keep hardware identity fixed. A one-worker comparison may retain the
    # smaller CPU share assigned when both GPU workers were planned.
    if limits["drivers"] != current["drivers"]:
        raise ValueError("current drivers differ from comparison assignment")
    cpu, live_cpu = limits["cpu"], current["cpu"]
    cpu_caps = {"quota_percent", "rayon_threads"}
    if (not isinstance(cpu, dict) or set(cpu) != set(live_cpu)
            or any(cpu[key] != live_cpu[key] for key in set(live_cpu) - cpu_caps)):
        raise ValueError("current CPU topology or capacity differs from comparison assignment")
    try:
        if not isinstance(cpu["quota_percent"], str) or not cpu["quota_percent"].endswith('%'):
            raise ValueError("invalid CPU quota")
        quota = Fraction(cpu["quota_percent"][:-1]) / 100
        live_quota = Fraction(live_cpu["quota_percent"][:-1]) / 100
    except (ValueError, ZeroDivisionError) as error:
        raise ValueError("comparison CPU quota must be a finite percentage") from error
    if (type(cpu["rayon_threads"]) is not int
            or not 1 <= cpu["rayon_threads"] <= live_cpu["rayon_threads"]
            or not cpu["rayon_threads"] <= quota <= live_quota):
        raise ValueError("comparison CPU limits exceed current capacity or reduce thread quota")
    gpu, live_gpu = limits["gpu"], current["gpu"]
    adjustable_gpu = {"managed_bytes", "context_bytes", "total_bytes", "headroom_bytes"}
    if not isinstance(gpu, dict) or set(gpu) != set(live_gpu):
        raise ValueError("comparison GPU assignment has incomplete limits")
    if any(gpu[key] != live_gpu[key] for key in set(live_gpu) - adjustable_gpu):
        raise ValueError("comparison GPU identity, capacity or context policy changed")
    if any(type(gpu[key]) is not int or gpu[key] <= 0 for key in adjustable_gpu):
        raise ValueError("comparison GPU limits must be positive integer bytes")
    if gpu["headroom_bytes"] < live_gpu["headroom_bytes"]:
        raise ValueError("comparison assignment reduces GPU headroom")
    if gpu["managed_bytes"] + gpu["context_bytes"] != gpu["total_bytes"]:
        raise ValueError("comparison GPU total differs from its reservations")
    if gpu["total_bytes"] + gpu["headroom_bytes"] > budget["gpu"]["available_bytes"]:
        raise ValueError("current free VRAM cannot admit the comparison assignment")
    if gpu["bootstrap"]:
        if gpu["context_bytes"] < max(512 * R.MIB, gpu["managed_bytes"]):
            raise ValueError("comparison assignment reduces the bootstrap context margin")
    elif gpu["context_bytes"] < live_gpu["context_bytes"]:
        raise ValueError("comparison assignment reduces the calibrated context margin")
    host, live = limits["host"], current["host"]
    if not isinstance(host, dict) or set(host) != set(live):
        raise ValueError("comparison host assignment has incomplete limits")
    adjustable = {"worker_bytes", "fleet_bytes", "coordinator_bytes", "spill_bytes"}
    if any(host[key] != live[key] for key in set(live) - adjustable):
        raise ValueError("host margins or scratch filesystem changed")
    if any(type(host[key]) is not int or host[key] <= 0 for key in adjustable):
        raise ValueError("comparison limits must be positive integer bytes")
    if any(host[key] > live[key] for key in ("worker_bytes", "fleet_bytes", "spill_bytes")):
        raise ValueError("current host capacity cannot admit the fixed comparison limits")
    if host["coordinator_bytes"] < live["coordinator_bytes"]:
        raise ValueError("comparison assignment reduces the coordinator margin")
    if host["worker_bytes"] + host["coordinator_bytes"] > host["fleet_bytes"]:
        raise ValueError("comparison fleet cap cannot contain worker and coordinator")
    if host["tmpfs"] and host["spill_bytes"] > host["worker_bytes"]:
        raise ValueError("comparison tmpfs spill exceeds the charged worker cap")
    if host["worker_bytes"] < minimum_ram(profile):
        raise ValueError("comparison assignment violates the typed retained-storage guard")
    result = copy.deepcopy(budget)
    result["cpu"] = copy.deepcopy(cpu)
    result["host"] = copy.deepcopy(host)
    result["gpu"].update(copy.deepcopy(gpu))
    if not R.workload_fits(result, profile):
        raise ValueError("typed workload does not fit the fixed comparison assignment")
    if resource_signature(result) != limits:
        raise ValueError("assigned comparison limits differ from the pinned limits")
    return result


def comparison_assignment(budget, profile):
    """Leave capacity for small availability changes without relaxing margins."""
    limits = resource_signature(budget)
    host = limits["host"]
    host["worker_bytes"] = max(minimum_ram(profile), R.down(host["worker_bytes"] * 9 // 10))
    # Reserve against total RAM, so normal free-RAM changes cannot increase the
    # automatic coordinator reserve above this fixed comparison reservation.
    host["coordinator_bytes"] = R.up(max(512 * R.MIB,
        (budget["detected_host"]["physical_bytes"] + 49) // 50))
    host["fleet_bytes"] = host["worker_bytes"] + host["coordinator_bytes"]
    host["spill_bytes"] = R.down(host["spill_bytes"] * 9 // 10)
    assignment = {"schema": "lattica-typed-resource-assignment-v1", "limits": limits}
    apply_resource_assignment(budget, assignment, profile)
    return assignment


def execute_logged(argv, log, env):
    with log.open("x") as output:
        subprocess.run(list(map(str, argv)), stdout=output, stderr=subprocess.STDOUT,
                       env=env, check=True)


def public_events(path, event):
    result = []
    for line in path.read_text().splitlines():
        if line.startswith("{"):
            record = json.loads(line)
            if record.get("event") == event:
                result.append(record)
    return result


def validate_fresh_nodes(plan, proof_log, gpu_log):
    nodes = public_events(proof_log, "fresh_typed_node")
    actual = [(f"node.{n['level']}.{n['index']}", n["mode"], n["count"]) for n in nodes]
    required = [(task["file"], task["mode"], task["count"]) for task in plan["tasks"]]
    if actual != required or len(actual) != plan["fresh_proofs"]:
        raise ValueError("typed GPU work did not produce exactly the planned fresh nodes")
    finished = public_events(gpu_log, "typed_gpu_work_complete")
    if len(finished) != 1 or finished[0].get("recursive_proofs") != len(actual):
        raise ValueError("typed GPU work counters are missing or inconsistent")


def validate_accounting(accounting, budget):
    events = dict(line.split() for line in accounting["memory.events"].splitlines())
    if not {"high", "max", "oom", "oom_kill", "oom_group_kill"}.issubset(events) or any(int(v) for v in events.values()):
        raise ValueError("typed worker memory-limit events invalidate qualification")
    if not 0 < int(accounting["memory.peak"]) <= budget["host"]["worker_bytes"]:
        raise ValueError("typed worker exceeded assigned memory")


def measured_context(log, uuid):
    contexts = [json.loads(line.split(" ", 1)[1]) for line in log.read_text().splitlines()
                if line.startswith("bounded_gpu_context ")]
    if not contexts or any(sample.get("uuid") != uuid for sample in contexts):
        raise ValueError("typed GPU context measurements are missing or use another UUID")
    return {"uuid": uuid, "peak_context_bytes": max(sample["context_bytes"] for sample in contexts),
            "samples": len(contexts)}


def execution_command(config):
    execution_backend = config.get("execution_backend", "bootstrap")
    if execution_backend not in ("bootstrap", "typed-dag", "typed-process-dag") or (execution_backend != "bootstrap" and config.get("construction") != "paired"):
        raise ValueError("typed DAG execution requires the paired construction")
    return {"bootstrap": "prove-gpu", "typed-dag": "prove-execution-gpu",
            "typed-process-dag": "prove-process-gpu"}[execution_backend]


def validate_execution_result(config, result):
    execution_command(config)
    backend = config.get("execution_backend", "bootstrap")
    if backend in ("typed-dag", "typed-process-dag"):
        expected = "typed_process_dag_v1" if backend == "typed-process-dag" else "typed_inline_dag_v1"
        if (result.get("execution_backend") != expected
                or result.get("workspace_released_after_gpu_teardown") is not True
                or result.get("arrival_backend_integrated") is not False):
            raise ValueError("typed DAG worker did not report bounded workspace teardown")
        if backend == "typed-process-dag":
            worker, coordinator = result.get("worker_pid"), result.get("coordinator_pid")
            if (type(worker) is not int or worker <= 0 or type(coordinator) is not int
                    or coordinator <= 0 or worker == coordinator
                    or result.get("worker_process_exited") is not True):
                raise ValueError("typed process worker did not report distinct child exit")


def worker(attempt_file):
    packet = json.loads(attempt_file.read_text())
    config, budget = packet["config"], packet["budget"]
    command = execution_command(config)
    construction = config.get("construction", "reference")
    spec = construction_spec(construction)
    ram_admission = config.get("ram_admission", "full")
    if (ram_admission not in ("full", "compact")
            or budget.get("typed_ram_admission", "full") != ram_admission
            or budget.get("workload_kind") != spec["compact_workload" if ram_admission == "compact" else "workload"]):
        raise ValueError("typed worker construction or RAM admission differs from its assignment")
    if config.get("resource_assignment"):
        assignment = json.loads(Path(config["resource_assignment"]).read_text())
        if resource_signature(budget) != assignment.get("limits"):
            raise ValueError("worker budget differs from the pinned comparison assignment")
    directory = attempt_file.parent
    started = time.monotonic()
    check_pins(config["pins"])
    source = Path(config["fixture"])
    fixture = directory / "fixture"
    fixture.mkdir(mode=0o700)
    for path in fixture_files(source, config["count"], construction):
        shutil.copyfile(path, fixture / path.name)
        if G.digest(fixture / path.name) != config["pins"][str(path)]:
            raise ValueError("copied typed input differs from its pin")
    expected = Path(config["expected"])
    plan = json.loads(Path(config["plan"]).read_text())
    validate_plan(plan, construction)
    proof_dir = directory / "proofs"
    gpu_env = {**clean_environment(), **G.environment(budget, directory)}
    prove_started = time.monotonic()
    execute_logged([config["gpu_binary"], command, fixture, expected, proof_dir,
                    budget["host"]["worker_bytes"]], directory / "prove.log", gpu_env)
    proving_seconds = time.monotonic() - prove_started
    validate_fresh_nodes(plan, directory / "prove.log", directory / "prove.log")
    root = proof_dir / "node.6.0"
    execution_result = json.loads((proof_dir / "result.json").read_text())
    validate_execution_result(config, execution_result)
    if not 0 < root.stat().st_size <= 2 * R.MIB:
        raise ValueError("typed root is outside the 2 MiB artifact limit")
    # Expose only the root, public body, expected policy, and trusted registry to
    # the audit process. It cannot load wallets or intermediate node proofs.
    audit = directory / "root-only"
    audit.mkdir(mode=0o700)
    for name in public_names(construction):
        shutil.copyfile(fixture / name, audit / name)
    shutil.copyfile(expected, audit / "expected.json")
    shutil.copyfile(root, audit / "node.6.0")
    audit_started = time.monotonic()
    execute_logged([config["cpu_binary"], "audit-root", audit, audit / "expected.json",
                    audit / "body.json", audit / "node.6.0"], directory / "audit.log",
                   {**clean_environment(), "RAYON_NUM_THREADS": str(budget["cpu"]["rayon_threads"])})
    audit_seconds = time.monotonic() - audit_started
    audits = public_events(directory / "audit.log", "independent_cpu_root_audit")
    if len(audits) != 1 or audits[0].get("passed") is not True or audits[0].get("count") != config["count"]:
        raise ValueError("independent typed CPU root audit did not pass")
    check_pins(config["pins"])
    G.durable(directory / "result.json", {
        "schema": "lattica-typed-gpu-bootstrap-v1", "status": "succeeded", "cpu_audited": True,
        "execution_backend": config.get("execution_backend", "bootstrap"),
        "execution_result": execution_result,
        "construction": construction, "registry_keys": spec["keys"],
        "ram_admission": config.get("ram_admission", "full"),
        "count": config["count"], "fresh_proofs": plan["fresh_proofs"], "budget": budget,
        "proving_seconds": proving_seconds, "cpu_audit_seconds": audit_seconds,
        "elapsed_seconds": time.monotonic() - started, "root_bytes": root.stat().st_size,
        "artifacts": {name: G.digest(audit / name) for name in (*public_names(construction), "expected.json", "node.6.0")},
        "binary_sha256": config["pins"][config["gpu_binary"]],
        "resource_assignment_sha256": config.get("resource_assignment_sha256"),
        "profile_sha256": G.profile_digest(config), "production_ready": False,
        "durable_host_applied": False}, True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--construction", choices=CONSTRUCTIONS, default="reference")
    parser.add_argument("--execution-backend", choices=("bootstrap", "typed-dag", "typed-process-dag"), default="bootstrap")
    parser.add_argument("--ram-admission", choices=("full", "compact"), default="full",
                        help="Admission model; compact requires separately qualified binaries and geometry")
    parser.add_argument("--gpu-binary", type=Path)
    parser.add_argument("--cpu-binary", type=Path)
    parser.add_argument("--fixture", type=Path)
    parser.add_argument("--gpu-uuid")
    parser.add_argument("--count", type=int, choices=COUNTS)
    parser.add_argument("--scratch", type=Path, default=Path("/tmp"))
    parser.add_argument("--expected", type=Path,
                        help="Independent host expectation, including height and issuance grants; otherwise use the fixed research fixture policy")
    parser.add_argument("--resource-assignment", type=Path,
                        help="Pinned equal-resource comparison assignment; checked against live admission")
    parser.add_argument("--workload", type=Path, default=Path(__file__).with_name("block-v2-multi-gpu-direct-readback-workload.json"))
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--worker", type=Path)
    args = parser.parse_args()
    if args.worker:
        worker(args.worker)
        return
    if args.execution_backend != "bootstrap" and args.construction != "paired":
        parser.error("typed-dag execution requires --construction paired")
    if any(getattr(args, name) is None for name in ("gpu_binary", "cpu_binary", "fixture", "gpu_uuid", "count", "evidence")):
        parser.error("gpu-binary, cpu-binary, fixture, gpu-uuid, count and evidence are required")
    os.umask(0o077)
    source = args.fixture.resolve(strict=True)
    paths = fixture_files(source, args.count, args.construction)
    profile = resource_profile(args.workload, args.construction, args.ram_admission)
    config = {"gpu_binary": str(args.gpu_binary.resolve(strict=True)),
              "cpu_binary": str(args.cpu_binary.resolve(strict=True)),
              "fixture": str(source), "count": args.count, "workload": profile,
              "construction": args.construction, "ram_admission": args.ram_admission,
              "execution_backend": args.execution_backend}
    sources = [*paths, args.gpu_binary, args.cpu_binary, Path(__file__), Path(G.__file__),
               Path(R.__file__), args.workload]
    if args.expected:
        args.expected = args.expected.resolve(strict=True)
        sources.append(args.expected)
        config['host_expected'] = str(args.expected)
    if args.resource_assignment:
        args.resource_assignment = args.resource_assignment.resolve(strict=True)
        sources.append(args.resource_assignment)
        config["resource_assignment"] = str(args.resource_assignment)
    config["pins"] = dict(map(pin, sources))
    if args.resource_assignment:
        config["resource_assignment_sha256"] = config["pins"][str(args.resource_assignment)]
    locks = G.lock_fleet()
    out = args.evidence.resolve()
    unit = f"lattica-v2-multi-{os.getpid()}-typed.service"
    attempt = {"unit": unit, "uuid": args.gpu_uuid, "directory": str(out / "001-typed"), "status": "preparing"}
    report = {"schema": "lattica-typed-gpu-bootstrap-v1", "status": "preparing",
              "count": args.count, "attempt": attempt, "production_ready": False, "construction": args.construction,
              "timing_boundary": "worker fixture copy, recursive proving, and independent CPU root audit; registry preparation excluded",
              "cold_full64_qualified": False, "durable_host_applied": False}
    launched = created = False
    try:
        if json.loads(G.systemctl("list-units", "lattica-v2-multi-*.service", "--state=active,activating,deactivating", "--output=json", "--no-pager")):
            raise ValueError("another GPU worker is active")
        out.mkdir(parents=True, exist_ok=False)
        created = True
        G.durable(out / "summary.json", report, True)
        expected, plan_file = out / "expected.json", out / "plan.json"
        if args.expected:
            shutil.copyfile(args.expected, expected)
            if G.digest(expected) != config['pins'][str(args.expected)]:
                raise ValueError('independent host expectation changed while copying')
        else:
            execute_logged([config["cpu_binary"], "expected", source, args.count, expected], out / "expected.log", clean_environment())
        execute_logged([config["cpu_binary"], "plan", source, expected], plan_file, clean_environment())
        validate_plan(json.loads(plan_file.read_text()), args.construction)
        if json.loads(plan_file.read_text()).get('count') != args.count:
            raise ValueError('independent host expectation count differs from requested geometry')
        config.update(expected=str(expected), plan=str(plan_file))
        config["pins"].update(dict(map(pin, [expected, plan_file])))
        check_pins(config["pins"])
        G.systemctl("start", G.SLICE)
        host = G.detect_worker_host(str(args.scratch.resolve(strict=True)))
        devices = [d for d in R.detect_gpus(config["gpu_binary"]) if d["uuid"] == args.gpu_uuid]
        if len(devices) != 1:
            raise ValueError("selected GPU UUID was not uniquely detected")
        budget = assigned_budget(host, devices[0], profile)
        automatic_budget = copy.deepcopy(budget)
        if args.resource_assignment:
            budget = apply_resource_assignment(budget,
                json.loads(args.resource_assignment.read_text()), profile)
        budget["unit"] = unit
        G.durable(out / "admission.json", {"host": host, "device": devices[0], "budget": budget,
                  "automatic_budget": automatic_budget}, True)
        G.durable(out / "config.json", config, True)
        G.systemctl("set-property", "--runtime", G.SLICE,
                    f"MemoryMax={budget['host']['fleet_bytes']}", "MemorySwapMax=0", "MemoryAccounting=yes")
        attempt["status"] = report["status"] = "running"
        G.durable(out / "summary.json", report)
        directory = Path(attempt["directory"])
        # Mark before launching so an interrupted systemd-run is reconciled.
        launched = True
        G.launch(config, {"id": "typed-bootstrap"}, budget, directory, worker_script=Path(__file__))
        observed_pids = set()
        while True:
            sample = G.telemetry(attempt, budget)
            observed_pids.update(sample.get("pids", []))
            with (directory / "telemetry.jsonl").open("a") as telemetry:
                telemetry.write(json.dumps(sample) + "\n")
            if G.terminated(sample["unit"]) and not any(pid in observed_pids for pid, _, _ in G.gpu_processes()):
                if not G.attempt_succeeded(directory, sample["unit"]):
                    raise ValueError("typed worker failed; no automatic retry")
                break
            time.sleep(0.5)
        result = json.loads((directory / "result.json").read_text())
        accounting = json.loads((directory / "accounting.json").read_text())
        validate_accounting(accounting, budget)
        context = measured_context(directory / "prove.log", args.gpu_uuid)
        context.update(binary_sha256=config["pins"][config["gpu_binary"]],
                       profile_sha256=G.profile_digest(config),
                       driver=devices[0]["nvidia"]["driver"], runtime=devices[0]["opencl"]["driver"])
        report.update(status="succeeded", result=result, accounting=accounting,
                      context_measurement=context, all_mixed_counts_qualified=False)
        attempt["status"] = "succeeded"
    except BaseException as error:
        report.update(status="failed", failure=f"{type(error).__name__}: {error}")
        attempt["status"] = "failed"
        raise
    finally:
        try:
            if launched:
                state = G.unit_state(unit)
                if not G.terminated(state):
                    G.systemctl("stop", unit)
                    state = G.unit_state(unit)
                if not G.terminated(state):
                    raise ValueError("typed worker has not stopped; scratch retained")
                scratch = out / "001-typed" / "scratch"
                if scratch.is_symlink():
                    target = scratch.resolve()
                    expected_scratch = args.scratch.resolve() / unit.removesuffix(".service")
                    if target == expected_scratch and target.is_dir():
                        shutil.rmtree(target)
        except BaseException as error:
            report.update(status="failed", cleanup_failure=f"{type(error).__name__}: {error}")
            raise
        finally:
            if created:
                G.durable(out / "summary.json", report)
            for lock in locks:
                os.close(lock)
    print(json.dumps(report), flush=True)


if __name__ == "__main__":
    main()
