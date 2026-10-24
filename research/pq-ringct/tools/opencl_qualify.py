#!/usr/bin/env python3
"""Plan first; run isolated OpenCL qualification after fresh exclusive admission."""
import argparse
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
PACKAGE = ROOT / "research/pq-ringct"
BATCH_PACKAGE = ROOT / "research/pq-ringct-batch"
TOOLS = ROOT / ".tools/pq-opencl"
BASELINE_ROOT = ROOT.parent / "pq-ringct-research"
BASELINE = BASELINE_ROOT / "research/pq-ringct/data/complete-spend-acceptance-recovery-v2-1db18b9e1bece2fd.json"
BASELINE_UNIT = "lattica-pq-spend-recovery-v2-1db18b9e1bece2fd.service"
BASELINE_SHA256 = "35e6e6f74f9b4d3c31ade50b2b60fcc75e9beb24e9384ad9c70ee072046fb95e"
BATCH_BASELINE = BASELINE_ROOT / ".tools/pq-logs/pq-ringct-batch-accept-recovery-v2-r1-prove.json"
BATCH_BASELINE_SHA256 = "b45e0cd7e97dfcb129ca7c42b8ba8f4c23c7ef13a44858a1ddac6d30b149a796"
RUST_BIN = Path("/home/access/code/lattica/.tools/rust-1.96.0/bin")
GIB = 1 << 30
PROPERTIES = ("LoadState", "ActiveState", "SubState", "Result", "MainPID", "NRestarts",
              "ExecMainCode", "ExecMainStatus", "ExecMainExitTimestampMonotonic",
              "MemoryMax", "MemoryHigh", "MemorySwapMax", "MemoryPeak")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def sha(path):
    result = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1 << 20), b""):
            result.update(block)
    return result.hexdigest()


def command(args):
    return subprocess.run(args, text=True, capture_output=True, timeout=15, check=False)


def service(unit):
    response = command(["/usr/bin/systemctl", "--user", "show", unit]
                       + ["--property=" + name for name in PROPERTIES])
    require(response.returncode == 0, "user systemd state unavailable: " + response.stderr.strip())
    result = dict(line.split("=", 1) for line in response.stdout.splitlines() if "=" in line)
    require(result.get("LoadState") == "loaded", "service missing or unverified: " + unit)
    require(all(name in result for name in PROPERTIES), "incomplete service observation")
    return result


def terminal(state):
    # The baseline has RemainAfterExit=yes: successful completion is active/exited.
    return (state["MainPID"] == "0" and state["NRestarts"] == "0"
            and int(state["ExecMainExitTimestampMonotonic"]) > 0
            and (state["ActiveState"], state["SubState"]) in {
                ("active", "exited"), ("inactive", "dead"), ("failed", "failed")})


def baseline_gate():
    # Accepted record identities survive reboot; transient user services do not.
    # A historical service that still exists must nevertheless be terminal.
    require(sha(BASELINE) == BASELINE_SHA256, "CPU baseline record identity changed")
    require(sha(BATCH_BASELINE) == BATCH_BASELINE_SHA256,
            "CPU recursive-batch record identity changed")
    record = json.loads(BASELINE.read_text())
    batch = json.loads(BATCH_BASELINE.read_text())
    require(record.get("status") == "passed"
            and record.get("all_subprocesses_terminal_and_reaped") is True
            and record.get("measurement", {}).get("exit_code") == 0,
            "baseline record has no accepted terminal/reaped measurement")
    require(batch.get("status") == "passed"
            and batch.get("all_subprocesses_terminal_and_reaped") is True
            and batch.get("complete_n3_n4_batch_proofs_accepted") is True,
            "recursive-batch baseline is not accepted and reaped")
    observed = command(["/usr/bin/systemctl", "--user", "show", BASELINE_UNIT,
                        "--property=LoadState", "--value"])
    state = None
    require(observed.stdout.strip() in {"loaded", "not-found"},
            "cannot inspect historical baseline service: " + observed.stderr.strip())
    if observed.stdout.strip() == "loaded":
        state = service(BASELINE_UNIT)
        require(terminal(state), "CPU baseline service is live or unverified")
        require(state["Result"] == "success" and state["ExecMainCode"] == "1"
                and state["ExecMainStatus"] == "0",
                "successful baseline record conflicts with service exit")
    return {"observed_utc": now(), "unit": BASELINE_UNIT, "state": state,
            "record": str(BASELINE), "record_sha256": BASELINE_SHA256,
            "batch_record": str(BATCH_BASELINE), "batch_record_sha256": BATCH_BASELINE_SHA256,
            "status": record["status"], "performance_comparison_qualified": False}
def available():
    return int(next(line.split()[1] for line in Path("/proc/meminfo").read_text().splitlines()
                    if line.startswith("MemAvailable:"))) * 1024


PROTECTED_NON_WORKERS = frozenset({"systemd", "(sd-pam)", "kwin_wayland", "polkit-kde-auth", "btop"})


def protected_nonworker(directory, error):
    # Desktop/session processes can be nondumpable even to their own user.
    # This is workload admission, not a security boundary. Only the observed
    # ordinary non-worker names may be excluded; unknown names fail closed.
    name = (directory / "comm").read_text().strip()
    require(name in PROTECTED_NON_WORKERS,
            "cannot inspect unknown same-user process during exclusive admission: "
            + json.dumps({"pid": int(directory.name), "comm": name}))
    return {"pid": int(directory.name), "comm": name,
            "reason": "known protected desktop/session non-worker",
            "inspection_error": str(error)}


def conflicting_processes():
    """Fresh observed workload admission, including explicit protected exclusions."""
    busy, excluded = [], []
    project = Path("/home/access/code/lattica")
    for directory in Path("/proc").iterdir():
        if not directory.name.isdigit() or int(directory.name) == os.getpid():
            continue
        try:
            if directory.stat().st_uid != os.getuid():
                continue
            executable = (directory / "exe").resolve(strict=True)
            cwd = (directory / "cwd").resolve(strict=True)
            building = executable.name in {"cargo", "rustc", "cc", "gcc", "clang", "ld", "ld.lld"}
            proving = executable.is_relative_to(project) and any(
                part.startswith("target") or part == "pq-binaries" for part in executable.parts)
            if (building and cwd.is_relative_to(project)) or proving:
                busy.append({"pid": int(directory.name), "executable": str(executable)})
        except FileNotFoundError:
            continue  # Process exited during observation.
        except PermissionError as error:
            try:
                excluded.append(protected_nonworker(directory, error))
            except FileNotFoundError:
                continue  # Process exited before its comm could be observed.
    return {"conflicts": busy, "protected_non_workers": excluded}
def inputs():
    paths = {Path(__file__).resolve(), PACKAGE / "Cargo.toml", PACKAGE / "Cargo.lock",
             PACKAGE / "build.rs", PACKAGE / "graph_proof_sources.rs", PACKAGE / "data/baselines.json",
             BATCH_PACKAGE / "Cargo.toml", BATCH_PACKAGE / "Cargo.lock",
             TOOLS / "source-snapshot.json"}
    snapshot = json.loads((TOOLS / "source-snapshot.json").read_text())
    paths.update(ROOT / name for name in snapshot["source_sha256"])
    paths.update((PACKAGE / "src").rglob("*.rs"))
    paths.update((BATCH_PACKAGE / "src").rglob("*.rs"))
    paths.update((BATCH_PACKAGE / "tools").rglob("*.rs"))
    paths.update((ROOT / "lattica-prover-p3/src").rglob("*.cl"))
    return {str(path.relative_to(ROOT)): sha(path) for path in sorted(paths)}
def build_plan(args):
    require(not getattr(args, "allow_cpu_child_preparation", False),
            "--allow-cpu-child-preparation is no longer supported; remove it to use strict GPU child preparation")
    aggregate = args.stage == "aggregate"
    full_graph = aggregate and args.mode == "matrict"
    require(not full_graph or args.native_mib <= args.host_mib,
            "strict GPU native preparation allowance must not exceed --host-mib; reduce --native-mib or select an admitted host allowance")
    aes_component = args.stage == "probe" and args.relation == "pq-aes-component"
    proving = args.stage in {"probe", "aggregate"}
    cap = (48 if full_graph else 40 if aes_component else 16 if proving else 8) * GIB
    package = BATCH_PACKAGE if args.target == "aggregate" else PACKAGE
    binary = "pq-ringct-opencl-aggregate" if args.target == "aggregate" else "pq-ringct-opencl-probe"
    environment = {
        "PATH": str(RUST_BIN) + ":/usr/bin:/bin", "HOME": os.environ["HOME"],
        "CARGO_HOME": str(ROOT / ".tools/cargo-opencl"),
        "CARGO_TARGET_DIR": str(ROOT / ".tools/target-opencl"),
        "RAYON_NUM_THREADS": "8" if full_graph else "4" if proving else "2",
        "CARGO_BUILD_JOBS": "2", "LATTICA_V2_GPU_DEVICE": str(args.device_index),
    }
    # Must match opencl::REQUIRED_SWITCHES; policy itself is explicit too.
    switches = (
        "LATTICA_V2_GPU_HASH", "LATTICA_V2_GPU_RETAIN_TREES",
        "LATTICA_V2_GPU_QUERY_GATHER", "LATTICA_V2_GPU_RESIDENT_LDE",
        "LATTICA_V2_GPU_OPENINGS", "LATTICA_V2_QUOTIENT_FUSION",
        "LATTICA_V2_GPU_QUOTIENT_LDE", "LATTICA_V2_GPU_QUOTIENT_EVAL",
        "LATTICA_V2_GPU_QUOTIENT_RESIDENT", "LATTICA_V2_GPU_LOOKUP",
        "LATTICA_V2_GPU_OPENING_EVAL", "LATTICA_V2_GPU_FRI_RESIDENT",
        "LATTICA_V2_GPU_PCS_DEVICE_ONLY", "LATTICA_V2_GPU_WITNESS",
        "LATTICA_V2_GPU_RANDOMNESS", "LATTICA_V2_GPU_TRANSCRIPT",
        "LATTICA_V2_GPU_FRI_FOLD", "LATTICA_PROVING_REPORT",
    )
    if proving:
        environment.update({name: "1" for name in switches})
        environment.update(LATTICA_PROVING_POLICY="gpu-required",
                           LATTICA_V2_GPU_MANAGED_BYTES=str(args.device_mib << 20),
                           LATTICA_V2_GPU_CONTEXT_BYTES=str(4 * GIB),
                           LATTICA_V2_HOST_OUTPUT_BYTES=str(args.host_mib << 20))
    cargo = [str(RUST_BIN / "cargo")]
    common = ["--manifest-path", str(package / "Cargo.toml"), "--locked", "--offline",
              "--no-default-features", "--features", "opencl"]
    executable = ROOT / ".tools/target-opencl/release" / binary
    if args.stage == "build":
        argv = cargo + ["build", "--release"] + common + ["--bin", binary]
    elif args.stage == "check":
        selection = ["opencl::tests::"] if args.target == "probe" else []
        argv = cargo + ["test", "--lib"] + common + selection + ["--", "--test-threads=1"]
    else:
        argv = [str(executable), "--host-bytes", str(args.host_mib << 20),
                "--device-bytes", str(args.device_mib << 20), "--max-rows", str(args.max_rows)]
        if aggregate:
            argv += ["--mode", args.mode, "--output", str(args.output)]
            if full_graph:
                argv += ["--fixture", str(args.fixture),
                         "--cache-dir", str(args.cache_dir), "--count", str(args.count),
                         "--native-bytes", str(args.native_mib << 20)]
        else:
            argv += ["--stage", args.relation]
    return {"schema": "pq-ringct-opencl-run-v2", "stage": args.stage, "target": args.target,
            "relation": args.relation if not aggregate else "complete-recursive-batch" if full_graph else "nested-recursion-diagnostic",
            "mode": args.mode if aggregate else None,
            "prepared_only": not args.execute, "command": argv, "environment": environment,
            "binary": str(executable), "memory_max_bytes": cap,
            "memory_high_bytes": cap - 2 * GIB,
            "fresh_memavailable_required_bytes": cap + 2 * GIB if full_graph else cap + (4 if proving else 2) * GIB,
            "disk_reserve_bytes": 16 * GIB, "runtime_seconds": args.seconds,
            "cpu_quota": "800%" if full_graph else "400%" if proving else "200%",
            "launch": False, "full_matrict_graph_qualified": False,
            "performance_comparison_qualified": False, "writes": False,
            "cpu_preparation_before_gpu_session": full_graph,
            "managed_device_allowance_bytes": args.device_mib << 20 if proving else 0,
            "device_context_reserve_bytes": 4 * GIB if proving else 0}
def reject_interruption(signum, _frame):
    raise InterruptedError("received signal " + str(signum))


def execute(args, plan):
    # This lock excludes this helper's jobs; root coordination also excludes CUDA
    # and recursive-batch jobs that do not use this lock. No automatic retry.
    TOOLS.mkdir(parents=True, exist_ok=True)
    with (TOOLS / "qualification.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        plan["baseline_before"] = baseline_gate()
        require(args.exclusive_window, "execution requires --exclusive-window after coordinator admission")
        plan["process_admission"] = conflicting_processes()
        busy = plan["process_admission"]["conflicts"]
        require(not busy, "conflicting local build/proof processes: " + json.dumps(busy))
        require(available() >= plan["fresh_memavailable_required_bytes"], "fresh memory admission failed")
        require(shutil.disk_usage(ROOT).free >= plan["disk_reserve_bytes"], "disk reserve failed")
        require((ROOT / ".tools/cargo-opencl/registry").is_dir(),
                "isolated offline Cargo cache missing; seed it before execution")
        runs = TOOLS / "runs"
        runs.mkdir(exist_ok=True)
        record_path, log = runs / (args.label + ".json"), runs / (args.label + ".log")
        require(not record_path.exists() and not log.exists(), "run label already exists")
        before = inputs()
        plan.update(started_utc=now(), input_sha256=before, writes=True, prepared_only=False)
        if args.stage in {"probe", "aggregate"}:
            require(Path(plan["command"][0]).is_file(), "release probe binary is absent; run build first")
            build_record = json.loads((runs / (args.build_label + ".json")).read_text())
            require(build_record.get("status") == "passed" and build_record.get("stage") == "build"
                    and build_record.get("target", "probe") == args.target
                    and build_record.get("input_sha256") == before
                    and build_record.get("binary_sha256") == sha(Path(plan["command"][0])),
                    "release binary does not match successful build evidence and current inputs")
        if args.stage == "aggregate":
            require(args.probe_label is not None, "aggregate requires --probe-label from same-source device qualification")
            probe_path = runs / (args.probe_label + ".json")
            probe_record = json.loads(probe_path.read_text())
            require(probe_record.get("status") == "passed" and probe_record.get("stage") == "probe"
                    and probe_record.get("input_sha256") == before
                    and probe_record.get("probe_acceptance", {}).get("result", {}).get("passed") is True,
                    "aggregate prerequisite probe did not pass for current sources")
            plan["probe_prerequisite"] = {"path": str(probe_path), "sha256": sha(probe_path)}
            require(not args.output.exists(), "aggregate output already exists")
            args.output.parent.mkdir(parents=True, exist_ok=True)
            if args.mode == "matrict":
                args.cache_dir.mkdir(parents=True, exist_ok=True)
                plan["fixture_sha256"] = sha(args.fixture)
                plan["fixture"] = str(args.fixture)
                plan["cache_dir"] = str(args.cache_dir)
        unit = "lattica-pq-opencl-" + args.label + ".service"
        existing = command(["/usr/bin/systemctl", "--user", "show", unit,
                            "--property=LoadState", "--value"])
        require(existing.stdout.strip() == "not-found", "qualification unit already exists or is unverified")
        properties = {"Type": "exec", "RemainAfterExit": "yes", "Restart": "no",
                      "MemoryMax": str(plan["memory_max_bytes"]),
                      "MemoryHigh": str(plan["memory_high_bytes"]), "MemorySwapMax": "0",
                      "CPUQuota": plan["cpu_quota"], "TasksMax": "256",
                      "RuntimeMaxSec": str(args.seconds), "TimeoutStopSec": "10",
                      "KillMode": "control-group", "WorkingDirectory": str(ROOT),
                      "StandardOutput": "append:" + str(log), "StandardError": "inherit"}
        argv = ["/usr/bin/systemd-run", "--user", "--quiet", "--unit=" + unit]
        argv += ["--property=" + key + "=" + value for key, value in properties.items()]
        argv += ["/usr/bin/env", "-i"] + [key + "=" + value for key, value in plan["environment"].items()]
        argv += plan["command"]
        plan.update(unit=unit, service_command=argv, status="starting")
        record_path.write_text(json.dumps(plan, indent=2) + "\n")
        error, attempted, state = None, False, None
        began = time.monotonic()
        try:
            attempted = True
            response = command(argv)
            require(response.returncode == 0, "service launch failed: " + response.stderr.strip())
            plan["launch"] = True
            while True:
                state = service(unit)
                require(state["MemoryMax"] == str(plan["memory_max_bytes"])
                        and state["MemoryHigh"] == str(plan["memory_high_bytes"])
                        and state["MemorySwapMax"] == "0", "service memory limits differ")
                baseline_gate()
                if terminal(state):
                    break
                require(time.monotonic() - began < args.seconds + 30, "service exceeded bounded observation")
                time.sleep(5)
            require(state["Result"] == "success" and state["ExecMainCode"] == "1"
                    and state["ExecMainStatus"] == "0", "stage failed: " + json.dumps(state))
            if args.stage == "build":
                plan["binary_sha256"] = sha(Path(plan["binary"]))
            if args.stage == "check":
                require(re.search(r"test result: ok\. [1-9][0-9]* passed; 0 failed;", log.read_text()),
                        "focused CPU checks did not report a nonempty passing test run")
            if args.stage == "probe":
                plan["probe_acceptance"] = validate_probe(log, args)
            if args.stage == "aggregate":
                plan["aggregate_acceptance"] = validate_aggregate(log, args)
                plan["full_matrict_graph_qualified"] = args.mode == "matrict"
        except BaseException as caught:
            error = repr(caught)
        finally:
            # Stopping a terminal RemainAfterExit service releases its cgroup. On
            # cancellation, stop kills/reaps the entire group before recording.
            if attempted:
                for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
                    signal.signal(sig, signal.SIG_IGN)
                try:
                    stopped = command(["/usr/bin/systemctl", "--user", "stop", unit])
                    plan["service_stop_completed"] = stopped.returncode == 0
                    if stopped.returncode:
                        error = (error or "") + "; service stop failed: " + stopped.stderr.strip()
                except Exception as stop_error:
                    plan["service_stop_completed"] = False
                    error = (error or "") + "; service stop unverified: " + repr(stop_error)
            try:
                reaped = command(["/usr/bin/systemctl", "--user", "show", unit,
                                  "--property=LoadState", "--property=MainPID",
                                  "--property=ControlPID", "--property=ControlGroup"])
                after_stop = dict(line.split("=", 1) for line in reaped.stdout.splitlines() if "=" in line)
                gone = after_stop.get("LoadState") == "not-found"
                dead = (after_stop.get("LoadState") == "loaded"
                        and after_stop.get("MainPID") == "0" and after_stop.get("ControlPID") == "0")
                remaining = []
                if after_stop.get("ControlGroup"):
                    group = Path("/sys/fs/cgroup") / after_stop["ControlGroup"].lstrip("/")
                    if group.exists():
                        for process_file in group.rglob("cgroup.procs"):
                            remaining += process_file.read_text().split()
                plan["post_stop_state"] = after_stop
                plan["all_subprocesses_terminal_and_reaped"] = (
                    plan.get("service_stop_completed") is True and (gone or dead) and not remaining)
                require(plan["all_subprocesses_terminal_and_reaped"], "service cgroup termination/reaping unverified")
                if args.stage == "aggregate" and args.mode == "matrict":
                    require(sha(args.fixture) == plan["fixture_sha256"], "native fixture changed during execution")
            except Exception as reap_error:
                plan["all_subprocesses_terminal_and_reaped"] = False
                error = (error or "") + "; termination/preservation audit failed: " + repr(reap_error)
            try:
                plan["source_inputs_unchanged"] = inputs() == before
                if not plan["source_inputs_unchanged"]:
                    error = (error or "") + "; source inputs changed during execution"
            except Exception as audit_error:
                plan["source_inputs_unchanged"] = False
                error = (error or "") + "; source audit failed: " + repr(audit_error)
            plan.update(status="passed" if error is None else "failed_or_incomplete", error=error,
                        finished_utc=now(), wall_seconds=time.monotonic() - began,
                        terminal_state=state, raw_log=str(log),
                        raw_log_sha256=sha(log) if log.exists() else None)
            record_path.write_text(json.dumps(plan, indent=2) + "\n")
        print(json.dumps({"status": plan["status"], "record": str(record_path), "error": error}, indent=2))
        return 0 if error is None else 1


def validate_probe(log, args):
    results, gpu_reports = [], []
    required = {"block_v2_preprocessing", "block_v2_registered_program"}
    with log.open() as stream:
        for line in stream:
            if line.startswith("proving_stage_report "):
                report = json.loads(line.removeprefix("proving_stage_report "))
                if report.get("entry_point") in required:
                    require(report.get("policy") == "gpu_required",
                            "targeted preprocessing/proving report did not require GPU")
                if report.get("policy") == "gpu_required":
                    require(report.get("schema") == "lattica-proving-stages-v1"
                            and report.get("succeeded") is True
                            and report.get("stage_coverage_complete") is True
                            and report.get("completion_rejected") is False
                            and report.get("observation_errors") == 0,
                            "strict native GPU stage report failed")
                    gpu_reports.append(report)
            elif line.startswith("{"):
                result = json.loads(line)
                if result.get("schema") == "lattica-pq-opencl-qualification-v1":
                    results.append(result)
    require(len(results) == 1, "missing or duplicate qualification result")
    result = results[0]
    require(result.get("stage") == args.relation and result.get("passed") is True
            and result.get("cpu_verification") is True
            and result.get("changed_public_rejected") is True
            and result.get("changed_proof_rejected") is True
            and result.get("complete_transaction_qualified") is False
            and result.get("original_profile") is True
            and result.get("num_queries") == 128 and result.get("blowup") == 16
            and result.get("extension") == "Goldilocks cubic trinomial"
            and result.get("hiding") is True and result.get("strict_stage_reports_required") is True,
            "probe scope, verification, mutation, or security contract differs")
    details = result.get("details", {})
    if args.relation == "pq-aes-component":
        require(details.get("recursive_component") is True
                and details.get("complete_request_verified") is True
                and details.get("native_child_backend") == "cpu"
                and details.get("complete_matrict_graph_verified") is False,
                "AES component qualification scope differs")
    else:
        require(details.get("recursive_component") is False
                and details.get("native_child_backend") is None
                and details.get("complete_request_verified") in (None, False)
                and details.get("complete_matrict_graph_verified") in (None, False),
                "byte diagnostic claimed recursive or complete-graph qualification")
    require(result.get("host_allowance_bytes") == args.host_mib << 20
            and result.get("device_allowance_bytes") == args.device_mib << 20
            and result.get("gpu_context_allowance_bytes") == 4 * GIB
            and result.get("max_rows") == args.max_rows, "probe resource bounds differ")
    gpu, device = result.get("gpu", {}), result.get("device", {})
    require(gpu.get("commits", 0) > 0 and gpu.get("allocations", 0) > 0
            and 0 < gpu.get("managed_peak_bytes", 0) <= args.device_mib << 20,
            "missing completed GPU work or device allowance exceeded")
    require(device.get("opencl_index") == args.device_index and device.get("name")
            and device.get("driver") and device.get("max_allocation_bytes", 0) > 0
            and device.get("global_bytes", 0) >= (args.device_mib << 20) + 4 * GIB,
            "missing or mismatched GPU identity")
    require(required.issubset({report.get("entry_point") for report in gpu_reports}),
            "missing strict GPU registration/proving reports")
    return {"result": result, "strict_gpu_stage_reports": gpu_reports,
            "full_transaction_qualified": False, "performance_comparison_qualified": False}


GPU_NATIVE_STAGES = {
    "public_values", "witness_trace", "preprocessing", "transform", "quotient",
    "randomness", "hiding", "commitment", "opening", "fri_fold", "fri_query",
    "final_polynomial", "scalar", "transcript", "grinding",
}
GPU_MACHINE_INVENTORIES = {
    "block_v2_preprocessing": (
        "preprocessing", {"preprocessing", "randomness", "transform", "commitment"}),
    "block_v2_registered_program": (
        "registered_proof", (GPU_NATIVE_STAGES - {"public_values"}) | {"lookup"}),
}
GPU_NATIVE_ENTRIES = {
    "pq_statement", "pq_private_source", "matrict_affine_gpu", "matrict_ntt_gpu",
    "matrict_mul_gpu", "matrict_g_bound_gpu", "matrict_permutation_gpu",
    "matrict_linear_map_gpu", "pq_aes_lane_native", "pq_shake_segment_native",
    "pq_aes_wide_native", "pq_shake_wide_native", "pq_uniform_gpu", "pq_sparse_gpu",
    "pq_transcript_source",
}
FRESH_FAMILIES = {"sources", "algebra", "crypto", "auxiliary", "outer"}


def validate_full_gpu_report(report):
    """Pin the native, preparation and registered API inventories independently."""
    require(isinstance(report, dict), "full proving receipt must be an object")
    entry = report.get("entry_point")
    require(report.get("schema") == "lattica-proving-stages-v1"
            and report.get("policy") == "gpu_required"
            and report.get("succeeded") is True
            and report.get("stage_coverage_complete") is True
            and report.get("completion_rejected") is False
            and report.get("observation_errors") == 0
            and report.get("components") == [],
            "full preparation/proving receipt is not complete strict GPU work")
    if entry in GPU_MACHINE_INVENTORIES:
        scope, expected = GPU_MACHINE_INVENTORIES[entry]
        category = "machine"
    elif entry == "pq_graph_witness_preparation":
        scope, expected, category = "operation", {"witness_trace"}, "preparation"
    else:
        require(entry in GPU_NATIVE_ENTRIES, "unexpected full GPU proving entry")
        scope, expected, category = "proof_request", GPU_NATIVE_STAGES, "native"
    capabilities = report.get("capabilities")
    require(isinstance(capabilities, dict)
            and capabilities.get("profile") == "block_v2_cubic"
            and capabilities.get("scope") == scope, "full GPU profile/scope differs")
    stages, observations = capabilities.get("stages"), report.get("observations")
    require(isinstance(stages, list) and len(stages) == len(expected)
            and all(isinstance(stage, dict) and stage.get("backend") == "open_cl"
                    for stage in stages)
            and {stage.get("stage") for stage in stages} == expected,
            "full GPU capability inventory/backend differs")
    require(isinstance(observations, list) and len(observations) == len(expected),
            "full GPU observation inventory differs")
    observed = set()
    for observation in observations:
        require(isinstance(observation, dict), "full GPU observation must be an object")
        stage, calls = observation.get("stage"), observation.get("calls")
        completed, devices = observation.get("completed_calls"), observation.get("device_calls")
        require(stage in expected and stage not in observed
                and observation.get("backend") == "open_cl"
                and type(calls) is int and calls > 0
                and type(completed) is int and calls == completed
                and type(devices) is int and 0 < devices <= calls,
                "full GPU stage backend/completion/device observation differs")
        observed.add(stage)
    require(observed == expected, "full GPU receipt omitted a required stage")
    return category


def validate_fresh_cache(cache):
    require(isinstance(cache, dict) and cache.get("policy") == "fresh_only",
            "full child preparation requires FreshOnly proof caches")
    families = cache.get("families")
    require(isinstance(families, dict) and set(families) == FRESH_FAMILIES,
            "full child proof cache families differ")
    for family, counters in families.items():
        require(isinstance(counters, dict), "invalid proof cache family " + family)
        reads, hits = counters.get("reads"), counters.get("hits")
        fresh, attempts = counters.get("fresh_proofs"), counters.get("proof_attempts")
        require(type(reads) is int and reads == 0 and type(hits) is int and hits == 0
                and type(fresh) is int and fresh >= 0
                and type(attempts) is int and attempts == fresh,
                "full child preparation reused or failed a cached proof: " + family)
    require(sum(counters["fresh_proofs"] for counters in families.values()) > 0,
            "full child preparation did not produce fresh proofs")
    return families


def validate_matrict_evidence(log, result, args, gpu_reports):
    """Validate one strict child-preparation session and ordered repeated-child aggregation."""
    phase, begins, ends, initializations, shutdowns = "before", [], [], [], []
    merge_sequence, child_machine_sequence = [], []
    receipts = []
    native_reports = preparation_reports = 0
    for line in log.read_text().splitlines():
        if line.startswith("OPENCL_AGGREGATION "):
            event = json.loads(line.removeprefix("OPENCL_AGGREGATION "))
            if event.get("event") == "gpu_child_preparation_begin":
                require(phase == "before", "duplicate or misplaced GPU preparation begin")
                begins.append(event.get("details", {}))
                phase = "preparation"
            elif event.get("event") == "gpu_child_preparation_end":
                require(phase == "preparation" and initializations
                        and all(name in child_machine_sequence for name in GPU_MACHINE_INVENTORIES)
                        and native_reports > 0 and preparation_reports > 0,
                        "GPU child preparation ended without complete native/recursive work")
                ends.append(event.get("details", {}))
                phase = "aggregation"
            else:
                raise ValueError("unexpected full MatRiCT event; CPU preparation is unsupported")
        elif line.startswith("bounded_gpu_initialized "):
            require(phase in {"before", "preparation"} and not receipts and not initializations,
                    "GPU initialized outside its single child/aggregate session")
            initializations.append(line)
        elif line.startswith("bounded_gpu_identity "):
            require(phase in {"before", "preparation"} and not receipts,
                    "GPU identity appeared after proving")
            require(json.loads(line.removeprefix("bounded_gpu_identity ")) == result.get("session", {}).get("device"),
                    "GPU initialization identity differs from final device")
        elif line.startswith("bounded_gpu_shutdown "):
            require(phase == "aggregation" and initializations and merge_sequence,
                    "GPU shutdown is missing its initialized aggregation phase")
            require(line == "bounded_gpu_shutdown managed_live_bytes=0 lease_released=true",
                    "GPU shutdown did not release its managed allocations and lease")
            shutdowns.append(line)
            phase = "shutdown"
        elif line.startswith("proving_stage_report "):
            report = json.loads(line.removeprefix("proving_stage_report "))
            require(phase in {"preparation", "aggregation"} and initializations,
                    "proving receipt outside initialized GPU preparation/aggregation")
            category = validate_full_gpu_report(report)
            receipts.append(report)
            if category == "machine":
                sequence = child_machine_sequence if phase == "preparation" else merge_sequence
                sequence.append(report["entry_point"])
            elif category == "native":
                require(phase == "preparation", "native child proof appeared during aggregation")
                native_reports += 1
            else:
                preparation_reports += 1
        elif line.startswith("{"):
            value = json.loads(line)
            if value.get("schema") == "lattica-pq-opencl-recursive-aggregation-v1":
                require(phase == "shutdown", "final full result preceded GPU shutdown")
                phase = "result"
    require(phase == "result" and len(begins) == len(ends) == len(initializations) == len(shutdowns) == 1,
            "full-run phase events are incomplete")
    require(receipts == gpu_reports, "full GPU receipt inventories differ")
    begin, end = begins[0], ends[0]
    require(begin.get("policy") == "gpu-required" and begin.get("counts_as_gpu_work") is True
            and begin.get("proof_cache_policy") == "fresh_only"
            and begin.get("source_specific_cache") == str(args.cache_dir),
            "GPU preparation/cache admission event differs")
    source = result.get("source_identity")
    require(isinstance(source, str) and re.fullmatch(r"[0-9a-f]{64}", source),
            "invalid full-run compiled source identity")
    marker = args.cache_dir / ".opencl-compiled-source-identity"
    require(args.cache_dir.is_dir() and not args.cache_dir.is_symlink()
            and marker.is_file() and not marker.is_symlink()
            and marker.read_bytes() == source.encode("ascii"),
            "full-run cache source identity does not match regular marker")
    require(end.get("complete_graph_verified") is True and end.get("registered_leaves") == 91
            and end.get("policy") == "gpu-required" and end.get("source_identity") == source
            and end.get("seconds") == result.get("gpu_child_preparation_seconds")
            and type(end.get("fresh_complete_graph_proofs")) is int
            and end["fresh_complete_graph_proofs"] == 1
            and end.get("cache") == result.get("cache"),
            "GPU preparation completion/result identity differs")
    families = validate_fresh_cache(result.get("cache"))
    require(result.get("fixture_pattern") == "repeated_single_fixture"
            and type(result.get("unique_fixture_statements")) is int
            and result["unique_fixture_statements"] == 1
            and type(result.get("fresh_complete_graph_proofs")) is int
            and result["fresh_complete_graph_proofs"] == 1
            and result.get("repeated_child_proof") is True
            and result.get("fresh_distinct_transaction_qualified") is False
            and result.get("fixture_sha3_256") == hashlib.sha3_256(args.fixture.read_bytes()).hexdigest()
            and result.get("decoded_verification_after_gpu_shutdown") is True,
            "full fixture pattern/identity or post-shutdown verification differs")
    artifact = result.get("artifact", {})
    require(artifact.get("includes_original_statements") is False
            and artifact.get("includes_ledger_body") is False,
            "full artifact scope differs")
    expected = [([[0, 1], [1, 1]], [0, 2], 1, 0)]
    if args.count == 3:
        expected.append(([[0, 2], [2, 1]], [0, 3], 2, 1))
    else:
        expected += [([[2, 1], [3, 1]], [2, 2], 1, 0),
                     ([[0, 2], [2, 2]], [0, 4], 2, 2)]
    merges = result.get("merges", [])
    require(len(merges) == len(expected), "full merge topology count differs")
    for merge, (children, span, level, aggregate_children) in zip(merges, expected):
        require(merge.get("child_spans") == children and merge.get("span") == span
                and merge.get("level") == level and merge.get("aggregate_children") == aggregate_children,
                "full ordered N3/N4 merge topology differs")
        rows, active = merge.get("padded_rows"), merge.get("active_rows")
        require(type(rows) is int and 0 < rows <= args.max_rows and rows & (rows - 1) == 0
                and type(active) is int and 0 < active <= rows,
                "full merge geometry is not valid admitted power-of-two geometry")
    expected_sequence = [name for _ in expected
                         for name in ("block_v2_preprocessing", "block_v2_registered_program")]
    require(merge_sequence == expected_sequence,
            "full aggregate GPU report count/order differs from exact merge count")
    context = result.get("context", {})
    require(isinstance(context, dict), "full GPU worker context must be an object")
    operations = context.get("operations", {})
    require(isinstance(operations, dict), "full GPU worker operations must be an object")
    require(context.get("schema") == "pq-serial-proving-context-v1"
            and context.get("policy") == "gpu_required" and context.get("session_closed") is True
            and context.get("prepared_entries") == 0
            and context.get("session_finish") == result.get("session"),
            "full GPU worker did not release its prepared state and shared session")
    counts = {name: sum(r["entry_point"] == name for r in receipts)
              for name in GPU_MACHINE_INVENTORIES}
    proofs = operations.get("prove_calls")
    require(type(context.get("registrations")) is int and context["registrations"] > 0
            and counts["block_v2_preprocessing"] == context["registrations"]
            and type(proofs) is int and proofs > 0
            and operations.get("prove_succeeded") == proofs
            and counts["block_v2_registered_program"] == proofs
            and not operations.get("failures"), "full worker registration/proof accounting differs")
    require(type(operations.get("native_cpu_calls")) is int and operations["native_cpu_calls"] == 0
            and type(operations.get("native_cpu_succeeded")) is int and operations["native_cpu_succeeded"] == 0,
            "full GPU worker performed native CPU proving")
    for prefix, actual in (("native_gpu", native_reports), ("witness_preparation", preparation_reports)):
        calls = operations.get(prefix + "_calls")
        require(type(calls) is int and calls > 0 and calls == actual
                and operations.get(prefix + "_succeeded") == calls
                and operations.get(prefix + "_complete_reports") == calls,
                "full worker " + prefix + " receipt accounting differs")
    require(native_reports == sum(families[name]["fresh_proofs"] for name in FRESH_FAMILIES - {"outer"}),
            "full native GPU receipts differ from fresh child proof inventory")
    return {"gpu_preparation_targeted_reports": len(child_machine_sequence),
            "native_gpu_report_count": native_reports,
            "witness_preparation_report_count": preparation_reports,
            "gpu_targeted_report_count": len(merge_sequence), "exact_ordered_topology_checked": True,
            "compiled_source_identity": source, "fixture_sha3_256": result["fixture_sha3_256"],
            "gpu_shutdown_before_result": True}

def validate_aggregate(log, args):
    results, gpu_reports = [], []
    required = {"block_v2_preprocessing", "block_v2_registered_program"}
    for line in log.read_text().splitlines():
        if line.startswith("proving_stage_report "):
            report = json.loads(line.removeprefix("proving_stage_report "))
            require(report.get("policy") in {"compatible", "cpu_required", "gpu_required"},
                    "unknown serialized proving policy")
            if report.get("policy") == "gpu_required":
                require(report.get("schema") == "lattica-proving-stages-v1"
                        and report.get("succeeded") is True
                        and report.get("stage_coverage_complete") is True
                        and report.get("completion_rejected") is False
                        and report.get("observation_errors") == 0,
                        "recursive stage did not satisfy strict GPU policy")
                gpu_reports.append(report)
            elif args.mode == "diagnostic" and report.get("entry_point") in required:
                raise ValueError("diagnostic registration/proving used CPU policy")
        elif line.startswith("{"):
            result = json.loads(line)
            if result.get("schema") == "lattica-pq-opencl-recursive-aggregation-v1":
                results.append(result)
    require(len(results) == 1, "missing or duplicate aggregate result")
    result = results[0]
    require(result.get("passed") is True and result.get("mode") == args.mode
            and result.get("cpu_verification") is True
            and result.get("changed_public_rejected") is True
            and result.get("changed_proof_rejected") is True
            and result.get("strict_stage_reports_required") is True
            and result.get("complete_ledger_transaction_qualified") is False,
            "recursive aggregate acceptance or qualification scope is incomplete")
    require(result.get("original_profile") is True and result.get("num_queries") == 128
            and result.get("blowup") == 16 and result.get("extension") == "Goldilocks cubic trinomial"
            and result.get("hiding") is True,
            "recursive aggregate changed original proof profile")
    if args.mode == "diagnostic":
        proof_count = 3
        require(result.get("proof_count") == proof_count and result.get("recursive_depth") == 2
                and result.get("complete_matrict_relation_qualified") is False,
                "diagnostic did not prove both recursive layers or overclaimed full MatRiCT")
        layers = result.get("layers", [])
        require(len(layers) == 3 and [layer.get("depth") for layer in layers] == [0, 1, 2]
                and [layer.get("changed_public_rejected_count") for layer in layers] == [1, 2, 3]
                and result.get("ordered_public_value_count") == 3
                and result.get("decoded_verification_after_gpu_shutdown") is True,
                "diagnostic layers/public coverage or post-shutdown verification differs")
        for layer in layers:
            require(all(layer.get(field) is True for field in (
                        "strict_gpu_request", "actual_stark_proof", "cpu_verification",
                        "changed_public_rejected", "changed_proof_rejected",
                        "prepared_proving_state_dropped"))
                    and 0 < layer.get("rows", 0) <= args.max_rows,
                    "diagnostic layer lacks strict proving/verification/mutation evidence")
        checks = result.get("recursive_witness_checks", [])
        require(len(checks) == 1, "diagnostic requires one aggregate-child witness check")
        check = checks[0]
        require(check.get("child_index") == 0
                and check.get("mutated_field") == "trace_local[0].basis[0]"
                and check.get("execution_error") == "Unsatisfied"
                and all(check.get(field) is True for field in (
                    "original_witness_restored", "same_compiled_program",
                    "public_values_unchanged", "valid_parent_positive_control"))
                and check.get("negative_stark_proof_generated") is False
                and check.get("evaluation_budget_bytes") == GIB
                and 0 < check.get("principal_buffer_bound_bytes", 0) <= GIB,
                "diagnostic corrupted-child rejection/restoration/positive control differs")
    else:
        proof_count = args.count - 1
        merges = result.get("merges", [])
        require(result.get("count") == args.count and result.get("merge_count") == proof_count
                and len(merges) == proof_count
                and result.get("complete_matrict_relation_qualified") is True
                and result.get("repeated_standalone_relation") is True
                and result.get("registered_graph_leaves") == 91
                and result.get("changed_public_rejected_count") == 25
                and result.get("original_graph_dropped_before_final_verification") is True
                and result.get("child_preparation_backend") == "opencl"
                and result.get("gpu_child_preparation_seconds", -1) >= 0,
                "full MatRiCT aggregate scope/coverage incomplete")
        for merge in merges:
            require(merge.get("strict_gpu_request") is True
                    and merge.get("native_parent_verification") is True
                    and merge.get("prepared_registration_retained_in_context") is True
                    and merge.get("backend") == "opencl"
                    and merge.get("request_policy") == "GpuRequired"
                    and merge.get("cache_policy") == "fresh_only"
                    and merge.get("proof_cache_hit") is False
                    and 0 < merge.get("padded_rows", 0) <= args.max_rows,
                    "recursive merge did not satisfy admitted geometry/verification")
        require(sum(merge.get("aggregate_children", 0) for merge in merges) >= args.count - 2,
                "no sufficient aggregate-child recursion observed")
    full_evidence = validate_matrict_evidence(log, result, args, gpu_reports) if args.mode == "matrict" else None
    for entry_point in required:
        require(sum(report.get("entry_point") == entry_point for report in gpu_reports) >= proof_count,
                "missing per-proof strict GPU reports for " + entry_point)
    session = result.get("session", {})
    require(session.get("host_allowance_bytes") == args.host_mib << 20
            and session.get("device_allowance_bytes") == args.device_mib << 20
            and session.get("gpu_context_allowance_bytes") == 4 * GIB
            and session.get("max_rows") == args.max_rows,
            "recursive resource bounds differ from admission")
    require(session.get("commits", 0) > 0 and session.get("allocations", 0) > 0
            and 0 < session.get("managed_peak_bytes", 0) <= args.device_mib << 20,
            "no GPU work observed or device allowance exceeded")
    device = session.get("device", {})
    require(device.get("opencl_index") == args.device_index and device.get("name")
            and device.get("driver") and device.get("max_allocation_bytes", 0) > 0
            and device.get("global_bytes", 0) >= (args.device_mib << 20) + 4 * GIB,
            "recursive device identity missing/mismatched")
    artifact = result.get("artifact", {})
    require(artifact.get("path") == str(args.output)
            and artifact.get("decoded_payload_reverified") is True
            and artifact.get("includes_trusted_registered_key") is False,
            "aggregate artifact scope/reverification missing")
    require(args.output.is_file() and not args.output.is_symlink(), "aggregate artifact missing or indirect")
    actual = args.output.read_bytes()
    require(len(actual) == artifact.get("bytes")
            and hashlib.sha3_256(actual).hexdigest() == artifact.get("sha3_256"),
            "persisted aggregate artifact size/hash differs")
    return {"result": result, "strict_gpu_stage_reports": gpu_reports,
            "artifact_sha256": sha(args.output), "full_transaction_qualified": False,
            "performance_comparison_qualified": False, "full_mode_evidence": full_evidence}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", choices=("build", "check", "probe", "aggregate"), default="build")
    parser.add_argument("--target", choices=("probe", "aggregate"), default="probe")
    parser.add_argument("--mode", choices=("diagnostic", "matrict"), default="diagnostic")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--exclusive-window", action="store_true",
                        help="coordinator has excluded other CUDA/build/proof workloads")
    parser.add_argument("--label", default="opencl-v1")
    parser.add_argument("--build-label", default="opencl-build-v1")
    parser.add_argument("--probe-label", help="passed same-source byte/AES probe prerequisite")
    parser.add_argument("--relation", choices=("pq-byte", "pq-aes-component"), default="pq-aes-component")
    parser.add_argument("--device-index", type=int, default=0)
    parser.add_argument("--host-mib", type=int, default=4096)
    parser.add_argument("--device-mib", type=int, default=2048)
    parser.add_argument("--max-rows", type=int, default=1048576)
    parser.add_argument("--seconds", type=int, default=1800)
    parser.add_argument("--fixture", type=Path)
    parser.add_argument("--cache-dir", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--count", type=int, choices=(3, 4), default=3)
    parser.add_argument("--native-mib", type=int, default=32768)
    parser.add_argument("--allow-cpu-child-preparation", action="store_true",
                        help="deprecated and rejected; remove this flag for strict GPU child preparation")
    args = parser.parse_args()
    require(not args.allow_cpu_child_preparation,
            "--allow-cpu-child-preparation is no longer supported; remove it to use strict GPU child preparation")
    if args.stage == "aggregate":
        args.target = "aggregate"
    require(args.stage != "probe" or args.target == "probe", "probe stage requires probe target")
    for label in (args.label, args.build_label, args.probe_label):
        require(label is None or re.fullmatch(r"[a-z0-9][a-z0-9-]{0,39}", label), "unsafe run label")
    full_graph = args.stage == "aggregate" and args.mode == "matrict"
    aes_component = args.stage == "probe" and args.relation == "pq-aes-component"
    require(0 <= args.device_index < 64 and 1024 <= args.host_mib <= (32768 if full_graph or aes_component else 8192)
            and 256 <= args.device_mib <= 10240 and 1 <= args.max_rows <= 1048576
            and args.max_rows & (args.max_rows - 1) == 0
            and 1 <= args.seconds <= (86400 if full_graph else 7200),
            "resource argument exceeds qualification bounds")
    if args.stage == "aggregate":
        args.output = (args.output or TOOLS / "artifacts" / (args.label + ".postcard")).resolve()
        require(args.output.is_relative_to(TOOLS.resolve()), "output must stay in isolated OpenCL tools directory")
        if full_graph:
            require(args.fixture is not None and args.fixture.is_file(), "full MatRiCT requires existing --fixture")
            args.fixture = args.fixture.resolve()
            args.cache_dir = (args.cache_dir or TOOLS / "aggregate-cache" / args.label).resolve()
            require(args.cache_dir.is_relative_to((TOOLS / "aggregate-cache").resolve()),
                    "full MatRiCT cache must stay in isolated OpenCL aggregate-cache directory")
            require(1024 <= args.native_mib <= min(32768, args.host_mib),
                    "native preparation must be 1–32 GiB and must not exceed --host-mib")
    plan = build_plan(args)
    try:
        plan["baseline_gate"] = {"admitted": True, **baseline_gate()}
    except Exception as error:
        plan["baseline_gate"] = {"admitted": False, "reason": str(error)}
    if not args.execute:
        print(json.dumps(plan, indent=2))
        return 0
    require(plan["baseline_gate"]["admitted"], plan["baseline_gate"].get("reason"))
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, reject_interruption)
    return execute(args, plan)
if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(json.dumps({"status": "refused", "error": str(error)}), file=sys.stderr)
        sys.exit(1)
